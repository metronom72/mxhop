//! One inbound SMTP session, from `220` to `221`.
//!
//! The session is written over any stream rather than a socket, so the tests
//! drive the real state machine through a pipe. What it does *not* do is
//! decide policy: whether a recipient is ours comes from the [`Router`], and
//! nothing here looks inside the message.
//!
//! STARTTLS makes the stream type change in the middle of the conversation,
//! which is why the loop lives in [`talk`] and [`serve`] is an orchestrator:
//! `talk` runs over the plaintext stream, hands back [`Step::StartTls`], and
//! `serve` runs it again over the TLS stream. Two monomorphisations and no
//! enum of streams.

use std::io;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info};

use crate::config::Config;
use crate::envelope::{Envelope, now_unix_ms};
use crate::policy::{self, Decision, Limits, Trace};
use crate::routing::{Route, Router};
use crate::smtp::client::{Delivery, Relay};
use crate::smtp::command::{self, Command};
use crate::smtp::wire::{self, WireError};
use crate::spool::{Spool, new_id};

/// How many recipients one message may have before mxhop asks the client to
/// come back for the rest.
pub const MAX_RECIPIENTS: usize = 100;

/// How many refused commands a session may collect before mxhop stops
/// talking. A client that cannot speak SMTP is either broken or probing.
pub const MAX_ERRORS: u32 = 10;

/// How long a session may sit between commands, and inside DATA. RFC 5321
/// §4.5.3.2 asks for these; without them a connection that says nothing holds
/// a task for as long as it likes.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(5 * 60);
pub const DATA_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// How long the TLS handshake may take. A client that has said `STARTTLS` and
/// then nothing is past the point where an SMTP timeout could answer it, so
/// this is the only thing that can end the session.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the peer's reverse lookup may take before the trace says
/// `unknown`. Two seconds because the sending server is waiting on the final
/// dot while this happens, and a PTR record is a nicety: nothing is decided
/// on it, so a slow resolver must cost the message almost nothing.
pub const PTR_TIMEOUT: Duration = Duration::from_secs(2);

/// What the session needs to know about itself.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub hostname: String,
    pub max_message_bytes: u64,
    pub max_recipients: usize,
    pub max_errors: u32,
    pub command_timeout: Duration,
    pub data_timeout: Duration,
    pub handshake_timeout: Duration,
    pub ptr_timeout: Duration,
    /// What counts as a loop. See [`crate::policy::Limits`].
    pub limits: Limits,
}

impl SessionConfig {
    pub fn from_config(config: &Config) -> Self {
        Self {
            hostname: config.hostname.clone(),
            max_message_bytes: config.max_message_bytes,
            max_recipients: MAX_RECIPIENTS,
            max_errors: MAX_ERRORS,
            command_timeout: COMMAND_TIMEOUT,
            data_timeout: DATA_TIMEOUT,
            handshake_timeout: HANDSHAKE_TIMEOUT,
            ptr_timeout: PTR_TIMEOUT,
            limits: Limits::default(),
        }
    }
}

/// What happened, for the log line.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Outcome {
    /// Messages handed on, in whole or in part — the ones the sending server
    /// was told 250 for.
    pub accepted: usize,
    /// Whether the client said QUIT rather than vanishing.
    pub quit: bool,
    /// Whether the session ended up inside a TLS tunnel.
    pub tls: bool,
}

/// Everything the loop knows. The three facts a transaction is made of, plus
/// what the connection itself has become.
#[derive(Debug, Default)]
struct State {
    /// `from` is `Some(None)` for the null sender, which is a sender — just
    /// not one you can reply to.
    helo: Option<String>,
    /// Whether the client said EHLO rather than HELO, which is the `ESMTP`
    /// or `SMTP` the trace records.
    esmtp: bool,
    from: Option<Option<String>>,
    recipients: Vec<String>,
    errors: u32,
    outcome: Outcome,
}

impl State {
    /// RFC 3207 §4.2: the handshake resets the session to the state right
    /// after the greeting. The error count is not reset — it is ours, not the
    /// client's, and a client that has already made nine mistakes does not
    /// earn ten more by starting TLS.
    fn after_handshake(&mut self) {
        self.helo = None;
        self.esmtp = false;
        self.from = None;
        self.recipients.clear();
        self.outcome.tls = true;
    }
}

/// Why [`talk`] came back.
enum Step {
    /// The conversation is over; the outcome is in the [`State`].
    Done,
    /// The client asked for a handshake and may have one.
    StartTls,
}

/// Serves one session to its end. A client that disappears is not an error:
/// it happens all day, and nothing was promised to it.
///
/// `tls` is the certificate snapshot this connection was accepted with, or
/// `None` when no certificate is configured. TLS here is opportunistic and
/// never required: this is an MX, and refusing plaintext loses mail.
pub async fn serve<S, L>(
    stream: S,
    peer: String,
    config: &SessionConfig,
    router: &Router,
    spool: &Spool,
    relay: &L,
    tls: Option<TlsAcceptor>,
) -> Result<Outcome, WireError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    L: Relay,
{
    // One `BufReader` over the whole stream, written through `get_mut`: the
    // split halves that a session normally wants are exactly what makes the
    // stream impossible to swap out mid-conversation.
    let mut reader = BufReader::new(stream);
    let mut state = State::default();

    say(
        reader.get_mut(),
        &format!("220 {} mxhop ready", config.hostname),
    )
    .await?;

    match talk(
        &mut reader,
        &mut state,
        config,
        router,
        spool,
        relay,
        &peer,
        &tls,
    )
    .await?
    {
        Step::Done => return Ok(state.outcome),
        Step::StartTls => {}
    }

    // `talk` only asks for this when a certificate was configured.
    let acceptor = tls.clone().expect("STARTTLS is offered with a certificate");

    // **CVE-2011-0411.** Anything already buffered arrived in plaintext and
    // was not sent by whoever is about to hold the other end of the tunnel.
    // `BufReader::into_inner` discards its buffer by design, so this check has
    // to come before the upgrade, and refusing is the only safe answer:
    // replaying the bytes inside the tunnel is the vulnerability, and so is
    // running them before it.
    if !reader.buffer().is_empty() {
        // Worth a line: this is somebody trying the CVE on a live MX, and
        // without it the attempt is invisible — the session simply ends, and
        // the operator has no way to see it happening.
        info!(
            %peer,
            "commands were pipelined behind STARTTLS; refusing rather than upgrading"
        );
        say(
            reader.get_mut(),
            "554 5.5.1 commands sent before the TLS handshake are not accepted",
        )
        .await?;
        return Ok(state.outcome);
    }

    say(reader.get_mut(), "220 2.0.0 go ahead").await?;

    let plain = reader.into_inner();
    let encrypted = match timeout(config.handshake_timeout, acceptor.accept(plain)).await {
        Ok(Ok(encrypted)) => encrypted,
        // A handshake that did not happen admits no SMTP reply: there is no
        // agreed encoding left to send one in. Scanners do this all day, and
        // it is not a session failure.
        Ok(Err(e)) => {
            info!(%peer, "TLS handshake failed: {e}");
            return Ok(state.outcome);
        }
        Err(_) => {
            info!(%peer, "TLS handshake timed out");
            return Ok(state.outcome);
        }
    };

    state.after_handshake();
    let mut reader = BufReader::new(encrypted);

    // Inside the tunnel `talk` answers a second STARTTLS itself, so the only
    // way back here is `Done`.
    let step = talk(
        &mut reader,
        &mut state,
        config,
        router,
        spool,
        relay,
        &peer,
        &tls,
    )
    .await?;

    // `close_notify`, so the sender's own log does not record our goodbye as a
    // truncation attack. A client that has already gone is not an error here.
    let _ = reader.get_mut().shutdown().await;

    match step {
        Step::Done | Step::StartTls => Ok(state.outcome),
    }
}

/// The command loop, over whatever the stream currently is.
#[allow(clippy::too_many_arguments)]
async fn talk<S, L>(
    reader: &mut BufReader<S>,
    state: &mut State,
    config: &SessionConfig,
    router: &Router,
    spool: &Spool,
    relay: &L,
    peer: &str,
    tls: &Option<TlsAcceptor>,
) -> Result<Step, WireError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    L: Relay,
{
    loop {
        let line = match timeout(config.command_timeout, wire::read_line(reader)).await {
            Err(_) => {
                say(reader.get_mut(), "421 4.4.2 timeout waiting for a command").await?;
                return Ok(Step::Done);
            }
            Ok(Ok(line)) => line,
            Ok(Err(WireError::Closed)) => return Ok(Step::Done),
            Ok(Err(WireError::LineTooLong)) => {
                say(reader.get_mut(), "500 5.5.6 command line too long").await?;
                return Ok(Step::Done);
            }
            Ok(Err(e)) => return Err(e),
        };

        let command = match command::parse(&line) {
            Ok(command) => command,
            Err(e) => {
                say(reader.get_mut(), &e.to_string()).await?;
                if too_many_errors(reader, state, config).await? {
                    return Ok(Step::Done);
                }
                continue;
            }
        };

        match command {
            Command::Ehlo(name) => {
                state.helo = Some(name.clone());
                state.esmtp = true;
                state.from = None;
                state.recipients.clear();
                let mut greeting = format!(
                    "250-{} greets {}\r\n\
                     250-SIZE {}\r\n\
                     250-8BITMIME\r\n\
                     250-PIPELINING\r\n",
                    config.hostname, name, config.max_message_bytes
                );
                // Advertised only when there is a certificate to serve, and
                // never once the tunnel is up: RFC 3207 §4.2 forbids
                // re-offering it.
                if tls.is_some() && !state.outcome.tls {
                    greeting.push_str("250-STARTTLS\r\n");
                }
                greeting.push_str("250 ENHANCEDSTATUSCODES");
                say(reader.get_mut(), &greeting).await?;
            }

            Command::Helo(name) => {
                state.helo = Some(name);
                state.esmtp = false;
                state.from = None;
                state.recipients.clear();
                say(reader.get_mut(), &format!("250 {}", config.hostname)).await?;
            }

            // Allowed before EHLO on purpose: HELO-only clients exist, and a
            // client that wants encryption first is not making a mistake.
            Command::StartTls => {
                if state.outcome.tls {
                    say(reader.get_mut(), "503 5.5.1 TLS is already active").await?;
                } else if tls.is_none() {
                    say(reader.get_mut(), "502 5.5.1 STARTTLS is not offered here").await?;
                    if too_many_errors(reader, state, config).await? {
                        return Ok(Step::Done);
                    }
                } else {
                    // `serve` says `220` — it owns the stream from here.
                    return Ok(Step::StartTls);
                }
            }

            Command::Mail {
                from: sender, size, ..
            } => {
                if state.helo.is_none() {
                    say(reader.get_mut(), "503 5.5.1 say EHLO first").await?;
                } else if state.from.is_some() {
                    say(
                        reader.get_mut(),
                        "503 5.5.1 a message is already in progress",
                    )
                    .await?;
                } else if size.is_some_and(|size| size > config.max_message_bytes) {
                    // The client said how big it is. Reading it anyway would
                    // waste both sides' time.
                    say(
                        reader.get_mut(),
                        &format!(
                            "552 5.3.4 message larger than the {} byte limit",
                            config.max_message_bytes
                        ),
                    )
                    .await?;
                } else {
                    state.from = Some(sender);
                    state.recipients.clear();
                    say(reader.get_mut(), "250 2.1.0 sender accepted").await?;
                }
            }

            Command::Rcpt(address) => {
                if state.from.is_none() {
                    say(reader.get_mut(), "503 5.5.1 say MAIL FROM first").await?;
                } else if state.recipients.len() >= config.max_recipients {
                    // Temporary on purpose: the client should send the rest
                    // in another message rather than give up on them.
                    say(
                        reader.get_mut(),
                        "452 4.5.3 too many recipients for one message",
                    )
                    .await?;
                } else {
                    let reply = decide_recipient(router, &address, &mut state.recipients);
                    say(reader.get_mut(), &reply).await?;
                }
            }

            Command::Data => {
                if state.recipients.is_empty() {
                    say(reader.get_mut(), "503 5.5.1 no accepted recipients").await?;
                    continue;
                }
                say(reader.get_mut(), "354 end your message with a single dot").await?;

                let body = match timeout(
                    config.data_timeout,
                    wire::read_body(reader, config.max_message_bytes),
                )
                .await
                {
                    Err(_) => {
                        say(reader.get_mut(), "421 4.4.2 timeout inside DATA").await?;
                        return Ok(Step::Done);
                    }
                    Ok(Ok(body)) => body,
                    Ok(Err(WireError::TooLarge { limit })) => {
                        // The stream now holds the rest of a message we have
                        // already refused; draining it is work on behalf of
                        // whoever sent it.
                        say(
                            reader.get_mut(),
                            &format!("552 5.3.4 message larger than {limit} bytes"),
                        )
                        .await?;
                        return Ok(Step::Done);
                    }
                    Ok(Err(WireError::UnterminatedBody | WireError::Closed)) => {
                        return Ok(Step::Done);
                    }
                    Ok(Err(e)) => return Err(e),
                };

                let (reply, delivered) =
                    hand_on(config, router, spool, relay, peer, state, body).await;
                say(reader.get_mut(), &reply).await?;
                if delivered {
                    state.outcome.accepted += 1;
                }

                state.from = None;
                state.recipients.clear();
            }

            Command::Rset => {
                state.from = None;
                state.recipients.clear();
                say(reader.get_mut(), "250 2.0.0 reset").await?;
            }

            Command::Noop => say(reader.get_mut(), "250 2.0.0 ok").await?,

            Command::Quit => {
                say(
                    reader.get_mut(),
                    &format!("221 2.0.0 {} closing", config.hostname),
                )
                .await?;
                state.outcome.quit = true;
                return Ok(Step::Done);
            }

            // An alias table is not a directory for strangers to read, so the
            // answer is the same whether the address exists or not.
            Command::Vrfy => {
                say(
                    reader.get_mut(),
                    "252 2.5.2 cannot verify, will try to deliver",
                )
                .await?
            }

            Command::Help => {
                say(
                    reader.get_mut(),
                    "214 2.0.0 https://github.com/metronom72/mxhop",
                )
                .await?
            }

            Command::Unknown(_) => {
                say(reader.get_mut(), "500 5.5.2 command not recognised").await?;
                if too_many_errors(reader, state, config).await? {
                    return Ok(Step::Done);
                }
            }
        }
    }
}

/// Everything between the final dot and the reply: the trace, the decision,
/// the deliveries, and whatever is left over.
///
/// Nothing is stored before delivery is attempted. While the message is only
/// on the wire the sending server still owns it, and that is the one place a
/// message can wait that has a retry queue today.
async fn hand_on<L>(
    config: &SessionConfig,
    router: &Router,
    spool: &Spool,
    relay: &L,
    peer: &str,
    state: &State,
    body: Vec<u8>,
) -> (String, bool)
where
    L: Relay,
{
    let id = new_id();
    let helo = state.helo.clone().unwrap_or_default();

    // The peer's own name, under a short clock: nothing is decided on it, so
    // a resolver that is thinking must not cost the sending server its
    // session. `unknown` in the trace is the honest answer.
    let address = peer.parse::<std::net::SocketAddr>();
    let ptr = match &address {
        Ok(address) => timeout(config.ptr_timeout, relay.ptr(address.ip()))
            .await
            .unwrap_or(None),
        // A peer that is not an address at all happens only in a test, and
        // the header says `unknown` rather than guessing.
        Err(_) => None,
    };
    let ip = match &address {
        Ok(address) => address.ip().to_string(),
        Err(_) => peer.to_string(),
    };

    let received = Trace {
        helo: helo.clone(),
        ptr,
        ip,
        by: config.hostname.clone(),
        id: id.clone(),
        esmtp: state.esmtp,
        tls: state.outcome.tls,
        recipients: state.recipients.clone(),
        at_unix_ms: now_unix_ms(),
    }
    .header();

    let envelope = Envelope {
        id,
        from: state.from.clone().flatten(),
        to: state.recipients.clone(),
        helo,
        peer: peer.to_string(),
        received_at_unix_ms: now_unix_ms(),
        size: body.len() as u64,
        received: received.clone(),
        last_reply: None,
    };

    // The message's own trace, read before anything leaves: the loop that
    // bites a forwarder is not in the alias table but in somebody else's
    // filter rule.
    let head = policy::Head::scan(&body, &config.hostname);
    let plan = match policy::decide(&envelope, router, &head, &config.limits) {
        Decision::Refuse(reply) => {
            info!(
                %peer,
                id = %envelope.id,
                received = head.received_count,
                by_us = head.by_us_count,
                "refusing to relay: {reply}"
            );
            return (reply.to_string(), false);
        }
        Decision::Deliver(plan) => plan,
    };

    // One `Arc` for every group: the body is handed to each delivery without
    // being copied, which for a 25 MiB message to three domains is the
    // difference between one copy and four.
    let body: std::sync::Arc<[u8]> = body.into();
    let mut outcomes = Vec::with_capacity(plan.groups.len());
    for group in &plan.groups {
        // Sequentially, on purpose. The inbound sender is waiting, but three
        // concurrent deliveries would also mean three connections out of one
        // inbound session, which is how a forwarder becomes an amplifier.
        outcomes.push(
            relay
                .deliver(Delivery::new(
                    plan.sender.clone(),
                    group.recipients.clone(),
                    received.clone().into_bytes(),
                    std::sync::Arc::clone(&body),
                ))
                .await,
        );
    }

    let verdict = policy::reply_for(&outcomes, &envelope.id);
    let delivered = (200..300).contains(&verdict.reply.code);

    // Every copy that is being thrown away, named one line at a time. The
    // sending server has been told 250 and cannot be told otherwise, and
    // there is no DSN generator yet, so this log line is the only record
    // these recipients' mail ever existed — one line each rather than a
    // count, because an operator asked "did my mail to b@ arrive?" has to be
    // able to grep for `b@`.
    for (mailbox, reply) in &verdict.lost {
        error!(
            %peer,
            id = %envelope.id,
            recipient = %mailbox,
            "this copy was permanently refused and is lost: part of the message was \
             delivered, so the sending server was told 250 and will not send it again, \
             and mxhop cannot send a bounce of its own yet: {reply}"
        );
    }

    if verdict.hold.is_empty() {
        info!(
            %peer,
            id = %envelope.id,
            domains = plan.groups.len(),
            lost = verdict.lost.len(),
            "relayed: {}",
            verdict.reply
        );
        return (verdict.reply.to_string(), delivered);
    }

    // Some of it arrived, so the sender is told 250 and must not send it
    // again — which makes the rest ours. It is written to the spool before
    // the 250 goes out, in that order: a crash in between then leaves the
    // sending server still holding the message rather than nobody holding it.
    // One reason per held recipient, in the same order as `to`: two
    // recipients at two hosts are stuck for two different reasons, and an
    // operator reading the sidecar has to be able to tell which belongs to
    // which.
    let held = Envelope {
        to: verdict
            .hold
            .iter()
            .map(|(mailbox, _)| mailbox.to_string())
            .collect(),
        last_reply: Some(
            verdict
                .hold
                .iter()
                .map(|(mailbox, reply)| format!("{mailbox}: {reply}"))
                .collect::<Vec<_>>()
                .join("; "),
        ),
        ..envelope.clone()
    };
    match spool.store(&held, &body).await {
        // Error level because nothing collects these yet: until the
        // retry-queue milestone they sit in `queue/`, and an operator has to
        // be able to see that they are there.
        Ok(()) => error!(
            %peer,
            id = %held.id,
            held = held.to.join(", "),
            "part of the message was not delivered and is held in the queue with no \
             retry: {}",
            held.last_reply.as_deref().unwrap_or("no reason recorded")
        ),
        // The sender is still told 250: the copies that did arrive have
        // arrived, and asking for the message again would deliver those
        // twice. These recipients have lost their copy — the same hole a
        // permanent refusal in a mixed outcome falls into, and it closes only
        // when mxhop can send a DSN of its own.
        Err(e) => error!(
            %peer,
            id = %held.id,
            held = held.to.join(", "),
            "part of the message was not delivered and could not be held either: {e}"
        ),
    }

    (verdict.reply.to_string(), delivered)
}

/// Counts one refusal and says goodbye if the client has made too many.
/// `true` means the session is over.
async fn too_many_errors<S>(
    reader: &mut BufReader<S>,
    state: &mut State,
    config: &SessionConfig,
) -> Result<bool, WireError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    state.errors += 1;
    if state.errors >= config.max_errors {
        say(reader.get_mut(), "421 4.7.0 too many errors, goodbye").await?;
        return Ok(true);
    }
    Ok(false)
}

/// The reply for one `RCPT TO`, and the recipient added to the envelope if it
/// is one of ours.
fn decide_recipient(router: &Router, address: &str, recipients: &mut Vec<String>) -> String {
    let Some((local, domain)) = address.rsplit_once('@') else {
        return "501 5.1.3 recipient is not <local@domain>".to_string();
    };

    match router.resolve(domain, local) {
        Some((_, Route::Reject(reply))) => reply.clone(),
        Some((_, Route::Forward(_))) => {
            recipients.push(address.to_string());
            "250 2.1.5 recipient accepted".to_string()
        }
        // Two different refusals, and the difference matters: one means the
        // address does not exist, the other that mxhop is not this domain's
        // mail server. An operator chasing a misdirected MX record needs to
        // be able to tell them apart.
        None if router.handles_domain(domain) => "550 5.1.1 no such address here".to_string(),
        None => "550 5.7.1 relaying is not allowed".to_string(),
    }
}

/// Writes one reply, terminator included, as a single write.
///
/// Splitting the CRLF into a write of its own is what breaks a client that
/// reads the STARTTLS prologue a `recv` at a time — `openssl s_client` among
/// them.
async fn say<W>(out: &mut W, line: &str) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut reply = String::with_capacity(line.len() + 2);
    reply.push_str(line);
    reply.push_str("\r\n");
    out.write_all(reply.as_bytes()).await?;
    out.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::Mailbox;
    use crate::smtp::client;
    use std::path::PathBuf;
    use tokio::io::{AsyncReadExt, duplex};

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join("mxhop-tests")
            .join(format!("{name}-{}", new_id()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    /// `example.com` is served: `hi` forwards, `team` forwards to two,
    /// `noreply` refuses, and there is no catch-all — so an unknown local part
    /// is not ours. `elsewhere.test` is not served at all.
    fn test_router() -> Router {
        let mut r = Router::default();
        r.insert(
            "example.com",
            "hi",
            Route::Forward(vec![Mailbox::parse("me@gmail.test").unwrap()]),
        );
        r.insert(
            "example.com",
            "team",
            Route::Forward(vec![
                Mailbox::parse("a@gmail.test").unwrap(),
                Mailbox::parse("b@fastmail.test").unwrap(),
            ]),
        );
        r.insert(
            "example.com",
            "noreply",
            Route::Reject("550 5.1.1 this address does not accept mail".into()),
        );
        r
    }

    /// A destination that answers however the test tells it to, and keeps
    /// what it was handed.
    ///
    /// The session must never be near a socket in a test, and this is the
    /// whole of what it asks of the delivery side: hand this on, and what is
    /// the peer called.
    #[derive(Clone, Default)]
    struct Fake {
        seen: std::sync::Arc<std::sync::Mutex<Vec<Delivery>>>,
        /// What each destination domain says. Anything not listed accepts.
        answers: std::collections::BTreeMap<String, client::Verdict>,
        ptr: Option<String>,
    }

    impl Fake {
        fn accepting() -> Self {
            Self {
                ptr: Some("mail.elsewhere.test".into()),
                ..Self::default()
            }
        }

        fn answering(domain: &str, verdict: client::Verdict) -> Self {
            let mut fake = Self::accepting();
            fake.answers.insert(domain.to_string(), verdict);
            fake
        }

        fn deliveries(&self) -> Vec<Delivery> {
            self.seen.lock().unwrap().clone()
        }

        fn only(&self) -> Delivery {
            let seen = self.deliveries();
            assert_eq!(seen.len(), 1, "expected one delivery, got {}", seen.len());
            seen.into_iter().next().unwrap()
        }
    }

    impl Relay for Fake {
        async fn deliver(&self, delivery: Delivery) -> client::Outcome {
            let domain = delivery.to[0].domain().to_string();
            let verdict = self
                .answers
                .get(&domain)
                .cloned()
                .unwrap_or(client::Verdict::Accepted);
            let results = delivery
                .to
                .iter()
                .map(|mailbox| client::RecipientResult {
                    mailbox: mailbox.clone(),
                    verdict: verdict.clone(),
                })
                .collect();
            self.seen.lock().unwrap().push(delivery);
            client::Outcome {
                host: Some(format!("mx.{domain}")),
                results,
            }
        }

        async fn ptr(&self, _ip: std::net::IpAddr) -> Option<String> {
            self.ptr.clone()
        }
    }

    /// A reply from a destination, as it would arrive off the wire.
    fn theirs(code: u16, enhanced: &str, text: &str) -> client::Reply {
        client::Reply {
            code,
            enhanced: Some(enhanced.to_string()),
            text: text.to_string(),
        }
    }

    struct Talk {
        out: String,
        spool: Spool,
        relay: Fake,
        outcome: Outcome,
    }

    impl Talk {
        /// The final reply codes, in order. Continuation lines (`250-…`) are
        /// part of one reply and are not counted twice.
        fn codes(&self) -> Vec<&str> {
            self.out
                .lines()
                .filter(|l| l.len() >= 4 && l.as_bytes()[3] == b' ' || l.len() == 3)
                .map(|l| &l[..3])
                .collect()
        }

        fn last_code(&self) -> &str {
            self.codes().last().copied().unwrap_or("")
        }
    }

    async fn talk_limited(limit: u64, script: &str) -> Talk {
        talk_with(Fake::accepting(), limit, script).await
    }

    async fn talk_with(relay: Fake, limit: u64, script: &str) -> Talk {
        let root = scratch("session");
        let spool = Spool::open(&root).await.unwrap();
        let config = SessionConfig {
            hostname: "mx.test".into(),
            max_message_bytes: limit,
            max_recipients: 3,
            max_errors: 4,
            command_timeout: Duration::from_secs(10),
            data_timeout: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(10),
            ptr_timeout: Duration::from_secs(10),
            limits: Limits::default(),
        };

        let (mut client, server) = duplex(256 * 1024);
        let spool_for_task = spool.clone();
        let relay_for_task = relay.clone();
        let task = tokio::spawn(async move {
            serve(
                server,
                "198.51.100.7:40000".to_string(),
                &config,
                &test_router(),
                &spool_for_task,
                &relay_for_task,
                None,
            )
            .await
        });

        client.write_all(script.as_bytes()).await.unwrap();
        client.shutdown().await.unwrap();
        let mut out = String::new();
        client.read_to_string(&mut out).await.unwrap();
        let outcome = task.await.unwrap().expect("the session should not fail");

        Talk {
            out,
            spool,
            relay,
            outcome,
        }
    }

    async fn talk(script: &str) -> Talk {
        talk_limited(26_214_400, script).await
    }

    const DELIVER: &str = "EHLO mail.elsewhere.test\r\n\
                           MAIL FROM:<sender@elsewhere.test>\r\n\
                           RCPT TO:<hi@example.com>\r\n\
                           DATA\r\n\
                           Subject: hello\r\n\
                           \r\n\
                           body\r\n\
                           .\r\n\
                           QUIT\r\n";

    /// A reply has to leave as one write. `openssl s_client -starttls smtp`
    /// reads the prologue with one `recv` per line and takes a segment
    /// without CRLF for a whole line; split the terminator off and its reader
    /// runs a line behind, sends its ClientHello early, and reads our
    /// `220 go ahead` as a TLS record — "wrong version number", with no
    /// handshake. Found by hand against a real listener.
    #[tokio::test]
    async fn a_reply_leaves_in_one_write() {
        struct Segments(std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>);

        impl AsyncWrite for Segments {
            fn poll_write(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
                buf: &[u8],
            ) -> std::task::Poll<io::Result<usize>> {
                self.0.lock().unwrap().push(buf.to_vec());
                std::task::Poll::Ready(Ok(buf.len()))
            }

            fn poll_flush(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }

            fn poll_shutdown(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }
        }

        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut out = Segments(std::sync::Arc::clone(&seen));
        say(&mut out, "220 mx.test mxhop ready").await.unwrap();

        let seen = seen.lock().unwrap();
        assert_eq!(
            *seen,
            vec![b"220 mx.test mxhop ready\r\n".to_vec()],
            "line and terminator together, or a line-at-a-time reader loses its place"
        );
    }

    #[tokio::test]
    async fn the_greeting_names_the_host_and_quit_is_answered() {
        let t = talk("QUIT\r\n").await;

        assert!(t.out.starts_with("220 mx.test"), "{}", t.out);
        assert_eq!(t.last_code(), "221");
        assert!(t.outcome.quit);
    }

    #[tokio::test]
    async fn ehlo_advertises_only_what_is_implemented() {
        let t = talk("EHLO mail.elsewhere.test\r\nQUIT\r\n").await;

        assert!(t.out.contains("250-mx.test"), "{}", t.out);
        assert!(t.out.contains("SIZE 26214400"), "{}", t.out);
        assert!(t.out.contains("8BITMIME"), "{}", t.out);
        assert!(t.out.contains("PIPELINING"), "{}", t.out);
        assert!(
            !t.out.contains("SMTPUTF8"),
            "offering it would mean promising to carry addresses we refuse: {}",
            t.out
        );
    }

    #[tokio::test]
    async fn helo_gets_one_line_without_extensions() {
        let t = talk("HELO mail.elsewhere.test\r\nQUIT\r\n").await;

        assert!(t.out.contains("250 mx.test"), "{}", t.out);
        assert!(!t.out.contains("250-"), "{}", t.out);
    }

    #[tokio::test]
    async fn mail_before_a_greeting_is_out_of_order() {
        let t = talk("MAIL FROM:<a@b.test>\r\nQUIT\r\n").await;
        assert_eq!(t.codes(), vec!["220", "503", "221"]);
    }

    #[tokio::test]
    async fn rcpt_before_mail_is_out_of_order() {
        let t = talk("EHLO x.test\r\nRCPT TO:<hi@example.com>\r\nQUIT\r\n").await;
        assert_eq!(t.codes(), vec!["220", "250", "503", "221"]);
    }

    #[tokio::test]
    async fn data_without_a_recipient_is_out_of_order() {
        let t = talk("EHLO x.test\r\nMAIL FROM:<a@b.test>\r\nDATA\r\nQUIT\r\n").await;
        assert_eq!(t.codes(), vec!["220", "250", "250", "503", "221"]);
    }

    #[tokio::test]
    async fn an_unknown_local_part_in_our_own_domain_is_refused() {
        let t =
            talk("EHLO x.test\r\nMAIL FROM:<a@b.test>\r\nRCPT TO:<nobody@example.com>\r\nQUIT\r\n")
                .await;

        assert_eq!(t.codes(), vec!["220", "250", "250", "550", "221"]);
        assert!(t.out.contains("5.1.1"), "{}", t.out);
    }

    #[tokio::test]
    async fn a_domain_we_do_not_serve_is_refused_as_relaying() {
        let t = talk(
            "EHLO x.test\r\nMAIL FROM:<a@b.test>\r\nRCPT TO:<someone@elsewhere.test>\r\nQUIT\r\n",
        )
        .await;

        assert_eq!(t.codes(), vec!["220", "250", "250", "550", "221"]);
        assert!(
            t.out.contains("5.7.1"),
            "relaying is a different refusal from an unknown address, and \
             saying so is how an operator finds a misconfigured MX: {}",
            t.out
        );
    }

    #[tokio::test]
    async fn a_rejecting_alias_answers_with_the_configured_reply() {
        let t = talk(
            "EHLO x.test\r\nMAIL FROM:<a@b.test>\r\nRCPT TO:<noreply@example.com>\r\nQUIT\r\n",
        )
        .await;

        assert!(
            t.out
                .contains("550 5.1.1 this address does not accept mail"),
            "{}",
            t.out
        );
    }

    #[tokio::test]
    async fn a_complete_delivery_is_accepted_and_handed_on() {
        let t = talk(DELIVER).await;

        assert_eq!(
            t.codes(),
            vec!["220", "250", "250", "250", "354", "250", "221"]
        );
        assert_eq!(t.outcome.accepted, 1);

        // What used to be read back out of the spool is read off the
        // delivery: a message that arrived is handed on inside the session
        // and never stored.
        let delivery = t.relay.only();
        assert_eq!(delivery.from.as_deref(), Some("sender@elsewhere.test"));
        assert_eq!(
            String::from_utf8(delivery.body.to_vec()).unwrap(),
            "Subject: hello\r\n\r\nbody\r\n"
        );
    }

    #[tokio::test]
    async fn the_acceptance_names_the_queue_id_so_the_log_can_be_followed() {
        let t = talk(DELIVER).await;
        let head = String::from_utf8(t.relay.only().head.clone()).unwrap();
        let id = head
            .split("with ESMTP id ")
            .nth(1)
            .and_then(|rest| rest.split("\r\n").next())
            .expect("the trace names the id")
            .to_string();

        assert!(
            t.out.contains(&id),
            "the sender's log, our trace and ours have to be joinable: {} / {head}",
            t.out
        );
    }

    #[tokio::test]
    async fn dot_stuffing_is_undone_before_the_message_leaves() {
        let script = "EHLO x.test\r\nMAIL FROM:<a@b.test>\r\nRCPT TO:<hi@example.com>\r\nDATA\r\n\
                      a line\r\n..stuffed\r\n.\r\nQUIT\r\n";
        let t = talk(script).await;

        assert_eq!(
            String::from_utf8(t.relay.only().body.to_vec()).unwrap(),
            "a line\r\n.stuffed\r\n",
            "the client's stuffing is the transport's, not the message's; the \
             outbound side puts its own back"
        );
    }

    #[tokio::test]
    async fn every_accepted_recipient_reaches_a_delivery() {
        let script = "EHLO x.test\r\nMAIL FROM:<a@b.test>\r\n\
                      RCPT TO:<hi@example.com>\r\nRCPT TO:<team@example.com>\r\n\
                      DATA\r\nbody\r\n.\r\nQUIT\r\n";
        let t = talk(script).await;

        let mut reached: Vec<String> = t
            .relay
            .deliveries()
            .iter()
            .flat_map(|d| d.to.iter())
            .map(ToString::to_string)
            .collect();
        reached.sort();
        assert_eq!(
            reached,
            vec!["a@gmail.test", "b@fastmail.test", "me@gmail.test"],
            "both aliases are expanded, and me@ and a@ are different mailboxes"
        );
    }

    #[tokio::test]
    async fn a_refused_recipient_does_not_stop_the_accepted_one() {
        let script = "EHLO x.test\r\nMAIL FROM:<a@b.test>\r\n\
                      RCPT TO:<nobody@example.com>\r\nRCPT TO:<hi@example.com>\r\n\
                      DATA\r\nbody\r\n.\r\nQUIT\r\n";
        let t = talk(script).await;

        assert_eq!(
            t.codes(),
            vec!["220", "250", "250", "550", "250", "354", "250", "221"]
        );
        assert_eq!(
            t.relay
                .only()
                .to
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            vec!["me@gmail.test"],
            "the refused recipient is not on the delivery either"
        );
    }

    #[tokio::test]
    async fn rset_forgets_the_envelope() {
        let script = "EHLO x.test\r\nMAIL FROM:<a@b.test>\r\nRCPT TO:<hi@example.com>\r\n\
                      RSET\r\nRCPT TO:<hi@example.com>\r\nQUIT\r\n";
        let t = talk(script).await;

        assert_eq!(
            t.codes(),
            vec!["220", "250", "250", "250", "250", "503", "221"],
            "after RSET there is no sender, so RCPT is out of order again"
        );
    }

    #[tokio::test]
    async fn one_session_may_carry_two_messages() {
        let script = "EHLO x.test\r\n\
                      MAIL FROM:<a@b.test>\r\nRCPT TO:<hi@example.com>\r\nDATA\r\none\r\n.\r\n\
                      MAIL FROM:<c@d.test>\r\nRCPT TO:<team@example.com>\r\nDATA\r\ntwo\r\n.\r\n\
                      QUIT\r\n";
        let t = talk(script).await;

        assert_eq!(t.outcome.accepted, 2);
        assert_eq!(
            t.relay.deliveries().len(),
            3,
            "two messages, and the second one's alias leads to two domains: three \
             connections, and nothing stored for any of them"
        );
        assert!(t.spool.queued().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_null_sender_is_accepted_because_bounces_use_it() {
        let script =
            "EHLO x.test\r\nMAIL FROM:<>\r\nRCPT TO:<hi@example.com>\r\nDATA\r\nb\r\n.\r\nQUIT\r\n";
        let t = talk(script).await;

        assert_eq!(t.outcome.accepted, 1);
        assert!(
            t.relay.only().from.is_none(),
            "a bounce goes out with the null sender it arrived with, or the \
             destination can bounce it back at us"
        );
    }

    // ------------------------------------------------- handing the message on

    /// The whole point of the milestone. Before this the session answered
    /// `250 queued as …` and the message sat in `queue/` with nothing to
    /// collect it, so every sender was told the mail had been accepted and
    /// nobody ever received it.
    #[tokio::test]
    async fn a_delivered_message_is_not_stored() {
        let t = talk(DELIVER).await;

        assert_eq!(t.last_code(), "221");
        assert!(
            t.out.contains("250 2.0.0 delivered as "),
            "the sender is told it was delivered, not queued: {}",
            t.out
        );
        assert_eq!(t.outcome.accepted, 1);
        assert!(
            t.spool.queued().await.unwrap().is_empty(),
            "nothing is left over, so nothing is in the queue"
        );
        assert_eq!(
            t.relay
                .only()
                .to
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            vec!["me@gmail.test"],
            "the alias is resolved before the message leaves"
        );
    }

    /// The stored message is the sender's bytes and nothing else, and the
    /// trace is prepended on the wire. A `Received` baked into the stored
    /// file would be written twice on a retry.
    #[tokio::test]
    async fn the_received_header_is_prepended_on_the_wire() {
        let t = talk(DELIVER).await;
        let delivery = t.relay.only();
        let head = String::from_utf8(delivery.head.clone()).unwrap();

        assert!(
            head.starts_with(
                "Received: from mail.elsewhere.test (mail.elsewhere.test [198.51.100.7])\r\n"
            ),
            "{head:?}"
        );
        assert!(
            head.contains("by mx.test (mxhop) with ESMTP id "),
            "{head:?}"
        );
        assert!(
            head.contains("for <hi@example.com>;"),
            "one recipient, so the for clause is written: {head:?}"
        );
        assert_eq!(
            String::from_utf8(delivery.body.to_vec()).unwrap(),
            "Subject: hello\r\n\r\nbody\r\n",
            "the message itself is untouched"
        );
    }

    /// A crafted HELO name reaching the header would let a stranger forge a
    /// trace line — or an `Authentication-Results` the destination believes.
    /// The session is the place this arrives from, so it is checked here too
    /// and not only in `policy`.
    #[tokio::test]
    async fn a_crafted_helo_cannot_forge_a_header_through_the_session() {
        // A HELO name that is not domain-shaped: the parser keeps it, and
        // only the sanitising stops it reaching the header.
        let script = "EHLO not a domain\r\nMAIL FROM:<a@b.test>\r\nRCPT TO:<hi@example.com>\r\n\
                      DATA\r\nbody\r\n.\r\nQUIT\r\n";
        let t = talk(script).await;
        let head = String::from_utf8(t.relay.only().head.clone()).unwrap();

        assert!(
            head.starts_with("Received: from unknown ("),
            "a name that is not domain-shaped is reported as unknown: {head:?}"
        );
        for line in head.trim_end_matches("\r\n").split("\r\n").skip(1) {
            assert!(
                line.starts_with(' ') || line.starts_with('\t'),
                "every line after the first is a fold: {line:?}"
            );
        }
    }

    /// The reply a forwarder exists to relay. Gmail's own sentence tells the
    /// person who mistyped an address what is wrong with it; "delivery
    /// failed, contact your postmaster" from a host they have never heard of
    /// does not.
    #[tokio::test]
    async fn a_destination_5xx_reaches_the_sending_server_inside_the_same_session() {
        let refusing = Fake::answering(
            "gmail.test",
            client::Verdict::Refused(theirs(
                550,
                "5.1.1",
                "The email account that you tried to reach does not exist.",
            )),
        );
        let t = talk_with(refusing, 26_214_400, DELIVER).await;

        assert_eq!(
            t.codes(),
            vec!["220", "250", "250", "250", "354", "550", "221"]
        );
        assert!(
            t.out.contains(
                "550 5.1.1 mx.gmail.test said: The email account that you tried to reach \
                 does not exist."
            ),
            "the destination's own code and words, attributed: {}",
            t.out
        );
        assert_eq!(t.outcome.accepted, 0);
        assert!(
            t.spool.queued().await.unwrap().is_empty(),
            "a refusal is nobody's to retry, so nothing is kept"
        );
    }

    /// A deferral means nothing is known yet. The sending server still has
    /// the message and a retry queue of its own; mxhop has neither.
    #[tokio::test]
    async fn a_deferral_is_451_and_the_spool_stays_empty() {
        let slow = Fake::answering(
            "gmail.test",
            client::Verdict::Deferred(theirs(451, "4.3.2", "Try again later")),
        );
        let t = talk_with(slow, 26_214_400, DELIVER).await;

        assert_eq!(t.last_code(), "221");
        assert!(
            t.out
                .contains("451 4.3.2 mx.gmail.test said: Try again later"),
            "{}",
            t.out
        );
        assert_eq!(t.outcome.accepted, 0);
        assert!(
            t.spool.queued().await.unwrap().is_empty(),
            "answering 451 and keeping it too would make us responsible for a retry \
             we cannot perform"
        );
    }

    /// One of two destinations took it, so the sender must not send it again
    /// — which means 250 — and the other recipient's copy is ours to keep.
    #[tokio::test]
    async fn a_mixed_outcome_is_250_and_holds_the_rest() {
        let half = Fake::answering(
            "fastmail.test",
            client::Verdict::Deferred(theirs(451, "4.3.2", "Try again later")),
        );
        let script = "EHLO x.test\r\nMAIL FROM:<a@b.test>\r\nRCPT TO:<team@example.com>\r\n\
                      DATA\r\nbody\r\n.\r\nQUIT\r\n";
        let t = talk_with(half, 26_214_400, script).await;

        assert!(t.out.contains("250 2.0.0 delivered as "), "{}", t.out);
        let queued = t.spool.queued().await.unwrap();
        assert_eq!(queued.len(), 1, "the undelivered copy is held");
        assert_eq!(
            queued[0].to,
            vec!["b@fastmail.test"],
            "held for the recipient that has not had it, and nobody else"
        );
        assert!(
            queued[0].received.starts_with("Received: from x.test"),
            "the trace travels with the held copy so a retry sends identical bytes: {:?}",
            queued[0].received
        );
        assert!(
            queued[0]
                .last_reply
                .as_deref()
                .is_some_and(|r| r.contains("Try again later")),
            "the operator reading queue/ has to see why it is there: {:?}",
            queued[0].last_reply
        );
        assert_eq!(
            String::from_utf8(t.spool.body(&queued[0].id).await.unwrap()).unwrap(),
            "body\r\n",
            "the stored file is the message as it arrived, with no header of ours in it"
        );
    }

    /// The guarantee the spool gave before anything was delivered, kept: a
    /// half-written message in `tmp/` is either renamed into the queue whole
    /// or is not there at all.
    #[tokio::test]
    async fn a_crash_between_delivery_and_250_leaves_nothing_in_tmp() {
        let half = Fake::answering(
            "fastmail.test",
            client::Verdict::Deferred(theirs(451, "4.3.2", "Try again later")),
        );
        let script = "EHLO x.test\r\nMAIL FROM:<a@b.test>\r\nRCPT TO:<team@example.com>\r\n\
                      DATA\r\nbody\r\n.\r\nQUIT\r\n";
        let t = talk_with(half, 26_214_400, script).await;

        assert_eq!(
            std::fs::read_dir(t.spool.tmp_dir()).unwrap().count(),
            0,
            "tmp/ is a staging area, and anything left in it is a message nobody \
             will ever look at"
        );
    }

    /// One alias leading to two destinations is two connections, and each
    /// one carries only its own recipient: an envelope that named the other
    /// would tell each destination where else the alias forwards.
    #[tokio::test]
    async fn two_destinations_are_two_deliveries() {
        let script = "EHLO x.test\r\nMAIL FROM:<a@b.test>\r\nRCPT TO:<team@example.com>\r\n\
                      DATA\r\nbody\r\n.\r\nQUIT\r\n";
        let t = talk_with(Fake::accepting(), 26_214_400, script).await;

        let mut domains: Vec<String> = t
            .relay
            .deliveries()
            .iter()
            .map(|d| d.to[0].domain().to_string())
            .collect();
        domains.sort();
        assert_eq!(domains, vec!["fastmail.test", "gmail.test"]);
        for delivery in t.relay.deliveries() {
            assert_eq!(delivery.to.len(), 1);
            assert!(
                String::from_utf8(delivery.head.clone())
                    .unwrap()
                    .contains("for <team@example.com>;"),
                "the for clause names the address the sender wrote to — the alias — \
                 and so says nothing about where the alias forwards"
            );
        }
    }

    /// The loop the alias table cannot see, arriving as a real message: our
    /// own name already in the trace three times means the message has been
    /// here before and is going round.
    ///
    /// Folded, like every `Received` header a real mail server writes, and
    /// with our name in the `by` clause on the continuation line where real
    /// ones put it. Written unfolded this test passed while the scanner was
    /// counting nothing at all in production.
    #[tokio::test]
    async fn a_message_that_has_been_here_three_times_is_refused_554() {
        let script = "EHLO x.test\r\nMAIL FROM:<a@b.test>\r\nRCPT TO:<hi@example.com>\r\nDATA\r\n\
                      Received: from a.test (a.test [10.0.0.1])\r\n\
                      \tby mx.test (mxhop) with ESMTPS id 1;\r\n\
                      \tThu, 06 Nov 2026 10:00:00 +0000\r\n\
                      Received: from b.test (b.test [10.0.0.2])\r\n\
                      \tby mx.test (mxhop) with ESMTPS id 2;\r\n\
                      \tThu, 06 Nov 2026 10:00:01 +0000\r\n\
                      Received: from c.test (c.test [10.0.0.3])\r\n\
                      \tby mx.test (mxhop) with ESMTPS id 3;\r\n\
                      \tThu, 06 Nov 2026 10:00:02 +0000\r\n\
                      Content-Type: text/plain;\r\n\
                      \tcharset=utf-8\r\n\
                      \r\n\
                      body\r\n.\r\nQUIT\r\n";
        let t = talk(script).await;

        assert_eq!(t.last_code(), "221");
        assert!(t.out.contains("554 5.4.6"), "{}", t.out);
        assert!(
            t.relay.deliveries().is_empty(),
            "a message in a loop is not handed on"
        );
        assert!(t.spool.queued().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_unknown_command_is_refused_without_ending_the_session() {
        let t = talk("EHLO x.test\r\nWHAT\r\nQUIT\r\n").await;
        assert_eq!(t.codes(), vec!["220", "250", "500", "221"]);
    }

    #[tokio::test]
    async fn starttls_without_a_certificate_is_refused_as_not_offered() {
        let t = talk("EHLO x.test\r\nSTARTTLS\r\nQUIT\r\n").await;

        assert_eq!(t.codes(), vec!["220", "250", "502", "221"]);
        assert!(
            t.out.contains("502 5.5.1 STARTTLS is not offered here"),
            "a client that asks for something not advertised gets told, not hung up on: {}",
            t.out
        );
    }

    #[tokio::test]
    async fn vrfy_is_answered_but_tells_nothing() {
        let t = talk("EHLO x.test\r\nVRFY hi@example.com\r\nQUIT\r\n").await;

        assert_eq!(t.codes(), vec!["220", "250", "252", "221"]);
        assert!(
            !t.out.contains("me@gmail.test"),
            "an alias table is not a directory for strangers: {}",
            t.out
        );
    }

    #[tokio::test]
    async fn a_client_that_only_makes_mistakes_is_shown_the_door() {
        let t = talk("WHAT\r\nWHAT\r\nWHAT\r\nWHAT\r\nWHAT\r\nEHLO x.test\r\n").await;

        assert_eq!(
            t.last_code(),
            "421",
            "four refusals is enough to stop talking: {}",
            t.out
        );
        assert!(!t.outcome.quit);
    }

    #[tokio::test]
    async fn a_message_over_the_limit_is_refused() {
        let script = "EHLO x.test\r\nMAIL FROM:<a@b.test>\r\nRCPT TO:<hi@example.com>\r\nDATA\r\n\
                      0123456789\r\n0123456789\r\n.\r\n";
        let t = talk_limited(12, script).await;

        assert_eq!(t.last_code(), "552");
        assert!(
            t.spool.queued().await.unwrap().is_empty(),
            "nothing half-read may reach the queue"
        );
    }

    #[tokio::test]
    async fn an_announced_size_over_the_limit_is_refused_before_the_body() {
        let script = "EHLO x.test\r\nMAIL FROM:<a@b.test> SIZE=999999\r\nQUIT\r\n";
        let t = talk_limited(1024, script).await;

        assert_eq!(
            t.codes(),
            vec!["220", "250", "552", "221"],
            "the client said how big it is; reading it anyway would be rude to both of us"
        );
    }

    #[tokio::test]
    async fn more_recipients_than_allowed_are_asked_to_come_back() {
        let script = "EHLO x.test\r\nMAIL FROM:<a@b.test>\r\n\
                      RCPT TO:<hi@example.com>\r\nRCPT TO:<team@example.com>\r\n\
                      RCPT TO:<hi@example.com>\r\nRCPT TO:<team@example.com>\r\nQUIT\r\n";
        let t = talk(script).await;

        assert_eq!(t.last_code(), "221");
        assert!(
            t.out.contains("452"),
            "452 is temporary: the client should try the rest in another message: {}",
            t.out
        );
    }

    #[tokio::test]
    async fn a_non_ascii_recipient_is_refused_with_the_reason() {
        let t =
            talk("EHLO x.test\r\nMAIL FROM:<a@b.test>\r\nRCPT TO:<почта@example.com>\r\nQUIT\r\n")
                .await;

        assert!(t.out.contains("550 5.6.7"), "{}", t.out);
    }

    #[tokio::test]
    async fn a_client_that_says_nothing_is_dropped_rather_than_held_forever() {
        // This one keeps its end of the pipe open, so only the server's own
        // timeout can end it.
        let root = scratch("timeout");
        let spool = Spool::open(&root).await.unwrap();
        let config = SessionConfig {
            hostname: "mx.test".into(),
            max_message_bytes: 1024,
            max_recipients: 3,
            max_errors: 4,
            command_timeout: Duration::from_millis(50),
            data_timeout: Duration::from_millis(50),
            handshake_timeout: Duration::from_millis(50),
            ptr_timeout: Duration::from_secs(10),
            limits: Limits::default(),
        };

        let (mut client, server) = duplex(4096);
        let task = tokio::spawn(async move {
            serve(
                server,
                "198.51.100.7:40000".to_string(),
                &config,
                &test_router(),
                &spool,
                &Fake::accepting(),
                None,
            )
            .await
        });

        let mut out = String::new();
        client.read_to_string(&mut out).await.unwrap();
        let outcome = task.await.unwrap().unwrap();

        assert!(out.contains("421 4.4.2"), "{out}");
        assert!(!outcome.quit);
    }

    #[tokio::test]
    async fn a_client_that_vanishes_mid_session_is_not_an_error() {
        let t = talk("EHLO x.test\r\nMAIL FROM:<a@b.test>\r\n").await;

        assert_eq!(t.outcome.accepted, 0);
        assert!(!t.outcome.quit);
        assert!(t.spool.queued().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_client_that_vanishes_inside_data_leaves_nothing_behind() {
        let script = "EHLO x.test\r\nMAIL FROM:<a@b.test>\r\nRCPT TO:<hi@example.com>\r\nDATA\r\nhalf a message\r\n";
        let t = talk(script).await;

        assert_eq!(t.outcome.accepted, 0);
        assert!(t.spool.queued().await.unwrap().is_empty());
        assert!(
            std::fs::read_dir(t.spool.tmp_dir())
                .unwrap()
                .next()
                .is_none(),
            "and nothing in tmp either"
        );
    }

    // --------------------------------------------------------------- STARTTLS

    use crate::config::TlsPaths;
    use crate::tls::{Holder, testing};
    use rustls_pki_types::pem::PemObject;
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, DuplexStream};
    use tokio_rustls::TlsConnector;
    use tokio_rustls::rustls::{self, ClientConfig};

    /// A server-side acceptor for a freshly generated certificate, together
    /// with the leaf DER, so a test can say *which* certificate was served.
    fn acceptor(common_name: &str) -> (tokio_rustls::TlsAcceptor, Vec<u8>) {
        let dir = testing::scratch("session-tls");
        let (crt, key) = testing::write(&dir, "mx", common_name);
        let der = rustls_pki_types::CertificateDer::from_pem_file(&crt)
            .expect("read the leaf back")
            .as_ref()
            .to_vec();
        let holder = Holder::open(TlsPaths {
            certificate: crt,
            key,
            line: None,
        })
        .expect("a generated pair loads");
        (holder.acceptor(), der)
    }

    /// These tests are about mxhop's side of the handshake, not about PKI, so
    /// the client checks nothing. The boilerplate buys one thing:
    /// `peer_certificates()`, which is how a test proves which certificate
    /// came out of the holder.
    #[derive(Debug)]
    struct AcceptAnything(Arc<rustls::crypto::CryptoProvider>);

    impl rustls::client::danger::ServerCertVerifier for AcceptAnything {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls_pki_types::CertificateDer<'_>,
            _intermediates: &[rustls_pki_types::CertificateDer<'_>],
            _server_name: &rustls_pki_types::ServerName<'_>,
            _ocsp: &[u8],
            _now: rustls_pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &rustls_pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &rustls_pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    /// Collects log output so a test can assert a line was written.
    /// `#[tokio::test]` builds a current-thread runtime, so the session task
    /// spawned inside the test body is polled on this same thread and sees
    /// the subscriber `set_default` installed here.
    #[derive(Clone, Default)]
    struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

    impl Captured {
        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().expect("captured logs")).into_owned()
        }
    }

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("captured logs").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl tracing_subscriber::fmt::MakeWriter<'_> for Captured {
        type Writer = Self;

        fn make_writer(&self) -> Self::Writer {
            self.clone()
        }
    }

    fn connector() -> TlsConnector {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .expect("the default versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnything(provider)))
            .with_no_client_auth();
        TlsConnector::from(Arc::new(config))
    }

    /// The client's side of a session: whole replies in, commands out.
    struct Peer<S> {
        io: BufReader<S>,
    }

    impl<S: AsyncRead + AsyncWrite + Unpin> Peer<S> {
        fn new(io: S) -> Self {
            Self {
                io: BufReader::new(io),
            }
        }

        /// One reply, continuation lines included.
        async fn reply(&mut self) -> String {
            let mut whole = String::new();
            loop {
                let mut line = String::new();
                if self.io.read_line(&mut line).await.expect("read a reply") == 0 {
                    break;
                }
                let continues = line.as_bytes().get(3) == Some(&b'-');
                whole.push_str(&line);
                if !continues {
                    break;
                }
            }
            whole
        }

        async fn send(&mut self, text: &str) {
            let io = self.io.get_mut();
            io.write_all(text.as_bytes()).await.expect("write");
            io.flush().await.expect("flush");
        }

        /// Whatever is left once the server is finished.
        async fn rest(&mut self) -> String {
            let mut rest = String::new();
            self.io.read_to_string(&mut rest).await.expect("read rest");
            rest
        }
    }

    struct Served {
        spool: Spool,
        task: tokio::task::JoinHandle<Result<Outcome, WireError>>,
    }

    async fn serve_with_tls(common_name: &str) -> (Peer<DuplexStream>, Served, Vec<u8>) {
        let (acceptor, der) = acceptor(common_name);
        let root = scratch("session-tls");
        let spool = Spool::open(&root).await.unwrap();
        let config = SessionConfig {
            hostname: "mx.test".into(),
            max_message_bytes: 26_214_400,
            max_recipients: 3,
            max_errors: 4,
            command_timeout: Duration::from_secs(10),
            data_timeout: Duration::from_secs(10),
            handshake_timeout: Duration::from_millis(200),
            ptr_timeout: Duration::from_secs(10),
            limits: Limits::default(),
        };

        let (client, server) = duplex(256 * 1024);
        let spool_for_task = spool.clone();
        let task = tokio::spawn(async move {
            serve(
                server,
                "198.51.100.7:40000".to_string(),
                &config,
                &test_router(),
                &spool_for_task,
                &Fake::accepting(),
                Some(acceptor),
            )
            .await
        });

        (Peer::new(client), Served { spool, task }, der)
    }

    async fn upgrade(
        client: Peer<DuplexStream>,
        expected_leaf: &[u8],
    ) -> Peer<impl AsyncRead + AsyncWrite + Unpin> {
        assert!(
            client.io.buffer().is_empty(),
            "the test client must not swallow bytes meant for the tunnel"
        );
        let name = rustls_pki_types::ServerName::try_from("mx.test").unwrap();
        let stream = connector()
            .connect(name, client.io.into_inner())
            .await
            .expect("the handshake should succeed");

        let served = stream
            .get_ref()
            .1
            .peer_certificates()
            .expect("the server sent a certificate")[0]
            .as_ref()
            .to_vec();
        assert_eq!(
            served, expected_leaf,
            "the certificate must be the one the holder loaded"
        );

        Peer::new(stream)
    }

    #[tokio::test]
    async fn ehlo_offers_starttls_only_with_a_certificate() {
        let plain = talk("EHLO x.test\r\nQUIT\r\n").await;
        assert!(
            !plain.out.contains("STARTTLS"),
            "nothing is advertised that is not configured: {}",
            plain.out
        );

        let (mut client, served, _) = serve_with_tls("mx.test").await;
        client.reply().await;
        client.send("EHLO x.test\r\n").await;
        let greeting = client.reply().await;
        client.send("QUIT\r\n").await;
        client.reply().await;
        served.task.await.unwrap().unwrap();

        assert!(greeting.contains("250-STARTTLS"), "{greeting}");
    }

    /// An implementation that requires TLS loses mail: this is an MX, and a
    /// sender that offers no TLS still has to be able to deliver.
    #[tokio::test]
    async fn plaintext_delivery_still_works_when_tls_is_configured() {
        let (mut client, served, _) = serve_with_tls("mx.test").await;
        client.reply().await;
        client.send(DELIVER).await;
        let rest = client.rest().await;
        let outcome = served.task.await.unwrap().unwrap();

        assert_eq!(outcome.accepted, 1, "{rest}");
        assert!(!outcome.tls);
        assert!(rest.contains("250 2.0.0 delivered as "), "{rest}");
        assert!(served.spool.queued().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_message_is_delivered_inside_the_tunnel() {
        let (mut client, served, der) = serve_with_tls("mx.test").await;
        client.reply().await;
        client.send("EHLO x.test\r\n").await;
        client.reply().await;
        client.send("STARTTLS\r\n").await;
        assert!(client.reply().await.starts_with("220 2.0.0"));

        let mut inside = upgrade(client, &der).await;
        inside.send(DELIVER).await;
        let rest = inside.rest().await;
        let outcome = served.task.await.unwrap().unwrap();

        assert_eq!(outcome.accepted, 1, "{rest}");
        assert!(
            outcome.tls,
            "the log line has to say the session was encrypted"
        );
        assert!(rest.contains("250 2.0.0 delivered as "), "{rest}");
        assert!(served.spool.queued().await.unwrap().is_empty());
    }

    /// RFC 3207 §4.2. If this is forgotten, an EHLO or MAIL an attacker
    /// injected before the handshake is honoured inside the tunnel, and the
    /// spooled envelope's `helo` claims an identity nobody authenticated.
    #[tokio::test]
    async fn the_handshake_discards_helo_and_envelope() {
        let (mut client, served, der) = serve_with_tls("mx.test").await;
        client.reply().await;
        client.send("EHLO before.test\r\n").await;
        client.reply().await;
        client.send("MAIL FROM:<a@b.test>\r\n").await;
        client.reply().await;
        client.send("STARTTLS\r\n").await;
        client.reply().await;

        let mut inside = upgrade(client, &der).await;
        inside.send("MAIL FROM:<a@b.test>\r\n").await;
        let answer = inside.reply().await;
        inside.send("QUIT\r\n").await;
        inside.reply().await;
        served.task.await.unwrap().unwrap();

        assert!(
            answer.starts_with("503"),
            "the greeting went with everything else: {answer}"
        );
    }

    #[tokio::test]
    async fn after_the_handshake_ehlo_no_longer_offers_starttls() {
        let (mut client, served, der) = serve_with_tls("mx.test").await;
        client.reply().await;
        client.send("STARTTLS\r\n").await;
        client.reply().await;

        let mut inside = upgrade(client, &der).await;
        inside.send("EHLO x.test\r\n").await;
        let greeting = inside.reply().await;
        inside.send("QUIT\r\n").await;
        inside.reply().await;
        served.task.await.unwrap().unwrap();

        assert!(
            !greeting.contains("STARTTLS"),
            "RFC 3207 §4.2 forbids re-offering it: {greeting}"
        );
    }

    #[tokio::test]
    async fn starttls_twice_is_refused() {
        let (mut client, served, der) = serve_with_tls("mx.test").await;
        client.reply().await;
        client.send("STARTTLS\r\n").await;
        client.reply().await;

        let mut inside = upgrade(client, &der).await;
        inside.send("STARTTLS\r\n").await;
        let answer = inside.reply().await;
        inside.send("QUIT\r\n").await;
        inside.reply().await;
        served.task.await.unwrap().unwrap();

        assert!(answer.starts_with("503 5.5.1"), "{answer}");
    }

    /// CVE-2011-0411. Bytes pipelined behind STARTTLS belong to the plaintext
    /// conversation; replaying them inside the tunnel would let anyone on the
    /// path inject commands the client believes it sent encrypted.
    #[tokio::test]
    async fn commands_pipelined_behind_starttls_are_not_replayed() {
        let (mut client, served, _) = serve_with_tls("mx.test").await;
        client.reply().await;
        client
            .send("EHLO x.test\r\nSTARTTLS\r\nMAIL FROM:<attacker@evil.test>\r\n")
            .await;
        client.reply().await; // the EHLO
        let answer = client.reply().await;
        let rest = client.rest().await;
        let outcome = served.task.await.unwrap().unwrap();

        assert!(
            answer.starts_with("554 5.5.1"),
            "the injected line ends the session rather than riding into the tunnel: {answer}"
        );
        assert!(
            !answer.contains("220") && !rest.contains("220"),
            "and no handshake may begin: {answer}{rest}"
        );
        assert_eq!(outcome.accepted, 0);
        assert!(!outcome.tls);
    }

    /// Looks like an SMTP reply: three digits and a space or a hyphen. Used
    /// to assert the *absence* of any reply, which naming two codes cannot
    /// do — a stray `say("554 …")` on a path that must stay silent would slip
    /// past a test that only looks for `500` and `421`.
    fn is_reply_line(line: &str) -> bool {
        let bytes = line.as_bytes();
        bytes.len() >= 4
            && bytes[..3].iter().all(u8::is_ascii_digit)
            && (bytes[3] == b' ' || bytes[3] == b'-')
    }

    #[tokio::test]
    async fn a_failed_handshake_ends_the_session_quietly() {
        let (mut client, served, _) = serve_with_tls("mx.test").await;
        client.reply().await;
        client.send("STARTTLS\r\n").await;
        assert!(client.reply().await.starts_with("220"));

        // Not a TLS ClientHello but a whole plaintext SMTP transaction: the
        // case of an attacker's commands arriving *after* the go-ahead.
        // Scanners send nonsense here all day and that is not a session
        // failure; what must never happen is mxhop answering in the clear, or
        // spooling a message, on a connection it has already promised to
        // encrypt.
        client.send(DELIVER).await;
        let rest = client.rest().await;
        let outcome = served.task.await.unwrap().expect("not a session failure");

        let replied: Vec<&str> = rest.lines().filter(|line| is_reply_line(line)).collect();
        assert!(
            replied.is_empty(),
            "a broken handshake admits no SMTP reply at all — there is no agreed encoding \
             left to send one in: {replied:?} in {rest:?}"
        );
        assert_eq!(
            served.spool.queued().await.unwrap().len(),
            0,
            "and nothing sent after the go-ahead may reach the queue"
        );
        assert_eq!(outcome.accepted, 0);
        assert!(!outcome.tls);
        assert!(!outcome.quit);
    }

    /// The reply alone leaves no trace: an operator watching an MX being
    /// probed for CVE-2011-0411 sees a session that simply ended.
    #[tokio::test]
    async fn an_injection_behind_starttls_is_logged_with_the_peer() {
        let logs = Captured::default();
        let _guard = tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_writer(logs.clone())
                .with_max_level(tracing::Level::INFO)
                .finish(),
        );

        let (mut client, served, _) = serve_with_tls("mx.test").await;
        client.reply().await;
        client
            .send("EHLO x.test\r\nSTARTTLS\r\nMAIL FROM:<attacker@evil.test>\r\n")
            .await;
        client.reply().await; // the EHLO
        client.reply().await; // the refusal
        client.rest().await;
        served.task.await.unwrap().unwrap();

        let written = logs.text();
        assert!(
            written.contains("198.51.100.7"),
            "the peer is the only part an operator can act on: {written}"
        );
        assert!(
            written.contains("pipelined behind STARTTLS"),
            "and the line has to say what was attempted: {written}"
        );
    }

    #[tokio::test]
    async fn a_client_that_stalls_in_the_handshake_is_dropped() {
        let (mut client, served, _) = serve_with_tls("mx.test").await;
        client.reply().await;
        client.send("STARTTLS\r\n").await;
        client.reply().await;

        // Says nothing at all: only the handshake timeout can end this.
        let outcome = timeout(Duration::from_secs(5), served.task)
            .await
            .expect("a stalled handshake must not hold the task open")
            .unwrap()
            .unwrap();

        assert!(!outcome.tls);
    }
}
