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
use tracing::info;

use crate::config::Config;
use crate::envelope::{Envelope, now_unix_ms};
use crate::routing::{Route, Router};
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
        }
    }
}

/// What happened, for the log line.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Outcome {
    /// Messages accepted into the queue.
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
pub async fn serve<S>(
    stream: S,
    peer: String,
    config: &SessionConfig,
    router: &Router,
    spool: &Spool,
    tls: Option<TlsAcceptor>,
) -> Result<Outcome, WireError>
where
    S: AsyncRead + AsyncWrite + Unpin,
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

    match talk(&mut reader, &mut state, config, router, spool, &peer, &tls).await? {
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
    let step = talk(&mut reader, &mut state, config, router, spool, &peer, &tls).await?;

    // `close_notify`, so the sender's own log does not record our goodbye as a
    // truncation attack. A client that has already gone is not an error here.
    let _ = reader.get_mut().shutdown().await;

    match step {
        Step::Done | Step::StartTls => Ok(state.outcome),
    }
}

/// The command loop, over whatever the stream currently is.
async fn talk<S>(
    reader: &mut BufReader<S>,
    state: &mut State,
    config: &SessionConfig,
    router: &Router,
    spool: &Spool,
    peer: &str,
    tls: &Option<TlsAcceptor>,
) -> Result<Step, WireError>
where
    S: AsyncRead + AsyncWrite + Unpin,
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
                let out = reader.get_mut();
                out.write_all(greeting.as_bytes()).await?;
                out.write_all(b"\r\n").await?;
                out.flush().await?;
            }

            Command::Helo(name) => {
                state.helo = Some(name);
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

                let envelope = Envelope {
                    id: new_id(),
                    from: state.from.clone().flatten(),
                    to: state.recipients.clone(),
                    helo: state.helo.clone().unwrap_or_default(),
                    peer: peer.to_string(),
                    received_at_unix_ms: now_unix_ms(),
                    size: body.len() as u64,
                };

                match spool.store(&envelope, &body).await {
                    Ok(()) => {
                        say(
                            reader.get_mut(),
                            &format!("250 2.0.0 queued as {}", envelope.id),
                        )
                        .await?;
                        state.outcome.accepted += 1;
                    }
                    Err(_) => {
                        // Temporary: the sender keeps the message and will
                        // try again, which is where it belongs if our disk is
                        // unhappy.
                        say(
                            reader.get_mut(),
                            "451 4.3.0 cannot queue the message right now",
                        )
                        .await?;
                    }
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

async fn say<W>(out: &mut W, line: &str) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    out.write_all(line.as_bytes()).await?;
    out.write_all(b"\r\n").await?;
    out.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::Mailbox;
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

    struct Talk {
        out: String,
        spool: Spool,
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
        };

        let (mut client, server) = duplex(256 * 1024);
        let spool_for_task = spool.clone();
        let task = tokio::spawn(async move {
            serve(
                server,
                "198.51.100.7:40000".to_string(),
                &config,
                &test_router(),
                &spool_for_task,
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
    async fn a_complete_delivery_is_accepted_and_stored() {
        let t = talk(DELIVER).await;

        assert_eq!(
            t.codes(),
            vec!["220", "250", "250", "250", "354", "250", "221"]
        );
        assert_eq!(t.outcome.accepted, 1);

        let queued = t.spool.queued().await.unwrap();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].from.as_deref(), Some("sender@elsewhere.test"));
        assert_eq!(queued[0].to, vec!["hi@example.com"]);
        assert_eq!(queued[0].helo, "mail.elsewhere.test");
        assert_eq!(queued[0].peer, "198.51.100.7:40000");

        let body = t.spool.body(&queued[0].id).await.unwrap();
        assert_eq!(
            String::from_utf8(body).unwrap(),
            "Subject: hello\r\n\r\nbody\r\n"
        );
    }

    #[tokio::test]
    async fn the_acceptance_names_the_queue_id_so_the_log_can_be_followed() {
        let t = talk(DELIVER).await;
        let queued = t.spool.queued().await.unwrap();

        assert!(
            t.out.contains(&queued[0].id),
            "the sender's log and ours have to be joinable: {}",
            t.out
        );
    }

    #[tokio::test]
    async fn dot_stuffing_is_undone_before_storing() {
        let script = "EHLO x.test\r\nMAIL FROM:<a@b.test>\r\nRCPT TO:<hi@example.com>\r\nDATA\r\n\
                      a line\r\n..stuffed\r\n.\r\nQUIT\r\n";
        let t = talk(script).await;
        let queued = t.spool.queued().await.unwrap();

        assert_eq!(
            String::from_utf8(t.spool.body(&queued[0].id).await.unwrap()).unwrap(),
            "a line\r\n.stuffed\r\n"
        );
    }

    #[tokio::test]
    async fn every_accepted_recipient_is_on_the_envelope() {
        let script = "EHLO x.test\r\nMAIL FROM:<a@b.test>\r\n\
                      RCPT TO:<hi@example.com>\r\nRCPT TO:<team@example.com>\r\n\
                      DATA\r\nbody\r\n.\r\nQUIT\r\n";
        let t = talk(script).await;
        let queued = t.spool.queued().await.unwrap();

        assert_eq!(queued[0].to, vec!["hi@example.com", "team@example.com"]);
    }

    #[tokio::test]
    async fn a_refused_recipient_does_not_stop_the_accepted_one() {
        let script = "EHLO x.test\r\nMAIL FROM:<a@b.test>\r\n\
                      RCPT TO:<nobody@example.com>\r\nRCPT TO:<hi@example.com>\r\n\
                      DATA\r\nbody\r\n.\r\nQUIT\r\n";
        let t = talk(script).await;
        let queued = t.spool.queued().await.unwrap();

        assert_eq!(
            t.codes(),
            vec!["220", "250", "250", "550", "250", "354", "250", "221"]
        );
        assert_eq!(queued[0].to, vec!["hi@example.com"]);
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
        assert_eq!(t.spool.queued().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn the_null_sender_is_accepted_because_bounces_use_it() {
        let script =
            "EHLO x.test\r\nMAIL FROM:<>\r\nRCPT TO:<hi@example.com>\r\nDATA\r\nb\r\n.\r\nQUIT\r\n";
        let t = talk(script).await;
        let queued = t.spool.queued().await.unwrap();

        assert_eq!(t.outcome.accepted, 1);
        assert!(queued[0].is_bounce());
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
        };

        let (mut client, server) = duplex(4096);
        let task = tokio::spawn(async move {
            serve(
                server,
                "198.51.100.7:40000".to_string(),
                &config,
                &test_router(),
                &spool,
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
        assert_eq!(served.spool.queued().await.unwrap().len(), 1);
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
        assert_eq!(served.spool.queued().await.unwrap().len(), 1);
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

    #[tokio::test]
    async fn a_failed_handshake_ends_the_session_quietly() {
        let (mut client, served, _) = serve_with_tls("mx.test").await;
        client.reply().await;
        client.send("STARTTLS\r\n").await;
        assert!(client.reply().await.starts_with("220"));

        // Not a TLS ClientHello. Scanners do this all day, and it is not a
        // session failure.
        client.send("GET / HTTP/1.1\r\n\r\n").await;
        let rest = client.rest().await;
        let outcome = served.task.await.unwrap().expect("not a session failure");

        assert!(
            !rest.contains("500") && !rest.contains("421"),
            "a broken handshake admits no SMTP reply: {rest:?}"
        );
        assert!(!outcome.tls);
        assert!(!outcome.quit);
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
