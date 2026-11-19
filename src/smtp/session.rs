use std::collections::BTreeMap;
use std::io;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::config::Config;
use crate::envelope::{Envelope, now_unix_ms};
use crate::policy::{self, Decision, Limits, Trace};
use crate::routing::{Route, Router};
use crate::smtp::client::{self, Delivery, Relay};
use crate::smtp::command::{self, Command};
use crate::smtp::wire::{self, WireError};
use crate::spool::{Spool, new_id};
use crate::srs::Srs;

pub const MAX_RECIPIENTS: usize = 100;

pub const MAX_ERRORS: u32 = 10;

pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(5 * 60);
pub const DATA_TIMEOUT: Duration = Duration::from_secs(10 * 60);

pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

pub const PTR_TIMEOUT: Duration = Duration::from_secs(2);

pub const RELAY_BUDGET: Duration = Duration::from_secs(300);

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
    pub relay_budget: Duration,
    pub limits: Limits,
    pub auth_enabled: bool,
    pub queue: crate::queue::Schedule,
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
            relay_budget: RELAY_BUDGET,
            limits: Limits {
                enforce: config.auth.enforce,
                ..Limits::default()
            },
            auth_enabled: config.auth.enabled,
            queue: config.queue.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Outcome {
    pub accepted: usize,
    pub quit: bool,
    pub tls: bool,
}

#[derive(Debug, Default)]
struct State {
    helo: Option<String>,
    esmtp: bool,
    from: Option<Option<String>>,
    recipients: Vec<String>,
    errors: u32,
    outcome: Outcome,
}

impl State {
    fn after_handshake(&mut self) {
        self.helo = None;
        self.esmtp = false;
        self.from = None;
        self.recipients.clear();
        self.outcome.tls = true;
    }
}

enum Step {
    Done,
    StartTls,
}

#[allow(clippy::too_many_arguments)]
pub async fn serve<S, L>(
    stream: S,
    peer: String,
    config: &SessionConfig,
    router: &Router,
    srs: Option<&Srs>,
    spool: &Spool,
    relay: &L,
    tls: Option<TlsAcceptor>,
    shutdown: &mut crate::shutdown::Shutdown,
) -> Result<Outcome, WireError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    L: Relay,
{
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
        srs,
        spool,
        relay,
        &peer,
        &tls,
        shutdown,
    )
    .await?
    {
        Step::Done => return Ok(state.outcome),
        Step::StartTls => {}
    }

    let acceptor = tls.clone().expect("STARTTLS is offered with a certificate");

    if !reader.buffer().is_empty() {
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

    let step = talk(
        &mut reader,
        &mut state,
        config,
        router,
        srs,
        spool,
        relay,
        &peer,
        &tls,
        shutdown,
    )
    .await?;

    let _ = reader.get_mut().shutdown().await;

    match step {
        Step::Done | Step::StartTls => Ok(state.outcome),
    }
}

#[allow(clippy::too_many_arguments)]
async fn talk<S, L>(
    reader: &mut BufReader<S>,
    state: &mut State,
    config: &SessionConfig,
    router: &Router,
    srs: Option<&Srs>,
    spool: &Spool,
    relay: &L,
    peer: &str,
    tls: &Option<TlsAcceptor>,
    shutdown: &mut crate::shutdown::Shutdown,
) -> Result<Step, WireError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    L: Relay,
{
    loop {
        let read = timeout(config.command_timeout, wire::read_line(reader));
        let line = tokio::select! {
            biased;
            () = shutdown.wait() => {
                say(
                    reader.get_mut(),
                    "421 4.3.2 this server is shutting down; please try again",
                )
                .await?;
                return Ok(Step::Done);
            }
            read = read => match read {
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
            },
        };

        let command = match command::parse(&line) {
            Ok(command) => command,
            Err(e) => {
                say(reader.get_mut(), &e.to_string()).await?;
                if too_many_errors(reader, state, config, peer).await? {
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

            Command::StartTls => {
                if state.outcome.tls {
                    say(reader.get_mut(), "503 5.5.1 TLS is already active").await?;
                } else if tls.is_none() {
                    say(reader.get_mut(), "502 5.5.1 STARTTLS is not offered here").await?;
                    if too_many_errors(reader, state, config, peer).await? {
                        return Ok(Step::Done);
                    }
                } else {
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
                    say(
                        reader.get_mut(),
                        &format!(
                            "552 5.3.4 message larger than the {} byte limit",
                            config.max_message_bytes
                        ),
                    )
                    .await?;
                } else if let Some(problem) = srs
                    .zip(sender.as_deref())
                    .and_then(|(srs, from)| srs.wrappable(from).err())
                {
                    say(
                        reader.get_mut(),
                        &format!(
                            "550 5.1.7 sender {} {problem}, and mail from it cannot be \
                             forwarded with a rewritten envelope sender",
                            sender.as_deref().unwrap_or("<>")
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
                    say(
                        reader.get_mut(),
                        "452 4.5.3 too many recipients for one message",
                    )
                    .await?;
                } else {
                    let reply = decide_recipient(router, srs, &address, &mut state.recipients);
                    let refused = reply.starts_with('5');
                    say(reader.get_mut(), &reply).await?;
                    if refused && too_many_errors(reader, state, config, peer).await? {
                        return Ok(Step::Done);
                    }
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
                    hand_on(config, router, srs, spool, relay, peer, state, body).await;
                say_reply(reader.get_mut(), &reply).await?;
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
                if too_many_errors(reader, state, config, peer).await? {
                    return Ok(Step::Done);
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn hand_on<L>(
    config: &SessionConfig,
    router: &Router,
    srs: Option<&Srs>,
    spool: &Spool,
    relay: &L,
    peer: &str,
    state: &State,
    body: Vec<u8>,
) -> (client::Reply, bool)
where
    L: Relay,
{
    let id = new_id();
    let helo = state.helo.clone().unwrap_or_default();

    let deadline = std::time::Instant::now() + config.relay_budget;

    let body = match config
        .auth_enabled
        .then(|| crate::auth::strip_forged_results(&body, &config.hostname))
        .flatten()
    {
        Some(stripped) => {
            let removed = body.len() - stripped.len();
            warn!(
                %peer,
                id = %id,
                removed,
                "this message arrived carrying an Authentication-Results header under \
                 this host's own name, which only this host may write; it has been \
                 removed before the message was checked"
            );
            stripped
        }
        None => body,
    };

    let address = peer.parse::<std::net::SocketAddr>();
    let ptr = match &address {
        Ok(address) => timeout(config.ptr_timeout, relay.ptr(address.ip()))
            .await
            .unwrap_or(None),
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
        helo: helo.clone(),
        peer: peer.to_string(),
        received_at_unix_ms: now_unix_ms(),
        size: body.len() as u64,
        received: received.clone(),
        authentication_results: String::new(),
        last_reply: None,
        attempts: 0,
        next_attempt_unix_ms: 0,
        via: BTreeMap::new(),
        sender_authenticated: false,
    };

    let head = policy::Head::scan(&body, &config.hostname);
    if let Some(reply) = policy::check_trace(&head, &config.limits) {
        info!(
            %peer,
            id = %envelope.id,
            received = head.received_count,
            by_us = head.by_us_count,
            "refusing to relay: {reply}"
        );
        return (reply, false);
    }

    let auth = {
        let budget =
            crate::auth::Budget::of(deadline.saturating_duration_since(std::time::Instant::now()));
        let backstop = budget.total() + std::time::Duration::from_secs(1);
        let probe = crate::auth::Probe {
            ip: address.as_ref().map_or(
                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                |address| address.ip(),
            ),
            helo: &helo,
            mail_from: envelope.from.as_deref(),
            body: &body,
        };
        match timeout(backstop, relay.verify(probe, budget)).await {
            Ok(auth) => auth,
            Err(_) => {
                warn!(
                    %peer,
                    id = %envelope.id,
                    seconds = backstop.as_secs(),
                    "SPF, DKIM and DMARC could not be checked inside their budget; \
                     every result is reported as temporary and the message is \
                     forwarded with that in its header, because an expired clock \
                     of ours is not evidence against the sender"
                );
                crate::auth::Auth::timed_out(envelope.from.as_deref(), &helo, &body)
            }
        }
    };

    let results = if auth.checked {
        auth.header(&config.hostname)
    } else {
        String::new()
    };
    let envelope = Envelope {
        authentication_results: results.clone(),
        sender_authenticated: auth.checked
            && crate::dsn::proves_sender(&auth, envelope.from.as_deref()),
        ..envelope
    };

    let plan = match policy::decide(&envelope, router, &head, &config.limits, &auth) {
        Decision::Refuse(reply) => {
            info!(
                %peer,
                id = %envelope.id,
                received = head.received_count,
                by_us = head.by_us_count,
                "refusing to relay: {reply}"
            );
            return (reply, false);
        }
        Decision::Deliver(plan) => plan,
    };

    let sender = match (srs, plan.sender.as_deref()) {
        (None, _) => plan.sender.clone(),

        (Some(_), None) => None,

        (Some(srs), Some(from)) => match srs.rewrite(Some(from), crate::srs::today()) {
            Some(rewritten) => {
                info!(
                    id = %envelope.id,
                    from = %from,
                    srs = %rewritten,
                    "rewrote the envelope sender so the destination's SPF check \
                     is made against a domain that names this host"
                );
                let local = rewritten.rsplit_once('@').map_or("", |(l, _)| l);
                if local.len() > crate::srs::MAX_LOCAL_PART_OCTETS {
                    warn!(
                        id = %envelope.id,
                        srs = %rewritten,
                        octets = local.len(),
                        limit = crate::srs::MAX_LOCAL_PART_OCTETS,
                        "the rewritten sender's local part is longer than a receiver \
                         is obliged to accept; a destination that refuses it will \
                         refuse this MAIL FROM"
                    );
                }
                Some(rewritten)
            }
            None => {
                if !srs.is_ours(from.rsplit_once('@').map_or("", |(_, d)| d)) {
                    warn!(
                        id = %envelope.id,
                        from = %from,
                        "handing on a sender mxhop could not wrap: it should have been \
                         refused at MAIL FROM, and the destination will now check SPF \
                         against a domain that does not name this host"
                    );
                }
                Some(from.to_string())
            }
        },
    };

    let body: std::sync::Arc<[u8]> = body.into();

    let mut prepended = received.clone();
    prepended.push_str(&results);

    let mut outcomes = Vec::with_capacity(plan.groups.len());
    for group in &plan.groups {
        let started = std::time::Instant::now();
        outcomes.push(
            relay
                .deliver(
                    Delivery::new(
                        sender.clone(),
                        group.recipients.clone(),
                        prepended.clone().into_bytes(),
                        std::sync::Arc::clone(&body),
                    )
                    .via(group.via.as_deref())
                    .due_by(deadline),
                )
                .await,
        );
        crate::metrics::DELIVERY_SECONDS.took(started.elapsed());
    }

    let verdict = policy::reply_for(&outcomes, &envelope.id);
    let delivered = (200..300).contains(&verdict.reply.code);
    if delivered {
        crate::metrics::MESSAGES_ACCEPTED.hit();
    } else {
        crate::metrics::MESSAGES_REFUSED.hit();
    }
    for outcome in &outcomes {
        for result in &outcome.results {
            match result.verdict {
                client::Verdict::Accepted => crate::metrics::RECIPIENTS_DELIVERED.hit(),
                client::Verdict::Deferred(_) => crate::metrics::RECIPIENTS_DEFERRED.hit(),
                client::Verdict::Refused(_) => crate::metrics::RECIPIENTS_REFUSED.hit(),
            }
        }
    }

    for (mailbox, reply) in &verdict.lost {
        error!(
            %peer,
            id = %envelope.id,
            recipient = %mailbox,
            "this copy was permanently refused: part of the message was delivered, so \
             the sending server was told 250 and will not send it again: {reply}"
        );
    }

    if !verdict.lost.is_empty() {
        match crate::dsn::send(
            spool,
            &config.hostname,
            &envelope,
            &verdict.lost,
            crate::dsn::Refused::Permanently,
            now_unix_ms(),
        )
        .await
        {
            Ok(id) => {
                crate::metrics::REPORTS_SENT.hit();
                info!(
                    %peer,
                    id = %envelope.id,
                    report = %id,
                    "a delivery report for the refused copies is in the queue"
                )
            }
            Err(why) => {
                crate::metrics::REPORTS_SUPPRESSED.hit();
                warn!(
                    %peer,
                    id = %envelope.id,
                    from = envelope.from.as_deref().unwrap_or("<>"),
                    "no delivery report is being sent for the refused copies: {why}"
                )
            }
        }
    }

    if verdict.hold.is_empty() {
        info!(
            %peer,
            id = %envelope.id,
            message_id = head.message_id.as_deref().unwrap_or("none"),
            domains = plan.groups.len(),
            lost = verdict.lost.len(),
            "relayed: {}",
            verdict.reply
        );
        return (verdict.reply, delivered);
    }

    let attempts = 1;
    let routed: BTreeMap<String, String> = plan
        .groups
        .iter()
        .filter_map(|group| group.via.as_ref().map(|host| (group, host)))
        .flat_map(|(group, host)| {
            group
                .recipients
                .iter()
                .map(move |mailbox| (mailbox.to_string(), host.clone()))
        })
        .collect();
    let held = Envelope {
        via: verdict
            .hold
            .iter()
            .filter_map(|(mailbox, _)| {
                let address = mailbox.to_string();
                routed.get(&address).map(|host| (address, host.clone()))
            })
            .collect(),
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
        attempts,
        next_attempt_unix_ms: now_unix_ms() + config.queue.backoff(attempts).as_millis() as u64,
        ..envelope.clone()
    };
    match spool.store(&held, &body).await {
        Ok(()) => warn!(
            %peer,
            id = %held.id,
            message_id = head.message_id.as_deref().unwrap_or("none"),
            held = held.to.join(", "),
            minutes = config.queue.backoff(attempts).as_secs() / 60,
            "part of the message was not delivered and is held in the queue for the \
             runner to retry: {}",
            held.last_reply.as_deref().unwrap_or("no reason recorded")
        ),
        Err(e) => error!(
            %peer,
            id = %held.id,
            held = held.to.join(", "),
            "part of the message was not delivered and could not be held either: {e}"
        ),
    }

    (verdict.reply, delivered)
}

async fn too_many_errors<S>(
    reader: &mut BufReader<S>,
    state: &mut State,
    config: &SessionConfig,
    peer: &str,
) -> Result<bool, WireError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    state.errors += 1;
    if state.errors >= config.max_errors {
        warn!(
            peer = %peer,
            errors = state.errors,
            "cutting the session off after too many refused commands"
        );
        say(reader.get_mut(), "421 4.7.0 too many errors, goodbye").await?;
        return Ok(true);
    }
    Ok(false)
}

fn decide_recipient(
    router: &Router,
    srs: Option<&Srs>,
    address: &str,
    recipients: &mut Vec<String>,
) -> String {
    let Some((local, domain)) = address.rsplit_once('@') else {
        return "501 5.1.3 recipient is not <local@domain>".to_string();
    };

    if let Some(srs) = srs.filter(|srs| srs.is_ours(domain)) {
        return match srs.verify(local, crate::srs::today()) {
            Ok(mailbox) => {
                info!(
                    srs = %address,
                    decoded = %mailbox,
                    "a bounce came back to a rewritten sender"
                );
                recipients.push(mailbox.to_string());
                "250 2.1.5 recipient accepted".to_string()
            }
            Err(refusal) => {
                match refusal {
                    crate::srs::Refusal::Expired => {
                        info!(srs = %address, "refusing an address at the srs domain: {refusal}")
                    }
                    _ => {
                        debug!(srs = %address, "refusing an address at the srs domain: {refusal}")
                    }
                }
                refusal.reply().to_string()
            }
        };
    }

    match router.resolve(domain, local) {
        Some((_, Route::Reject(reply))) => reply.clone(),
        Some((_, Route::Forward(_) | Route::Via { .. })) => {
            recipients.push(address.to_string());
            "250 2.1.5 recipient accepted".to_string()
        }
        None if router.handles_domain(domain) => "550 5.1.1 no such address here".to_string(),
        None => "550 5.7.1 relaying is not allowed".to_string(),
    }
}

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

async fn say_reply<W>(out: &mut W, reply: &client::Reply) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut out_buf = String::new();
    for line in reply.wire() {
        out_buf.push_str(&line);
        out_buf.push_str("\r\n");
    }
    out.write_all(out_buf.as_bytes()).await?;
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
        r.insert(
            "example.com",
            "direct",
            Route::Via {
                to: Mailbox::parse("direct@example.com").unwrap(),
                host: "aspmx.l.google.test".into(),
            },
        );
        r
    }

    #[derive(Clone, Default)]
    struct Fake {
        seen: std::sync::Arc<std::sync::Mutex<Vec<Delivery>>>,
        answers: std::collections::BTreeMap<String, client::Verdict>,
        ptr: Option<String>,
        auth: crate::auth::Auth,
        probed: std::sync::Arc<std::sync::Mutex<Vec<Probed>>>,
    }

    type Probed = (String, Option<String>, usize);

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

        async fn verify(
            &self,
            probe: crate::auth::Probe<'_>,
            _budget: crate::auth::Budget,
        ) -> crate::auth::Auth {
            self.probed.lock().unwrap().push((
                probe.helo.to_string(),
                probe.mail_from.map(ToString::to_string),
                probe.body.len(),
            ));
            self.auth.clone()
        }
    }

    fn theirs(code: u16, enhanced: &str, text: &str) -> client::Reply {
        client::Reply {
            code,
            enhanced: Some(enhanced.to_string()),
            text: text.to_string(),
            lines: Vec::new(),
        }
    }

    struct Talk {
        out: String,
        spool: Spool,
        relay: Fake,
        outcome: Outcome,
    }

    impl Talk {
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
        talk_all(relay, limit, None, script).await
    }

    fn test_srs() -> Srs {
        Srs::new(
            "srs.mx.test",
            vec![format!("mxhop-session-test-{}", new_id()).into_bytes()],
            crate::srs::DEFAULT_MAX_AGE_DAYS,
        )
    }

    async fn talk_srs(srs: &Srs, script: &str) -> Talk {
        talk_all(Fake::accepting(), 26_214_400, Some(srs), script).await
    }

    async fn talk_all(relay: Fake, limit: u64, srs: Option<&Srs>, script: &str) -> Talk {
        talk_everything(relay, limit, srs, true, script).await
    }

    async fn talk_unchecked(relay: Fake, script: &str) -> Talk {
        talk_everything(relay, 26_214_400, None, false, script).await
    }

    async fn talk_everything(
        relay: Fake,
        limit: u64,
        srs: Option<&Srs>,
        auth_enabled: bool,
        script: &str,
    ) -> Talk {
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
            relay_budget: RELAY_BUDGET,
            queue: crate::queue::Schedule::default(),
            auth_enabled,
            limits: Limits::default(),
        };

        let (mut client, server) = duplex(256 * 1024);
        let spool_for_task = spool.clone();
        let relay_for_task = relay.clone();
        let srs_for_task = srs.cloned();
        let task = tokio::spawn(async move {
            serve(
                server,
                "198.51.100.7:40000".to_string(),
                &config,
                &test_router(),
                srs_for_task.as_ref(),
                &spool_for_task,
                &relay_for_task,
                None,
                &mut crate::shutdown::Shutdown::never(),
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

    #[tokio::test]
    async fn the_envelope_sender_handed_to_the_destination_is_rewritten() {
        let srs = test_srs();
        let talk = talk_srs(&srs, DELIVER).await;

        let seen = talk.relay.seen.lock().unwrap();
        let from = seen[0].from.clone().expect("a sender was announced");
        assert!(
            from.ends_with("@srs.mx.test"),
            "the destination has to see our own domain, not elsewhere.test: {from}"
        );
        assert_eq!(
            srs.verify(from.rsplit_once('@').unwrap().0, crate::srs::today())
                .expect("our own address")
                .to_string(),
            "sender@elsewhere.test",
            "and the original sender has to be recoverable from it, \
             or the bounce cannot be sent on"
        );
    }

    #[tokio::test]
    async fn a_forged_srs_recipient_is_550_not_relayed() {
        let srs = test_srs();
        let honest = srs
            .rewrite(Some("victim@elsewhere.test"), crate::srs::today())
            .unwrap();
        assert!(
            honest[5..].find('=').expect("a MAC terminator") + 5 > 6,
            "index 6 has to be inside the MAC of {honest}"
        );
        let mut forged: Vec<char> = honest.chars().collect();
        forged[6] = if forged[6] == 'A' { 'B' } else { 'A' };
        let forged: String = forged.into_iter().collect();
        assert_ne!(forged, honest, "the test has to change something");

        let talk = talk_srs(
            &srs,
            &format!(
                "EHLO mail.elsewhere.test\r\n\
                 MAIL FROM:<>\r\n\
                 RCPT TO:<{forged}>\r\n\
                 QUIT\r\n"
            ),
        )
        .await;

        assert_eq!(
            talk.codes(),
            vec!["220", "250", "250", "550", "221"],
            "a forged SRS address must be refused: {}",
            talk.out
        );
        assert!(
            talk.out.contains("not an address we issued"),
            "and the refusal must not say which half was wrong: {}",
            talk.out
        );
        assert!(
            talk.relay.seen.lock().unwrap().is_empty(),
            "nothing may leave this host for a forged address"
        );
    }

    #[tokio::test]
    async fn a_valid_srs_recipient_is_routed_to_the_decoded_sender() {
        let srs = test_srs();
        let wrapped = srs
            .rewrite(Some("Sender@elsewhere.test"), crate::srs::today())
            .unwrap();

        let talk = talk_srs(
            &srs,
            &format!(
                "EHLO mail.gmail.test\r\n\
                 MAIL FROM:<>\r\n\
                 RCPT TO:<{wrapped}>\r\n\
                 DATA\r\n\
                 Subject: Undelivered Mail Returned to Sender\r\n\
                 \r\n\
                 sorry\r\n\
                 .\r\n\
                 QUIT\r\n"
            ),
        )
        .await;

        assert_eq!(talk.last_code(), "221", "{}", talk.out);
        let seen = talk.relay.seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "{}", talk.out);
        assert_eq!(
            seen[0]
                .to
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            vec!["Sender@elsewhere.test"],
            "the bounce goes to the person who wrote the message, \
             with the local part's case as they sent it"
        );
        assert_eq!(
            seen[0].from, None,
            "and it keeps its own null sender: a bounce that acquired one \
             could be bounced again"
        );
    }

    #[tokio::test]
    async fn a_session_that_collects_max_errors_refused_recipients_is_disconnected() {
        let srs = test_srs();
        let talk = talk_srs(
            &srs,
            "EHLO mail.elsewhere.test\r\n\
             MAIL FROM:<>\r\n\
             RCPT TO:<SRS0=aaaaaaaa=AA=victim.test=one@srs.mx.test>\r\n\
             RCPT TO:<SRS0=bbbbbbbb=AA=victim.test=two@srs.mx.test>\r\n\
             RCPT TO:<SRS0=cccccccc=AA=victim.test=three@srs.mx.test>\r\n\
             RCPT TO:<SRS0=dddddddd=AA=victim.test=four@srs.mx.test>\r\n\
             RCPT TO:<SRS0=eeeeeeee=AA=victim.test=five@srs.mx.test>\r\n\
             QUIT\r\n",
        )
        .await;

        assert_eq!(
            talk.codes(),
            vec!["220", "250", "250", "550", "550", "550", "550", "421"],
            "the fourth refused recipient has to end the session, \
             not earn a fifth guess: {}",
            talk.out
        );
        assert!(
            talk.relay.seen.lock().unwrap().is_empty(),
            "and nothing may leave this host"
        );
    }

    #[tokio::test]
    async fn refusals_below_the_limit_do_not_end_the_session() {
        let talk = talk(
            "EHLO mail.elsewhere.test\r\n\
             MAIL FROM:<sender@elsewhere.test>\r\n\
             RCPT TO:<nobody@example.com>\r\n\
             RCPT TO:<also-nobody@example.com>\r\n\
             RCPT TO:<hi@example.com>\r\n\
             QUIT\r\n",
        )
        .await;

        assert_eq!(
            talk.codes(),
            vec!["220", "250", "250", "550", "550", "250", "221"],
            "two refusals under a limit of four must leave the session alone, \
             and the good recipient after them must still be accepted: {}",
            talk.out
        );
    }

    #[tokio::test]
    async fn a_sender_that_cannot_be_wrapped_is_refused_at_mail_from() {
        let srs = test_srs();
        for sender in ["bob@localhost", "user@[192.0.2.1]", "\"a b\"@x.test"] {
            let talk = talk_srs(
                &srs,
                &format!(
                    "EHLO mail.elsewhere.test\r\n\
                     MAIL FROM:<{sender}>\r\n\
                     RCPT TO:<hi@example.com>\r\n\
                     QUIT\r\n"
                ),
            )
            .await;

            assert_eq!(
                talk.codes(),
                vec!["220", "250", "550", "503", "221"],
                "{sender} cannot be rewritten, so it has to be refused here \
                 rather than forwarded unprotected: {}",
                talk.out
            );
        }
    }

    #[tokio::test]
    async fn without_srs_an_unwrappable_sender_is_still_accepted() {
        let talk = talk(
            "EHLO mail.elsewhere.test\r\n\
             MAIL FROM:<bob@localhost>\r\n\
             RCPT TO:<hi@example.com>\r\n\
             QUIT\r\n",
        )
        .await;

        assert_eq!(
            talk.codes(),
            vec!["220", "250", "250", "250", "221"],
            "{}",
            talk.out
        );
    }

    #[tokio::test]
    async fn an_ordinary_address_at_the_srs_domain_is_refused() {
        let srs = test_srs();
        let talk = talk_srs(
            &srs,
            "EHLO mail.elsewhere.test\r\n\
             MAIL FROM:<>\r\n\
             RCPT TO:<postmaster@srs.mx.test>\r\n\
             QUIT\r\n",
        )
        .await;

        assert_eq!(talk.codes(), vec!["220", "250", "250", "550", "221"]);
        assert!(talk.relay.seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn without_srs_the_envelope_sender_is_left_alone() {
        let talk = talk(DELIVER).await;

        assert_eq!(
            talk.relay.seen.lock().unwrap()[0].from.as_deref(),
            Some("sender@elsewhere.test")
        );
    }

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

    #[tokio::test]
    async fn a_crafted_helo_cannot_forge_a_header_through_the_session() {
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

    #[tokio::test]
    async fn an_address_routed_to_a_named_server_is_delivered_there() {
        let script = "EHLO x.test\r\nMAIL FROM:<a@b.test>\r\nRCPT TO:<direct@example.com>\r\n\
                      DATA\r\nbody\r\n.\r\nQUIT\r\n";
        let t = talk_with(Fake::accepting(), 26_214_400, script).await;

        assert!(t.out.contains("250 2.0.0 delivered as "), "{}", t.out);
        let sent = t.relay.deliveries();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].via.as_deref(), Some("aspmx.l.google.test"));
        assert_eq!(sent[0].to[0].to_string(), "direct@example.com");
    }

    #[tokio::test]
    async fn a_held_copy_remembers_the_server_it_was_routed_to() {
        let script = "EHLO x.test\r\nMAIL FROM:<a@b.test>\r\n\
                      RCPT TO:<hi@example.com>\r\nRCPT TO:<direct@example.com>\r\n\
                      DATA\r\nbody\r\n.\r\nQUIT\r\n";
        let t = talk_with(
            Fake::answering(
                "example.com",
                client::Verdict::Deferred(theirs(451, "4.3.2", "Try again later")),
            ),
            26_214_400,
            script,
        )
        .await;

        assert!(t.out.contains("250 2.0.0 delivered as "), "{}", t.out);
        let queued = t.spool.queued().await.unwrap();
        assert_eq!(queued[0].to, vec!["direct@example.com".to_string()]);
        assert_eq!(
            queued[0].via.get("direct@example.com").map(String::as_str),
            Some("aspmx.l.google.test"),
            "a retry that forgot this would look up the MX of example.com, which is us"
        );
    }

    #[tokio::test]
    async fn an_ordinary_held_copy_records_no_server() {
        let script = "EHLO x.test\r\nMAIL FROM:<a@b.test>\r\nRCPT TO:<team@example.com>\r\n\
                      DATA\r\nbody\r\n.\r\nQUIT\r\n";
        let t = talk_with(
            Fake::answering(
                "fastmail.test",
                client::Verdict::Deferred(theirs(451, "4.3.2", "Try again later")),
            ),
            26_214_400,
            script,
        )
        .await;

        let queued = t.spool.queued().await.unwrap();
        assert_eq!(queued[0].to, vec!["b@fastmail.test".to_string()]);
        assert!(queued[0].via.is_empty(), "{:?}", queued[0].via);
    }

    #[tokio::test]
    async fn a_destinations_multi_line_refusal_is_refolded_for_the_sender() {
        let refusal = client::Reply {
            code: 550,
            enhanced: Some("5.1.1".into()),
            text: "does not exist. Please try double-checking the address".into(),
            lines: vec![
                "does not exist.".into(),
                "Please try double-checking the address".into(),
            ],
        };
        let script = "EHLO x.test\r\nMAIL FROM:<a@b.test>\r\nRCPT TO:<hi@example.com>\r\n\
                      DATA\r\nbody\r\n.\r\nQUIT\r\n";
        let t = talk_with(
            Fake::answering("gmail.test", client::Verdict::Refused(refusal)),
            26_214_400,
            script,
        )
        .await;

        assert!(
            t.out.contains(
                "550-5.1.1 mx.gmail.test said: does not exist.\r\n\
                 550 5.1.1 Please try double-checking the address\r\n"
            ),
            "the attribution goes on the first line, the enhanced code on every \
             line, and only the last line ends the reply: {}",
            t.out.escape_debug()
        );
    }

    #[tokio::test]
    async fn every_destination_group_shares_one_deadline() {
        let script = "EHLO x.test\r\nMAIL FROM:<a@b.test>\r\nRCPT TO:<team@example.com>\r\n\
                      DATA\r\nbody\r\n.\r\nQUIT\r\n";
        let t = talk_with(Fake::accepting(), 26_214_400, script).await;

        let deadlines: Vec<_> = t
            .relay
            .deliveries()
            .iter()
            .map(|d| d.deadline.expect("a deadline set by the session"))
            .collect();

        assert_eq!(deadlines.len(), 2, "two destination domains");
        assert_eq!(
            deadlines[0], deadlines[1],
            "one deadline for the whole message, not one per domain"
        );
    }

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
            relay_budget: RELAY_BUDGET,
            queue: crate::queue::Schedule::default(),
            auth_enabled: true,
            limits: Limits::default(),
        };

        let (mut client, server) = duplex(4096);
        let task = tokio::spawn(async move {
            serve(
                server,
                "198.51.100.7:40000".to_string(),
                &config,
                &test_router(),
                None,
                &spool,
                &Fake::accepting(),
                None,
                &mut crate::shutdown::Shutdown::never(),
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

    use crate::config::TlsPaths;
    use crate::tls::{Holder, testing};
    use rustls_pki_types::pem::PemObject;
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, DuplexStream};
    use tokio_rustls::TlsConnector;
    use tokio_rustls::rustls::{self, ClientConfig};

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

    struct Peer<S> {
        io: BufReader<S>,
    }

    impl<S: AsyncRead + AsyncWrite + Unpin> Peer<S> {
        fn new(io: S) -> Self {
            Self {
                io: BufReader::new(io),
            }
        }

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
            relay_budget: RELAY_BUDGET,
            queue: crate::queue::Schedule::default(),
            auth_enabled: true,
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
                None,
                &spool_for_task,
                &Fake::accepting(),
                Some(acceptor),
                &mut crate::shutdown::Shutdown::never(),
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

    #[tokio::test]
    async fn commands_pipelined_behind_starttls_are_not_replayed() {
        let (mut client, served, _) = serve_with_tls("mx.test").await;
        client.reply().await;
        client
            .send("EHLO x.test\r\nSTARTTLS\r\nMAIL FROM:<attacker@evil.test>\r\n")
            .await;
        client.reply().await;
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
        client.reply().await;
        client.reply().await;
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

        let outcome = timeout(Duration::from_secs(5), served.task)
            .await
            .expect("a stalled handshake must not hold the task open")
            .unwrap()
            .unwrap();

        assert!(!outcome.tls);
    }

    use crate::auth::{Auth, Dmarc, DmarcVerdict, Policy as DmarcPolicy, Spf};

    fn fake_with(auth: Auth) -> Fake {
        Fake {
            auth,
            ..Fake::accepting()
        }
    }

    fn spf_passing() -> Auth {
        Auth {
            spf_mail: Spf::Pass,
            spf_helo: Spf::Pass,
            mail_from: Some("sender@elsewhere.test".into()),
            helo: Some("mail.elsewhere.test".into()),
            checked: true,
            ..Auth::default()
        }
    }

    fn spf_failing() -> Auth {
        Auth {
            spf_mail: Spf::Fail,
            checked: true,
            ..spf_passing()
        }
    }

    const LOST: &str = "EHLO mail.elsewhere.test\r\n\
                        MAIL FROM:<sender@elsewhere.test>\r\n\
                        RCPT TO:<team@example.com>\r\n\
                        DATA\r\nbody\r\n.\r\nQUIT\r\n";

    fn refusing(auth: Auth) -> Fake {
        Fake {
            auth,
            ..Fake::answering(
                "fastmail.test",
                client::Verdict::Refused(theirs(550, "5.1.1", "no such user")),
            )
        }
    }

    #[tokio::test]
    async fn a_copy_lost_after_a_250_is_reported_to_a_sender_that_proved_itself() {
        let t = talk_with(refusing(spf_passing()), 26_214_400, LOST).await;

        assert!(t.out.contains("250 2.0.0 delivered as "), "{}", t.out);
        let queued = t.spool.queued().await.unwrap();
        assert_eq!(queued.len(), 1, "the report, and nothing held");
        assert_eq!(
            queued[0].from, None,
            "a report is sent from the null sender"
        );
        assert_eq!(queued[0].to, vec!["sender@elsewhere.test".to_string()]);

        let body = String::from_utf8(t.spool.body(&queued[0].id).await.unwrap()).unwrap();
        assert!(
            body.contains("Final-Recipient: rfc822; b@fastmail.test"),
            "{body}"
        );
        assert!(
            body.contains("Diagnostic-Code: smtp; 550 5.1.1 no such user"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn a_copy_lost_for_a_sender_that_proved_nothing_is_only_logged() {
        let t = talk_with(refusing(spf_failing()), 26_214_400, LOST).await;

        assert!(t.out.contains("250 2.0.0 delivered as "), "{}", t.out);
        assert!(
            t.spool.queued().await.unwrap().is_empty(),
            "a report here would be mail sent to whoever the envelope named, which \
             is the backscatter this rule exists to stop"
        );
    }

    #[tokio::test]
    async fn a_bounce_that_cannot_be_delivered_is_not_bounced_again() {
        let script = "EHLO mail.elsewhere.test\r\nMAIL FROM:<>\r\n\
                      RCPT TO:<team@example.com>\r\nDATA\r\nbody\r\n.\r\nQUIT\r\n";
        let t = talk_with(refusing(spf_passing()), 26_214_400, script).await;

        assert!(
            t.spool.queued().await.unwrap().is_empty(),
            "the null sender has nowhere to send a report, and inventing one is how \
             a mail loop starts"
        );
    }

    fn verdict(from: &str, result: DmarcVerdict, policy: Option<DmarcPolicy>) -> Auth {
        Auth {
            spf_mail: Spf::Fail,
            spf_helo: Spf::Pass,
            mail_from: Some("sender@elsewhere.test".into()),
            helo: Some("mail.elsewhere.test".into()),
            dkim: Vec::new(),
            dmarc: Dmarc {
                from_domain: from.to_string(),
                result,
                policy,
            },
            checked: true,
            dkim_timed_out: false,
        }
    }

    #[tokio::test]
    async fn the_results_header_goes_on_the_wire_directly_under_our_received() {
        let auth = verdict(
            "elsewhere.test",
            DmarcVerdict::Pass,
            Some(DmarcPolicy::None),
        );
        let talk = talk_with(fake_with(auth), 26_214_400, DELIVER).await;

        let head = String::from_utf8(talk.relay.only().head).unwrap();
        let received = head
            .find("Received: from mail.elsewhere.test")
            .unwrap_or_else(|| panic!("a Received header: {head:?}"));
        let results = head
            .find("Authentication-Results: mx.test;")
            .unwrap_or_else(|| panic!("our results header: {head:?}"));

        assert!(
            received < results,
            "the trace comes first and ours is written under it: {head:?}"
        );
        assert!(head.contains("dmarc=pass"), "{head:?}");
        assert!(
            head.ends_with("\r\n"),
            "the prepended block has to end on a header boundary, or the first \
             line of the stored message is folded onto ours: {head:?}"
        );
    }

    #[tokio::test]
    async fn the_check_is_made_against_the_sender_that_arrived() {
        let srs = test_srs();
        let auth = verdict("elsewhere.test", DmarcVerdict::None, None);
        let relay = fake_with(auth);
        let talk = talk_all(relay, 26_214_400, Some(&srs), DELIVER).await;

        let probed = talk.relay.probed.lock().unwrap().clone();
        assert_eq!(
            probed
                .iter()
                .map(|(helo, from, _)| (helo.clone(), from.clone()))
                .collect::<Vec<_>>(),
            vec![(
                "mail.elsewhere.test".to_string(),
                Some("sender@elsewhere.test".to_string())
            )],
            "checked once, against the original envelope sender"
        );
        assert!(
            talk.relay
                .only()
                .from
                .as_deref()
                .is_some_and(|from| from.contains("srs.mx.test")),
            "and the rewrite still happened on the way out"
        );
    }

    #[tokio::test]
    async fn a_reject_policy_failure_is_refused_and_nothing_leaves() {
        let auth = verdict("paypal.test", DmarcVerdict::Fail, Some(DmarcPolicy::Reject));
        let talk = talk_with(fake_with(auth), 26_214_400, DELIVER).await;

        assert!(talk.codes().contains(&"550"), "{}", talk.out);
        assert!(
            talk.out.contains("paypal.test"),
            "the sender is told which domain and why: {}",
            talk.out
        );
        assert!(
            talk.relay.deliveries().is_empty(),
            "nothing may be handed on: {:?}",
            talk.relay.deliveries()
        );
        assert_eq!(talk.outcome.accepted, 0);
    }

    #[tokio::test]
    async fn a_dmarc_temperror_under_p_reject_is_deferred_on_the_wire() {
        let auth = verdict(
            "paypal.test",
            DmarcVerdict::TempError,
            Some(DmarcPolicy::Reject),
        );
        let talk = talk_with(fake_with(auth), 26_214_400, DELIVER).await;

        assert!(talk.codes().contains(&"451"), "{}", talk.out);
        assert!(talk.relay.deliveries().is_empty());
        assert!(
            talk.spool.queued().await.unwrap().is_empty(),
            "nothing is kept: the sending server still has it"
        );
    }

    #[tokio::test]
    async fn a_quarantine_failure_is_delivered_with_the_policy_in_the_header() {
        let auth = verdict(
            "shop.test",
            DmarcVerdict::Fail,
            Some(DmarcPolicy::Quarantine),
        );
        let talk = talk_with(fake_with(auth), 26_214_400, DELIVER).await;

        assert!(talk.codes().contains(&"250"), "{}", talk.out);
        let head = String::from_utf8(talk.relay.only().head).unwrap();
        assert!(head.contains("policy.dmarc=quarantine"), "{head:?}");
    }

    #[tokio::test]
    async fn a_check_that_was_never_run_writes_no_header() {
        let talk = talk_with(fake_with(Auth::not_checked()), 26_214_400, DELIVER).await;

        let head = String::from_utf8(talk.relay.only().head).unwrap();
        assert!(
            !head.to_ascii_lowercase().contains("authentication-results"),
            "{head:?}"
        );
    }

    #[tokio::test]
    async fn a_forged_results_header_does_not_reach_the_destination() {
        let auth = verdict("paypal.test", DmarcVerdict::Fail, Some(DmarcPolicy::None));
        let script = "EHLO mail.elsewhere.test\r\n\
                      MAIL FROM:<sender@elsewhere.test>\r\n\
                      RCPT TO:<hi@example.com>\r\n\
                      DATA\r\n\
                      Authentication-Results: mx.test; dmarc=pass header.from=paypal.test\r\n\
                      Subject: your account\r\n\
                      \r\n\
                      body\r\n\
                      .\r\n\
                      QUIT\r\n";

        let talk = talk_with(fake_with(auth), 26_214_400, script).await;

        let delivery = talk.relay.only();
        let wire =
            String::from_utf8([delivery.head.clone(), delivery.body.to_vec()].concat()).unwrap();

        assert_eq!(
            wire.matches("Authentication-Results:").count(),
            1,
            "exactly one, and it is ours: {wire:?}"
        );
        assert!(wire.contains("dmarc=fail"), "{wire:?}");
        assert!(
            !wire.contains("dmarc=pass"),
            "the sender's own claim must not survive: {wire:?}"
        );
    }

    #[tokio::test]
    async fn a_disabled_check_leaves_an_upstream_results_header_where_it_is() {
        let script = "EHLO mail.elsewhere.test\r\n\
                      MAIL FROM:<sender@elsewhere.test>\r\n\
                      RCPT TO:<hi@example.com>\r\n\
                      DATA\r\n\
                      Authentication-Results: mx.test; dmarc=pass header.from=elsewhere.test\r\n\
                      Subject: hello\r\n\
                      \r\n\
                      body\r\n\
                      .\r\n\
                      QUIT\r\n";

        let talk = talk_unchecked(fake_with(Auth::not_checked()), script).await;

        let delivery = talk.relay.only();
        let wire =
            String::from_utf8([delivery.head.clone(), delivery.body.to_vec()].concat()).unwrap();

        assert!(
            wire.contains("Authentication-Results: mx.test; dmarc=pass"),
            "with the check off mxhop has no opinion about this header, so it \
             is not ours to delete: {wire:?}"
        );
        assert_eq!(
            wire.matches("Authentication-Results:").count(),
            1,
            "and none of our own is written in its place: {wire:?}"
        );
    }

    #[tokio::test]
    async fn a_looping_message_is_refused_before_any_authentication_lookup() {
        let script = "EHLO mail.elsewhere.test\r\n\
                      MAIL FROM:<sender@elsewhere.test>\r\n\
                      RCPT TO:<hi@example.com>\r\n\
                      DATA\r\n\
                      Received: from a.test by mx.test with ESMTP id 1\r\n\
                      Received: from b.test by mx.test with ESMTP id 2\r\n\
                      Received: from c.test by mx.test with ESMTP id 3\r\n\
                      Subject: round and round\r\n\
                      \r\n\
                      body\r\n\
                      .\r\n\
                      QUIT\r\n";

        let talk = talk_with(Fake::accepting(), 26_214_400, script).await;

        assert!(talk.codes().contains(&"554"), "{}", talk.out);
        assert!(
            talk.relay.probed.lock().unwrap().is_empty(),
            "the loop was certain without DNS, so no lookup may have been \
             started: {:?}",
            talk.relay.probed.lock().unwrap()
        );
        assert!(talk.relay.deliveries().is_empty());
    }
}
