//! One inbound SMTP session, from `220` to `221`.
//!
//! The session is written over any stream rather than a socket, so the tests
//! drive the real state machine through a pipe. What it does *not* do is
//! decide policy: whether a recipient is ours comes from the [`Router`], and
//! nothing here looks inside the message.

use std::io;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::time::timeout;

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

/// What the session needs to know about itself.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub hostname: String,
    pub max_message_bytes: u64,
    pub max_recipients: usize,
    pub max_errors: u32,
    pub command_timeout: Duration,
    pub data_timeout: Duration,
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
}

/// Serves one session to its end. A client that disappears is not an error:
/// it happens all day, and nothing was promised to it.
pub async fn serve<S>(
    stream: S,
    peer: String,
    config: &SessionConfig,
    router: &Router,
    spool: &Spool,
) -> Result<Outcome, WireError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (read_half, mut out) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);
    let mut outcome = Outcome::default();

    say(&mut out, &format!("220 {} mxhop ready", config.hostname)).await?;

    // The three facts a transaction is made of. `from` is `Some(None)` for
    // the null sender, which is a sender — just not one you can reply to.
    let mut helo: Option<String> = None;
    let mut from: Option<Option<String>> = None;
    let mut recipients: Vec<String> = Vec::new();
    let mut errors = 0u32;

    loop {
        let line = match timeout(config.command_timeout, wire::read_line(&mut reader)).await {
            Err(_) => {
                say(&mut out, "421 4.4.2 timeout waiting for a command").await?;
                return Ok(outcome);
            }
            Ok(Ok(line)) => line,
            Ok(Err(WireError::Closed)) => return Ok(outcome),
            Ok(Err(WireError::LineTooLong)) => {
                say(&mut out, "500 5.5.6 command line too long").await?;
                return Ok(outcome);
            }
            Ok(Err(e)) => return Err(e),
        };

        let command = match command::parse(&line) {
            Ok(command) => command,
            Err(e) => {
                say(&mut out, &e.to_string()).await?;
                errors += 1;
                if errors >= config.max_errors {
                    say(&mut out, "421 4.7.0 too many errors, goodbye").await?;
                    return Ok(outcome);
                }
                continue;
            }
        };

        match command {
            Command::Ehlo(name) => {
                helo = Some(name.clone());
                from = None;
                recipients.clear();
                let greeting = format!(
                    "250-{} greets {}\r\n\
                     250-SIZE {}\r\n\
                     250-8BITMIME\r\n\
                     250-PIPELINING\r\n\
                     250 ENHANCEDSTATUSCODES",
                    config.hostname, name, config.max_message_bytes
                );
                out.write_all(greeting.as_bytes()).await?;
                out.write_all(b"\r\n").await?;
                out.flush().await?;
            }

            Command::Helo(name) => {
                helo = Some(name);
                from = None;
                recipients.clear();
                say(&mut out, &format!("250 {}", config.hostname)).await?;
            }

            Command::Mail {
                from: sender, size, ..
            } => {
                if helo.is_none() {
                    say(&mut out, "503 5.5.1 say EHLO first").await?;
                } else if from.is_some() {
                    say(&mut out, "503 5.5.1 a message is already in progress").await?;
                } else if size.is_some_and(|size| size > config.max_message_bytes) {
                    // The client said how big it is. Reading it anyway would
                    // waste both sides' time.
                    say(
                        &mut out,
                        &format!(
                            "552 5.3.4 message larger than the {} byte limit",
                            config.max_message_bytes
                        ),
                    )
                    .await?;
                } else {
                    from = Some(sender);
                    recipients.clear();
                    say(&mut out, "250 2.1.0 sender accepted").await?;
                }
            }

            Command::Rcpt(address) => {
                if from.is_none() {
                    say(&mut out, "503 5.5.1 say MAIL FROM first").await?;
                } else if recipients.len() >= config.max_recipients {
                    // Temporary on purpose: the client should send the rest
                    // in another message rather than give up on them.
                    say(&mut out, "452 4.5.3 too many recipients for one message").await?;
                } else {
                    let reply = decide_recipient(router, &address, &mut recipients);
                    say(&mut out, &reply).await?;
                }
            }

            Command::Data => {
                if recipients.is_empty() {
                    say(&mut out, "503 5.5.1 no accepted recipients").await?;
                    continue;
                }
                say(&mut out, "354 end your message with a single dot").await?;

                let body = match timeout(
                    config.data_timeout,
                    wire::read_body(&mut reader, config.max_message_bytes),
                )
                .await
                {
                    Err(_) => {
                        say(&mut out, "421 4.4.2 timeout inside DATA").await?;
                        return Ok(outcome);
                    }
                    Ok(Ok(body)) => body,
                    Ok(Err(WireError::TooLarge { limit })) => {
                        // The stream now holds the rest of a message we have
                        // already refused; draining it is work on behalf of
                        // whoever sent it.
                        say(
                            &mut out,
                            &format!("552 5.3.4 message larger than {limit} bytes"),
                        )
                        .await?;
                        return Ok(outcome);
                    }
                    Ok(Err(WireError::UnterminatedBody | WireError::Closed)) => return Ok(outcome),
                    Ok(Err(e)) => return Err(e),
                };

                let envelope = Envelope {
                    id: new_id(),
                    from: from.clone().flatten(),
                    to: recipients.clone(),
                    helo: helo.clone().unwrap_or_default(),
                    peer: peer.clone(),
                    received_at_unix_ms: now_unix_ms(),
                    size: body.len() as u64,
                };

                match spool.store(&envelope, &body).await {
                    Ok(()) => {
                        say(&mut out, &format!("250 2.0.0 queued as {}", envelope.id)).await?;
                        outcome.accepted += 1;
                    }
                    Err(_) => {
                        // Temporary: the sender keeps the message and will
                        // try again, which is where it belongs if our disk is
                        // unhappy.
                        say(&mut out, "451 4.3.0 cannot queue the message right now").await?;
                    }
                }

                from = None;
                recipients.clear();
            }

            Command::Rset => {
                from = None;
                recipients.clear();
                say(&mut out, "250 2.0.0 reset").await?;
            }

            Command::Noop => say(&mut out, "250 2.0.0 ok").await?,

            Command::Quit => {
                say(&mut out, &format!("221 2.0.0 {} closing", config.hostname)).await?;
                outcome.quit = true;
                return Ok(outcome);
            }

            // An alias table is not a directory for strangers to read, so the
            // answer is the same whether the address exists or not.
            Command::Vrfy => say(&mut out, "252 2.5.2 cannot verify, will try to deliver").await?,

            Command::Help => say(&mut out, "214 2.0.0 https://github.com/metronom72/mxhop").await?,

            Command::Unknown(_) => {
                say(&mut out, "500 5.5.2 command not recognised").await?;
                errors += 1;
                if errors >= config.max_errors {
                    say(&mut out, "421 4.7.0 too many errors, goodbye").await?;
                    return Ok(outcome);
                }
            }
        }
    }
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
        assert!(
            !t.out.contains("STARTTLS"),
            "not until it is actually implemented: {}",
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
    async fn starttls_is_refused_for_now_rather_than_pretended() {
        let t = talk("EHLO x.test\r\nSTARTTLS\r\nQUIT\r\n").await;
        assert_eq!(t.codes(), vec!["220", "250", "500", "221"]);
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
        };

        let (mut client, server) = duplex(4096);
        let task = tokio::spawn(async move {
            serve(
                server,
                "198.51.100.7:40000".to_string(),
                &config,
                &test_router(),
                &spool,
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
}
