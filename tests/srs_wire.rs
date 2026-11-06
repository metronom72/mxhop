//! SRS over real sockets, both directions.
//!
//! The session-level tests in `smtp::session` drive the state machine over a
//! pipe and read the sender off the `Delivery` struct. That proves what mxhop
//! decided; it does not prove what it *wrote*. The envelope sender is the one
//! field a destination's SPF check is made against, so the bytes of the
//! `MAIL FROM` line are worth a test that reads them off a socket — and it is
//! the same test the deployment is verified with, one port number apart.

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use mxhop::dns::Table;
use mxhop::routing::{Mailbox, Route, Router};
use mxhop::smtp::client::{Direct, Outbound};
use mxhop::smtp::session::{self, RELAY_BUDGET, SessionConfig};
use mxhop::spool::Spool;
use mxhop::srs::{DEFAULT_MAX_AGE_DAYS, Srs};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

/// Everything a destination was told, line by line, with the envelope it was
/// given kept apart from the chatter.
#[derive(Debug, Default)]
struct Seen {
    lines: Vec<String>,
}

impl Seen {
    fn line_starting(&self, prefix: &str) -> Option<&str> {
        self.lines
            .iter()
            .find(|l| l.to_ascii_uppercase().starts_with(prefix))
            .map(String::as_str)
    }
}

/// A destination that accepts everything and writes down what it was told.
///
/// Deliberately not mxhop: what is being checked is the bytes one SMTP
/// implementation puts on the wire, and a second copy of the same parser
/// would agree with a shared mistake.
async fn sink() -> (u16, Arc<Mutex<Seen>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind a sink");
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let kept = Arc::clone(&seen);

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let kept = Arc::clone(&kept);
            tokio::spawn(async move {
                let mut reader = BufReader::new(stream);
                reader
                    .get_mut()
                    .write_all(b"220 sink.test ESMTP\r\n")
                    .await
                    .ok();
                let mut in_data = false;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                        return;
                    }
                    let line = line.trim_end_matches(['\r', '\n']).to_string();
                    if in_data {
                        if line == "." {
                            in_data = false;
                            reader
                                .get_mut()
                                .write_all(b"250 2.0.0 accepted\r\n")
                                .await
                                .ok();
                        }
                        continue;
                    }
                    kept.lock().unwrap().lines.push(line.clone());
                    let upper = line.to_ascii_uppercase();
                    let answer: &[u8] = if upper.starts_with("EHLO") {
                        b"250-sink.test\r\n250 SIZE 52428800\r\n"
                    } else if upper.starts_with("DATA") {
                        in_data = true;
                        b"354 go on\r\n"
                    } else if upper.starts_with("QUIT") {
                        reader.get_mut().write_all(b"221 2.0.0 bye\r\n").await.ok();
                        return;
                    } else {
                        b"250 2.0.0 ok\r\n"
                    };
                    reader.get_mut().write_all(answer).await.ok();
                }
            });
        }
    });

    (port, seen)
}

/// A secret generated here. A key-shaped literal in a source file is a key in
/// a source file, whatever the comment beside it says.
fn secret() -> Vec<u8> {
    format!("mxhop-wire-test-{}", mxhop::spool::new_id()).into_bytes()
}

const SRS_DOMAIN: &str = "srs.tooling.ninja";

/// mxhop on a high port, forwarding `hi@forwarded.test` to
/// `destination@mailbox.test`, whose only mail exchanger is the sink.
async fn serve_mxhop(srs: Srs, sink_port: u16) -> (u16, Spool) {
    let mut router = Router::default();
    router.insert(
        "forwarded.test",
        "hi",
        Route::Forward(vec![Mailbox::parse("destination@mailbox.test").unwrap()]),
    );

    let table = Table::default()
        .mx("mailbox.test", &[(10, "mx.mailbox.test")])
        .addr("mx.mailbox.test", "127.0.0.1".parse().unwrap())
        .mx("elsewhere.test", &[(10, "mx.elsewhere.test")])
        .addr("mx.elsewhere.test", "127.0.0.1".parse().unwrap());

    // The real outbound client, over real TCP, with nothing changed but the
    // port — binding 25 needs privileges a test does not have.
    let mut out = Outbound::new("mx.tooling.ninja", false);
    out.port = sink_port;
    // Plaintext: the sink offers no STARTTLS, and the handshake is not what
    // is under test.
    out.tls = None;
    let relay = Arc::new(Direct::new(table, out, None));

    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("srs_wire")
        .join(mxhop::spool::new_id());
    let spool = Spool::open(&dir).await.expect("open a spool");

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mxhop");
    let port = listener.local_addr().unwrap().port();

    let config = SessionConfig {
        hostname: "mx.tooling.ninja".into(),
        max_message_bytes: 26_214_400,
        max_recipients: 10,
        max_errors: 4,
        command_timeout: Duration::from_secs(10),
        data_timeout: Duration::from_secs(10),
        handshake_timeout: Duration::from_secs(10),
        ptr_timeout: Duration::from_secs(1),
        relay_budget: RELAY_BUDGET,
        limits: Default::default(),
        auth_enabled: true,
    };

    let spool_for_task = spool.clone();
    tokio::spawn(async move {
        let srs = Arc::new(srs);
        while let Ok((stream, peer)) = listener.accept().await {
            let config = config.clone();
            let router = router.clone();
            let srs = Arc::clone(&srs);
            let spool = spool_for_task.clone();
            let relay = Arc::clone(&relay);
            tokio::spawn(async move {
                session::serve(
                    stream,
                    peer.to_string(),
                    &config,
                    &router,
                    Some(srs.as_ref()),
                    &spool,
                    relay.as_ref(),
                    None,
                )
                .await
                .ok();
            });
        }
    });

    (port, spool)
}

/// One SMTP conversation against mxhop, as a sending server has it: the
/// script in, the replies out.
async fn send(port: u16, script: &str) -> String {
    let stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect to mxhop");
    let mut reader = BufReader::new(stream);
    let mut out = String::new();

    /// One reply, continuation lines included: a `-` in the fourth column
    /// means there is more of it coming.
    async fn reply<S>(reader: &mut BufReader<S>) -> String
    where
        S: tokio::io::AsyncRead + Unpin,
    {
        let mut whole = String::new();
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                return whole;
            }
            whole.push_str(&line);
            if line.len() < 4 || line.as_bytes()[3] != b'-' {
                return whole;
            }
        }
    }

    out.push_str(&reply(&mut reader).await);

    // The body of a DATA block is not answered line by line, so a reader
    // that waits for a reply after every line deadlocks on the first one.
    let mut in_body = false;
    for step in script.split_inclusive('\n') {
        reader
            .get_mut()
            .write_all(step.as_bytes())
            .await
            .expect("write a command");
        if in_body {
            if step.trim_end() == "." {
                in_body = false;
                out.push_str(&reply(&mut reader).await);
            }
            continue;
        }
        let answer = reply(&mut reader).await;
        if answer.starts_with("354") {
            in_body = true;
        }
        out.push_str(&answer);
    }
    out
}

/// What the destination is actually told, in the bytes it reads.
///
/// Before SRS this line carried the original sender, whose SPF record does
/// not name this host; Gmail junked two test messages from this project for
/// exactly that.
///
/// It exists because it reads the `MAIL FROM` line off a socket. Reverting
/// the rewrite in `session::hand_on` also fails the unit test
/// `smtp::session::tests::the_envelope_sender_handed_to_the_destination_is_rewritten`,
/// which an earlier version of this comment denied — but that one asks the
/// fake relay what it was handed, and this one asks what was written to a
/// real TCP socket and read back by a real SMTP peer. A rewrite that is
/// correct in the struct and lost on the way to the wire fails only this
/// one, and that is a failure this project has had before.
#[tokio::test]
async fn the_mail_from_line_the_destination_reads_is_at_our_srs_domain() {
    let srs = Srs::new(SRS_DOMAIN, vec![secret()], DEFAULT_MAX_AGE_DAYS);
    let (sink_port, seen) = sink().await;
    let (port, _spool) = serve_mxhop(srs.clone(), sink_port).await;

    let out = send(
        port,
        "EHLO mail.elsewhere.test\r\n\
         MAIL FROM:<Author@elsewhere.test>\r\n\
         RCPT TO:<hi@forwarded.test>\r\n\
         DATA\r\n\
         Subject: forwarded\r\n\
         \r\n\
         body\r\n\
         .\r\n\
         QUIT\r\n",
    )
    .await;
    assert!(out.contains("250 2.0.0 delivered as"), "{out}");

    let seen = seen.lock().unwrap();
    let mail_from = seen
        .line_starting("MAIL FROM")
        .unwrap_or_else(|| panic!("the sink saw no MAIL FROM: {:#?}", seen.lines))
        .to_string();

    assert!(
        mail_from.contains(&format!("@{SRS_DOMAIN}>")),
        "the destination checks SPF against this and nothing else: {mail_from}"
    );
    assert!(
        !mail_from.contains("elsewhere.test>"),
        "and the original sender's domain must not be what it checks: {mail_from}"
    );

    let address = mail_from
        .trim_start_matches("MAIL FROM:<")
        .split('>')
        .next()
        .unwrap();
    assert_eq!(
        srs.verify(address.rsplit_once('@').unwrap().0, mxhop::srs::today())
            .expect("the address on the wire is one we can decode")
            .to_string(),
        "Author@elsewhere.test",
        "a bounce to it has to be able to find the author again"
    );
}

/// The bounce, end to end over sockets: a destination takes the address it
/// read off our `MAIL FROM` line and offers it back with an empty envelope
/// sender, which is what a delivery report looks like.
#[tokio::test]
async fn a_bounce_to_an_address_we_wrote_is_relayed_and_a_forged_one_is_not() {
    let srs = Srs::new(SRS_DOMAIN, vec![secret()], DEFAULT_MAX_AGE_DAYS);
    let (sink_port, seen) = sink().await;
    let (port, _spool) = serve_mxhop(srs.clone(), sink_port).await;

    let honest = srs
        .rewrite(Some("author@elsewhere.test"), mxhop::srs::today())
        .expect("a rewritten sender");

    let out = send(
        port,
        &format!(
            "EHLO mx.gmail.test\r\n\
             MAIL FROM:<>\r\n\
             RCPT TO:<{honest}>\r\n\
             DATA\r\n\
             Subject: Undelivered Mail Returned to Sender\r\n\
             \r\n\
             mailbox full\r\n\
             .\r\n\
             QUIT\r\n"
        ),
    )
    .await;
    assert!(out.contains("250 2.0.0 delivered as"), "{out}");

    {
        let seen = seen.lock().unwrap();
        assert_eq!(
            seen.line_starting("MAIL FROM"),
            Some("MAIL FROM:<>"),
            "a relayed bounce keeps its own null sender: {:#?}",
            seen.lines
        );
        assert_eq!(
            seen.line_starting("RCPT TO"),
            Some("RCPT TO:<author@elsewhere.test>"),
            "and reaches the person who wrote the original message: {:#?}",
            seen.lines
        );
    }

    // The same address with one character of the MAC changed. This is the
    // open-relay case: if it were accepted, anyone could post mail through
    // this host to any address in the world.
    //
    // The MAC runs from index 5 to the next `=`, and the index flipped below
    // has to land inside it or nothing about the signature is being tested.
    // Asserted rather than trusted, because the MAC's length has been
    // changed once already.
    assert!(
        honest[5..].find('=').expect("a MAC terminator") + 5 > 6,
        "index 6 has to be inside the MAC of {honest}"
    );
    let mut forged: Vec<char> = honest.chars().collect();
    forged[6] = if forged[6] == 'A' { 'B' } else { 'A' };
    let forged: String = forged.into_iter().collect();

    let out = send(
        port,
        &format!(
            "EHLO mx.attacker.test\r\n\
             MAIL FROM:<>\r\n\
             RCPT TO:<{forged}>\r\n\
             QUIT\r\n"
        ),
    )
    .await;

    assert!(
        out.contains("550 5.1.1 not an address we issued"),
        "a forged SRS recipient has to be refused: {out}"
    );

    // Nothing left this host for the forged address: the sink's record still
    // has exactly the one conversation the honest bounce made.
    let seen = seen.lock().unwrap();
    let conversations = seen
        .lines
        .iter()
        .filter(|l| l.to_ascii_uppercase().starts_with("MAIL FROM"))
        .count();
    assert_eq!(
        conversations, 1,
        "one delivery, the honest one: {:#?}",
        seen.lines
    );
}
