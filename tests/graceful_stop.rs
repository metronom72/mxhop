use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use mxhop::policy::Limits;
use mxhop::routing::{Mailbox, Route, Router};
use mxhop::server::accept_loop;
use mxhop::shutdown;
use mxhop::smtp::client::Blackhole;
use mxhop::smtp::session::SessionConfig;
use mxhop::spool::Spool;

fn router() -> Router {
    let mut r = Router::default();
    r.insert(
        "example.com",
        "hi",
        Route::Forward(vec![Mailbox::parse("me@gmail.test").unwrap()]),
    );
    r
}

fn config() -> SessionConfig {
    SessionConfig {
        hostname: "mx.test".into(),
        max_message_bytes: 26_214_400,
        max_recipients: 10,
        max_errors: 4,
        command_timeout: Duration::from_secs(30),
        data_timeout: Duration::from_secs(30),
        handshake_timeout: Duration::from_secs(10),
        ptr_timeout: Duration::from_secs(1),
        relay_budget: Duration::from_secs(30),
        queue: mxhop::queue::Schedule::default(),
        auth_enabled: false,
        limits: Limits::default(),
    }
}

struct Server {
    port: u16,
    trigger: shutdown::Trigger,
    idle: shutdown::Idle,
    loop_task: tokio::task::JoinHandle<()>,
    spool: Arc<Spool>,
}

async fn start() -> Server {
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("graceful")
        .join(mxhop::spool::new_id());
    let spool = Arc::new(Spool::open(&dir).await.expect("a spool"));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port");
    let port = listener.local_addr().unwrap().port();

    let (trigger, shutdown) = shutdown::channel();
    let (tracker, idle) = shutdown::tracker();

    let loop_task = tokio::spawn(accept_loop(
        listener,
        Arc::new(config()),
        Arc::new(router()),
        None,
        Arc::clone(&spool),
        Arc::new(Blackhole),
        None,
        shutdown,
        tracker,
    ));

    Server {
        port,
        trigger,
        idle,
        loop_task,
        spool,
    }
}

async fn connect(port: u16) -> BufReader<TcpStream> {
    let stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let mut reader = BufReader::new(stream);
    let banner = read_reply(&mut reader).await;
    assert!(banner.starts_with("220 "), "{banner}");
    reader
}

async fn send(reader: &mut BufReader<TcpStream>, line: &str) -> String {
    reader
        .get_mut()
        .write_all(format!("{line}\r\n").as_bytes())
        .await
        .expect("write");
    read_reply(reader).await
}

async fn read_reply(reader: &mut BufReader<TcpStream>) -> String {
    let mut whole = String::new();
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line).await.expect("a reply");
        assert!(read > 0, "the connection closed mid-reply: {whole:?}");
        let more = line.as_bytes().get(3) == Some(&b'-');
        whole.push_str(&line);
        if !more {
            return whole;
        }
    }
}

#[tokio::test]
async fn a_session_in_the_middle_of_data_finishes_and_the_process_can_then_exit() {
    let server = start().await;
    let mut client = connect(server.port).await;

    assert!(
        send(&mut client, "EHLO sender.test")
            .await
            .starts_with("250")
    );
    assert!(
        send(&mut client, "MAIL FROM:<a@sender.test>")
            .await
            .starts_with("250")
    );
    assert!(
        send(&mut client, "RCPT TO:<hi@example.com>")
            .await
            .starts_with("250")
    );
    assert!(send(&mut client, "DATA").await.starts_with("354"));

    client
        .get_mut()
        .write_all(b"Subject: half a message\r\n\r\nthe first line\r\n")
        .await
        .expect("write");

    server.trigger.fire();
    tokio::time::sleep(Duration::from_millis(100)).await;

    client
        .get_mut()
        .write_all(b"the rest of it\r\n.\r\n")
        .await
        .expect("the body must still be accepted");

    let reply = read_reply(&mut client).await;
    assert!(
        reply.starts_with("250"),
        "a message already inside DATA is taken, not thrown away: {reply}"
    );

    let next = send(&mut client, "MAIL FROM:<b@sender.test>").await;
    assert!(
        next.starts_with("421"),
        "and the next command is refused, because the server is stopping: {next}"
    );

    tokio::time::timeout(Duration::from_secs(5), server.loop_task)
        .await
        .expect("the accept loop returns on the signal")
        .expect("and does not panic");

    assert!(
        server.idle.wait(Duration::from_secs(5)).await,
        "every session finished, so the process is free to exit"
    );
}

#[tokio::test]
async fn a_client_waiting_for_a_command_is_told_to_come_back() {
    let server = start().await;
    let mut client = connect(server.port).await;

    assert!(
        send(&mut client, "EHLO sender.test")
            .await
            .starts_with("250")
    );

    server.trigger.fire();

    let reply = read_reply(&mut client).await;
    assert!(reply.starts_with("421"), "{reply}");
    assert!(
        reply.contains("shutting down"),
        "the sender has to be able to tell this from a timeout: {reply}"
    );

    assert!(server.idle.wait(Duration::from_secs(5)).await);
}

#[tokio::test]
async fn nothing_new_is_accepted_once_the_signal_has_been_given() {
    let server = start().await;

    server.trigger.fire();
    tokio::time::timeout(Duration::from_secs(5), server.loop_task)
        .await
        .expect("the accept loop returns")
        .expect("without panicking");

    let refused = tokio::time::timeout(
        Duration::from_secs(2),
        TcpStream::connect(("127.0.0.1", server.port)),
    )
    .await;

    match refused {
        Ok(Err(_)) => {}
        Ok(Ok(stream)) => {
            let mut reader = BufReader::new(stream);
            let mut banner = String::new();
            let read =
                tokio::time::timeout(Duration::from_millis(500), reader.read_line(&mut banner))
                    .await;
            assert!(
                matches!(read, Ok(Ok(0))) || read.is_err(),
                "a connection the kernel had already queued must not be served a \
                 banner: {banner:?}"
            );
        }
        Err(_) => panic!("connecting should not hang"),
    }

    assert!(server.spool.queued().await.unwrap().is_empty());
}
