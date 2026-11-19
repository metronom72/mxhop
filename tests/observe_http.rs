use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use mxhop::config::TlsPaths;
use mxhop::observe::{Health, Verdict, serve};
use mxhop::shutdown;
use mxhop::tls::Holder;

fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(name)
        .join(mxhop::spool::new_id());
    std::fs::create_dir_all(&dir).expect("a directory");
    dir
}

fn write_pair(dir: &Path, common_name: &str) -> TlsPaths {
    let generated =
        rcgen::generate_simple_self_signed([common_name.to_string()]).expect("a certificate");
    let certificate = dir.join("tls.crt");
    let key = dir.join("tls.key");
    std::fs::write(&certificate, generated.cert.pem()).expect("write certificate");
    std::fs::write(&key, generated.signing_key.serialize_pem()).expect("write key");
    TlsPaths {
        certificate,
        key,
        line: None,
    }
}

async fn get(port: u16, path: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    stream
        .write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
        .await
        .expect("write");

    let mut whole = String::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_string(&mut whole))
        .await
        .expect("the server answers")
        .expect("a readable response");

    let (head, body) = whole.split_once("\r\n\r\n").expect("a blank line");
    let status = head
        .split_whitespace()
        .nth(1)
        .expect("a status")
        .parse()
        .expect("a number");
    (status, body.to_string())
}

async fn start(health: Arc<Health>) -> (u16, shutdown::Trigger) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port");
    let port = listener.local_addr().unwrap().port();
    let (trigger, shutdown) = shutdown::channel();
    tokio::spawn(serve(listener, health, shutdown));
    (port, trigger)
}

#[tokio::test]
async fn a_failed_certificate_reload_does_not_take_healthz_down() {
    let dir = scratch("observe-reload");
    let paths = write_pair(&dir, "mx.test");
    let holder = Holder::open(paths.clone()).expect("a holder");
    let before = holder.fingerprint();

    let health = Health::new(10_000);
    health.listening(true);
    let (port, _trigger) = start(Arc::clone(&health)).await;

    assert_eq!(get(port, "/healthz").await.0, 200);

    std::fs::write(&paths.certificate, b"not a certificate at all\n").expect("break it");
    let failed = holder.reload();

    assert!(failed.is_err(), "the reload has to actually have failed");
    assert_eq!(
        holder.fingerprint(),
        before,
        "a failed reload keeps the certificate that was already loaded"
    );
    assert_eq!(health.verdict(), Verdict::Ready);

    let (status, body) = get(port, "/healthz").await;
    assert_eq!(
        status, 200,
        "a bad file on disk is not a reason to tell the orchestrator to kill a \
         process that is still serving mail on a certificate it already holds: {body}"
    );
}

#[tokio::test]
async fn healthz_turns_503_only_when_something_is_actually_wrong() {
    let health = Health::new(10_000);
    health.listening(true);
    let (port, _trigger) = start(Arc::clone(&health)).await;

    assert_eq!(get(port, "/healthz").await.0, 200);

    health.queue_writable(false);
    let (status, body) = get(port, "/healthz").await;
    assert_eq!(status, 503);
    assert!(body.contains("spool: no"), "{body}");

    health.queue_writable(true);
    assert_eq!(get(port, "/healthz").await.0, 200);
}

#[tokio::test]
async fn metrics_come_back_in_the_prometheus_text_format() {
    let health = Health::new(10_000);
    health.listening(true);
    let (port, _trigger) = start(Arc::clone(&health)).await;

    let (status, body) = get(port, "/metrics").await;

    assert_eq!(status, 200);
    assert!(
        body.contains("# TYPE mxhop_sessions_total counter"),
        "{body}"
    );
    assert!(body.contains("# TYPE mxhop_queue_depth gauge"), "{body}");
    assert!(
        body.contains("mxhop_session_seconds_bucket{le=\"+Inf\"}"),
        "{body}"
    );
    assert!(!body.contains('@'), "no addresses in metrics: {body}");
}

#[tokio::test]
async fn an_unknown_path_is_404_and_the_listener_stops_on_the_signal() {
    let health = Health::new(10_000);
    health.listening(true);
    let (port, trigger) = start(Arc::clone(&health)).await;

    assert_eq!(get(port, "/").await.0, 404);

    trigger.fire();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let after = tokio::time::timeout(
        Duration::from_secs(2),
        TcpStream::connect(("127.0.0.1", port)),
    )
    .await
    .expect("connecting must not hang");

    if let Ok(mut stream) = after {
        stream
            .write_all(b"GET /healthz HTTP/1.1\r\n\r\n")
            .await
            .ok();
        let mut back = String::new();
        let read =
            tokio::time::timeout(Duration::from_millis(500), stream.read_to_string(&mut back))
                .await;
        assert!(
            matches!(read, Ok(Ok(0))) || read.is_err(),
            "the listener is gone, so nothing should be answered: {back:?}"
        );
    }
}
