//! STARTTLS over real TCP, because the thing under test is the accept loop:
//! a reloaded certificate has to reach the next connection and leave the ones
//! already talking alone.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use mxhop::config::TlsPaths;
use mxhop::routing::{Mailbox, Route, Router};
use mxhop::server::accept_loop;
use mxhop::smtp::session::SessionConfig;
use mxhop::spool::Spool;
use mxhop::tls::Holder;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime, pem::PemObject};
use tokio_rustls::rustls::{self, ClientConfig};

// ------------------------------------------------------------- test fixtures

/// A directory of its own per run. `CARGO_TARGET_TMPDIR` survives between
/// runs, and a spool left behind by the last one would make the count at the
/// end of this test grow every time it is run.
fn dir(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("{name}-{}", mxhop::spool::new_id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

/// Generated rather than committed: a fixture expires, and two distinct
/// subjects are one call each.
fn write_pair(dir: &Path, name: &str, common_name: &str) -> (PathBuf, PathBuf) {
    let generated = rcgen::generate_simple_self_signed([common_name.to_string()])
        .expect("generate a certificate");
    let crt = dir.join(format!("{name}.crt"));
    let key = dir.join(format!("{name}.key"));
    std::fs::write(&crt, generated.cert.pem()).expect("write certificate");
    std::fs::write(&key, generated.signing_key.serialize_pem()).expect("write key");
    (crt, key)
}

fn leaf_of(path: &Path) -> Vec<u8> {
    CertificateDer::from_pem_file(path)
        .expect("read the leaf")
        .as_ref()
        .to_vec()
}

/// The test is about which certificate arrives, not about PKI.
#[derive(Debug)]
struct AcceptAnything(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AcceptAnything {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
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
        cert: &CertificateDer<'_>,
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
}

fn router() -> Router {
    let mut router = Router::default();
    router.insert(
        "example.com",
        "hi",
        Route::Forward(vec![Mailbox::parse("me@gmail.test").unwrap()]),
    );
    router
}

/// Connects, says EHLO, upgrades, and reports the leaf the server served.
async fn upgraded(
    address: std::net::SocketAddr,
) -> (Peer<impl AsyncRead + AsyncWrite + Unpin>, Vec<u8>) {
    let mut peer = Peer::new(TcpStream::connect(address).await.expect("connect"));
    peer.reply().await;
    peer.send("EHLO client.test\r\n").await;
    let greeting = peer.reply().await;
    assert!(greeting.contains("250-STARTTLS"), "{greeting}");
    peer.send("STARTTLS\r\n").await;
    assert!(peer.reply().await.starts_with("220"), "go ahead");

    let name = ServerName::try_from("mx.test").unwrap();
    let stream = connector()
        .connect(name, peer.io.into_inner())
        .await
        .expect("handshake");
    let leaf = stream
        .get_ref()
        .1
        .peer_certificates()
        .expect("a certificate")[0]
        .as_ref()
        .to_vec();

    (Peer::new(stream), leaf)
}

/// The whole point of the snapshot per accept. A certbot renewal replaces the
/// files while sessions are in flight; those sessions must finish on the
/// certificate they negotiated, and the next connection must get the new one
/// without a restart.
#[tokio::test]
async fn a_reload_is_seen_by_the_next_connection_and_not_the_current_one() {
    let root = dir("starttls");
    let (live_crt, live_key) = write_pair(&root, "live", "one.test");
    let a = leaf_of(&live_crt);

    let holder = Holder::open(TlsPaths {
        certificate: live_crt.clone(),
        key: live_key.clone(),
        line: None,
    })
    .expect("the first pair loads");

    let spool = Arc::new(
        Spool::open(&root.join("spool"))
            .await
            .expect("open the spool"),
    );
    let config = Arc::new(SessionConfig {
        hostname: "mx.test".into(),
        max_message_bytes: 1024 * 1024,
        max_recipients: 10,
        max_errors: 10,
        command_timeout: std::time::Duration::from_secs(10),
        data_timeout: std::time::Duration::from_secs(10),
        handshake_timeout: std::time::Duration::from_secs(10),
        ptr_timeout: std::time::Duration::from_secs(10),
        relay_budget: mxhop::smtp::session::RELAY_BUDGET,
        limits: mxhop::policy::Limits::default(),
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a high port");
    let address = listener.local_addr().expect("the address we actually got");
    let loop_task = tokio::spawn(accept_loop(
        listener,
        config,
        Arc::new(router()),
        Arc::clone(&spool),
        Arc::new(mxhop::smtp::client::Blackhole),
        Some(Arc::clone(&holder)),
    ));

    // Client one is inside the tunnel on certificate A, and stays there.
    let (mut first, first_leaf) = upgraded(address).await;
    assert_eq!(
        first_leaf, a,
        "the first session gets the first certificate"
    );

    // Somebody renews.
    let (other_crt, other_key) = write_pair(&root, "two", "two.test");
    let b = leaf_of(&other_crt);
    std::fs::copy(&other_crt, &live_crt).unwrap();
    std::fs::copy(&other_key, &live_key).unwrap();
    assert_ne!(a, b);
    holder.reload().expect("the replacement loads");

    // Client two sees B.
    let (mut second, second_leaf) = upgraded(address).await;
    assert_eq!(second_leaf, b, "the next connection gets the new one");

    // And client one, still on A, still delivers.
    first.send("EHLO client.test\r\n").await;
    first.reply().await;
    first.send("MAIL FROM:<sender@elsewhere.test>\r\n").await;
    assert!(first.reply().await.starts_with("250"));
    first.send("RCPT TO:<hi@example.com>\r\n").await;
    assert!(first.reply().await.starts_with("250"));
    first.send("DATA\r\n").await;
    assert!(first.reply().await.starts_with("354"));
    first.send("Subject: still here\r\n\r\nbody\r\n.\r\n").await;
    assert!(
        first.reply().await.starts_with("250"),
        "a session in flight is not a casualty of a renewal"
    );
    first.send("QUIT\r\n").await;
    second.send("QUIT\r\n").await;

    assert!(
        spool.queued().await.unwrap().is_empty(),
        "the message was handed on inside the session, so nothing is left in the queue"
    );
    loop_task.abort();
}
