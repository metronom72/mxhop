//! The certificate mxhop serves, and reloading it without a restart.
//!
//! Certificates are somebody else's job: Caddy or certbot renews the PEM
//! files, mxhop reads them. The whole point of this module is the second half
//! of that sentence — a renewal happens at three in the morning, and the only
//! acceptable way to pick it up is a signal, with the running service
//! unharmed if the files are half-written when it arrives.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;

use crate::config::TlsPaths;

/// What went wrong with the files, in the voice an operator needs: what mxhop
/// looked at, and what to do about it.
#[derive(Debug)]
pub enum TlsError {
    Unreadable { path: PathBuf, source: io::Error },
    NoCertificate(PathBuf),
    NoKey(PathBuf),
    Mismatch { certificate: PathBuf, key: PathBuf },
    Rustls(rustls::Error),
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsError::Unreadable { path, source } => {
                write!(
                    f,
                    "{} cannot be read: {source} — point it at the PEM Caddy or certbot writes, \
                     and give the mxhop user read access",
                    path.display()
                )?;
                // A 0600 key owned by Caddy reads fine for root and for
                // nobody else, so the same file produces a passing `check`
                // run by an admin and a failing `run` as the service user —
                // or the opposite, this refusal, while the service user's
                // access is already correct. Either way the user that did the
                // reading has to be in the sentence, otherwise the operator
                // goes off to fix permissions that were never broken.
                if source.kind() == io::ErrorKind::PermissionDenied {
                    write!(
                        f,
                        " — this ran as {}, which says nothing about the user the service runs \
                         as: `sudo -u mxhop mxhop check` reads the files the way `run` will",
                        current_user()
                    )?;
                }
                Ok(())
            }
            TlsError::NoCertificate(path) => write!(
                f,
                "{} contains no \"-----BEGIN CERTIFICATE-----\" block — Caddy writes the \
                 certificate as <name>.crt and the key as <name>.key; check they are not swapped",
                path.display()
            ),
            TlsError::NoKey(path) => write!(
                f,
                "{} contains no private key — expected a PEM PRIVATE KEY block \
                 (PKCS#8, RSA or EC)",
                path.display()
            ),
            TlsError::Mismatch { certificate, key } => write!(
                f,
                "the key in {} does not belong to the certificate in {} — if Caddy or certbot \
                 has just renewed, one file is new and the other is not yet: a reload a moment \
                 later picks up the finished pair, while at startup nothing is retrying, so \
                 the two files have to be made to match before mxhop will start",
                key.display(),
                certificate.display()
            ),
            TlsError::Rustls(e) => write!(f, "the certificate cannot be used: {e}"),
        }
    }
}

impl std::error::Error for TlsError {}

/// The SHA-256 of the leaf certificate's DER, lowercase hex pairs separated by
/// colons — the same string `openssl x509 -fingerprint -sha256` prints, so a
/// log line and a shell can be compared without arithmetic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint(String);

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Holds the certificate the next connection will use.
#[derive(Debug)]
pub struct Holder {
    paths: TlsPaths,
    current: ArcSwap<ServerConfig>,
    fingerprint: ArcSwap<Fingerprint>,
}

impl Holder {
    /// Reads the files once. Called at startup, where failing loudly is the
    /// right answer: there is no previous certificate to fall back to, and
    /// starting plaintext-only would downgrade every sender silently.
    pub fn open(paths: TlsPaths) -> Result<Arc<Self>, TlsError> {
        let (config, fingerprint) = build(&paths)?;
        Ok(Arc::new(Self {
            paths,
            current: ArcSwap::from(config),
            fingerprint: ArcSwap::from_pointee(fingerprint),
        }))
    }

    /// Rereads the files and, **only if that succeeded**, makes the result the
    /// one new connections get. A failed reload leaves the service serving
    /// what it served before.
    pub fn reload(&self) -> Result<Fingerprint, TlsError> {
        let (config, fingerprint) = build(&self.paths)?;
        self.current.store(config);
        self.fingerprint.store(Arc::new(fingerprint.clone()));
        Ok(fingerprint)
    }

    /// One snapshot, for one connection. A session keeps the certificate it
    /// started with, so its EHLO stays consistent with what STARTTLS does.
    pub fn acceptor(&self) -> TlsAcceptor {
        TlsAcceptor::from(self.current.load_full())
    }

    pub fn fingerprint(&self) -> Fingerprint {
        (**self.fingerprint.load()).clone()
    }

    pub fn paths(&self) -> &TlsPaths {
        &self.paths
    }
}

/// The user this process is running as, as a shell prompt would show it.
///
/// Read from the environment rather than from the system's user database:
/// mxhop has no C dependency for `getpwuid` and does not want one for a line
/// of prose. `sudo -u` sets `USER`, which is the case this exists for; a unit
/// file that scrubs the environment leaves it unknown, and an unknown user is
/// still better than implying the wrong one.
pub fn current_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "an unnamed user".to_string())
}

fn build(paths: &TlsPaths) -> Result<(Arc<ServerConfig>, Fingerprint), TlsError> {
    let chain = read_chain(&paths.certificate)?;
    let key = read_key(&paths.key)?;
    let fingerprint = fingerprint_of(&chain[0]);

    // The provider is named rather than left to rustls to work out. With
    // `ServerConfig::builder()` the choice is the process-wide default, and
    // that default is ambiguous — and so a panic, inside `Holder::open`, with
    // rustls's own wording rather than an operator message — the moment any
    // dependency enables `rustls/aws-lc-rs`. Outbound delivery is the next
    // milestone and several mail and HTTP crates pull aws-lc in by default,
    // so naming ring here is what keeps that from turning into a crash at
    // startup.
    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(TlsError::Rustls)?
            .with_no_client_auth()
            // A receiving MX cannot ask senders for certificates: nobody has one
            // it could check against.
            .with_single_cert(chain, key)
            .map_err(|e| match e {
                // rustls compares the public keys for us; the operator-facing
                // version of that is "your two files are from different
                // renewals".
                rustls::Error::InconsistentKeys(_) => TlsError::Mismatch {
                    certificate: paths.certificate.clone(),
                    key: paths.key.clone(),
                },
                other => TlsError::Rustls(other),
            })?;

    Ok((Arc::new(config), fingerprint))
}

fn read_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    readable(path)?;
    let chain: Vec<_> = CertificateDer::pem_file_iter(path)
        .map_err(|_| TlsError::NoCertificate(path.to_path_buf()))?
        .collect::<Result<_, _>>()
        .map_err(|_| TlsError::NoCertificate(path.to_path_buf()))?;

    if chain.is_empty() {
        return Err(TlsError::NoCertificate(path.to_path_buf()));
    }
    Ok(chain)
}

fn read_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsError> {
    readable(path)?;
    PrivateKeyDer::from_pem_file(path).map_err(|_| TlsError::NoKey(path.to_path_buf()))
}

/// Separates "I cannot open this" from "this is not a PEM file", because the
/// two have different fixes — a permission and a path.
fn readable(path: &Path) -> Result<(), TlsError> {
    std::fs::File::open(path).map_err(|source| TlsError::Unreadable {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

fn fingerprint_of(leaf: &CertificateDer<'_>) -> Fingerprint {
    let digest = ring::digest::digest(&ring::digest::SHA256, leaf.as_ref());
    let hex: Vec<String> = digest
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect();
    Fingerprint(hex.join(":"))
}

#[cfg(test)]
pub mod testing {
    //! Certificates are generated rather than committed: a fixture expires,
    //! and two distinct subjects are one call each.
    use std::path::{Path, PathBuf};

    pub struct Pair {
        pub certificate: String,
        pub key: String,
    }

    pub fn generate(common_name: &str) -> Pair {
        let cert = rcgen::generate_simple_self_signed([common_name.to_string()])
            .expect("generate a test certificate");
        Pair {
            certificate: cert.cert.pem(),
            key: cert.signing_key.serialize_pem(),
        }
    }

    /// Writes a fresh pair into `dir` as `name.crt` / `name.key`.
    pub fn write(dir: &Path, name: &str, common_name: &str) -> (PathBuf, PathBuf) {
        let pair = generate(common_name);
        let crt = dir.join(format!("{name}.crt"));
        let key = dir.join(format!("{name}.key"));
        std::fs::write(&crt, pair.certificate).expect("write certificate");
        std::fs::write(&key, pair.key).expect("write key");
        (crt, key)
    }

    pub fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join("mxhop-tests")
            .join(format!("{name}-{}", crate::spool::new_id()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{scratch, write};
    use super::*;

    fn paths(certificate: PathBuf, key: PathBuf) -> TlsPaths {
        TlsPaths {
            certificate,
            key,
            line: None,
        }
    }

    #[test]
    fn a_certificate_and_key_load() {
        let dir = scratch("tls-load");
        let (crt, key) = write(&dir, "mx", "mx.test");

        let holder = Holder::open(paths(crt, key)).expect("a fresh pair should load");
        assert_eq!(
            holder.fingerprint().to_string().len(),
            32 * 3 - 1,
            "a SHA-256 printed as colon-separated hex pairs"
        );
    }

    #[test]
    fn a_missing_file_names_the_path_and_the_fix() {
        let dir = scratch("tls-missing");
        let (_, key) = write(&dir, "mx", "mx.test");
        let absent = dir.join("gone.crt");

        let e = Holder::open(paths(absent.clone(), key)).expect_err("it is not there");
        let said = e.to_string();

        assert!(said.contains(&absent.display().to_string()), "{said}");
        assert!(said.contains("No such file"), "{said}");
        assert!(
            said.contains("read access"),
            "a permission is the other half of 'cannot be read': {said}"
        );
    }

    /// `ServerConfig::builder()` takes the process-wide default provider and
    /// panics when there is none or more than one. A dependency that enables
    /// `rustls/aws-lc-rs` would do exactly that, and the crash would land
    /// inside `Holder::open` — in `check` as well as `run`. Loading with no
    /// default installed is the only cheap proof that the provider is named
    /// here and not inherited.
    #[test]
    fn a_certificate_loads_without_a_process_wide_crypto_provider() {
        assert!(
            rustls::crypto::CryptoProvider::get_default().is_none(),
            "this test is only meaningful while nothing installs a default provider"
        );

        let dir = scratch("tls-provider");
        let (crt, key) = write(&dir, "mx", "mx.test");
        Holder::open(paths(crt, key)).expect("the provider is named, not looked up");
    }

    /// The message an admin gets when `[tls]` points at Caddy's 0600 key.
    /// Without the user in it, "give the mxhop user read access" sends them
    /// to fix permissions that may already be right, while the real
    /// difference is which user is doing the reading.
    #[test]
    fn a_file_that_cannot_be_opened_says_which_user_could_not_open_it() {
        let dir = scratch("tls-permission");
        let (crt, key) = write(&dir, "mx", "mx.test");
        std::fs::set_permissions(&crt, std::os::unix::fs::PermissionsExt::from_mode(0o000))
            .expect("drop the mode");

        // root reads it anyway, and then there is nothing to assert.
        if std::fs::File::open(&crt).is_ok() {
            return;
        }

        let e = Holder::open(paths(crt, key)).expect_err("0000 is not readable");
        let said = e.to_string();

        assert!(said.contains(&current_user()), "{said}");
        assert!(
            said.contains("sudo -u mxhop mxhop check"),
            "it has to name the command that reads the files as `run` will: {said}"
        );
    }

    /// The same text is printed at startup, where no reload is coming, and on
    /// SIGHUP, where one might. "reload again in a moment" alone is advice
    /// that does nothing for the startup case.
    #[test]
    fn the_mismatch_message_reads_at_startup_as_well_as_on_reload() {
        let dir = scratch("tls-mismatch-wording");
        let (crt, _) = write(&dir, "one", "one.test");
        let (_, key) = write(&dir, "two", "two.test");

        let said = Holder::open(paths(crt, key))
            .expect_err("the key belongs to the other one")
            .to_string();

        assert!(said.contains("reload"), "{said}");
        assert!(said.contains("startup"), "{said}");
    }

    /// A Caddy renewal that is half-finished leaves a new certificate beside
    /// an old key. Every handshake then fails, and the reason has to be in
    /// the log rather than in a packet capture.
    #[test]
    fn a_key_from_another_certificate_is_refused() {
        let dir = scratch("tls-mismatch");
        let (crt, _) = write(&dir, "one", "one.test");
        let (_, key) = write(&dir, "two", "two.test");

        let e = Holder::open(paths(crt, key)).expect_err("the key belongs to the other one");
        assert!(
            e.to_string().contains("does not belong to"),
            "{}",
            e.to_string()
        );
    }

    #[test]
    fn swapped_crt_and_key_say_so() {
        let dir = scratch("tls-swapped");
        let (crt, key) = write(&dir, "mx", "mx.test");

        let e = Holder::open(paths(key, crt)).expect_err("the files are the wrong way round");
        let said = e.to_string();

        assert!(
            said.contains("no \"-----BEGIN CERTIFICATE-----\""),
            "{said}"
        );
        assert!(said.contains("swapped"), "{said}");
    }

    /// The bug this exists for: storing the result of a failed read drops TLS
    /// for everyone until somebody notices.
    #[test]
    fn a_reload_with_a_broken_file_keeps_the_running_certificate() {
        let dir = scratch("tls-reload");
        let (crt, key) = write(&dir, "live", "one.test");
        let holder = Holder::open(paths(crt.clone(), key)).expect("the first pair loads");
        let before = holder.fingerprint();

        std::fs::write(&crt, "junk, not a certificate\n").expect("break the file");
        let e = holder.reload().expect_err("junk is not a certificate");

        assert!(e.to_string().contains("BEGIN CERTIFICATE"), "{e}");
        assert_eq!(
            holder.fingerprint(),
            before,
            "a failed reload must not disturb what is already serving"
        );
    }

    #[test]
    fn a_reload_of_a_replaced_pair_reports_the_new_fingerprint() {
        let dir = scratch("tls-replace");
        let (crt, key) = write(&dir, "live", "one.test");
        let holder = Holder::open(paths(crt.clone(), key.clone())).expect("the first pair loads");
        let before = holder.fingerprint();

        let (other_crt, other_key) = write(&dir, "two", "two.test");
        std::fs::copy(&other_crt, &crt).unwrap();
        std::fs::copy(&other_key, &key).unwrap();

        let after = holder.reload().expect("the replacement loads");
        assert_ne!(after, before);
        assert_eq!(holder.fingerprint(), after);
    }
}
