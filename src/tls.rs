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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint(String);

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug)]
pub struct Holder {
    paths: TlsPaths,
    current: ArcSwap<ServerConfig>,
    fingerprint: ArcSwap<Fingerprint>,
}

impl Holder {
    pub fn open(paths: TlsPaths) -> Result<Arc<Self>, TlsError> {
        let (config, fingerprint) = build(&paths)?;
        Ok(Arc::new(Self {
            paths,
            current: ArcSwap::from(config),
            fingerprint: ArcSwap::from_pointee(fingerprint),
        }))
    }

    pub fn reload(&self) -> Result<Fingerprint, TlsError> {
        let (config, fingerprint) = build(&self.paths)?;
        self.current.store(config);
        self.fingerprint.store(Arc::new(fingerprint.clone()));
        Ok(fingerprint)
    }

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

pub fn current_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "an unnamed user".to_string())
}

fn build(paths: &TlsPaths) -> Result<(Arc<ServerConfig>, Fingerprint), TlsError> {
    let chain = read_chain(&paths.certificate)?;
    let key = read_key(&paths.key)?;
    let fingerprint = fingerprint_of(&chain[0]);

    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(TlsError::Rustls)?
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .map_err(|e| match e {
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

    #[test]
    fn a_file_that_cannot_be_opened_says_which_user_could_not_open_it() {
        let dir = scratch("tls-permission");
        let (crt, key) = write(&dir, "mx", "mx.test");
        std::fs::set_permissions(&crt, std::os::unix::fs::PermissionsExt::from_mode(0o000))
            .expect("drop the mode");

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
