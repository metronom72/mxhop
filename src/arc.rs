use std::fmt;
use std::path::{Path, PathBuf};

use mail_auth::arc::ArcSealer;
use mail_auth::crypto::{RsaKey, Sha256};
use mail_auth::signer::Ready;
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::pem::PemObject;

pub const SIGNED_HEADERS: &[&str] = &[
    "From",
    "To",
    "Cc",
    "Subject",
    "Date",
    "Message-ID",
    "In-Reply-To",
    "References",
    "MIME-Version",
    "Content-Type",
    "Content-Transfer-Encoding",
];

pub struct Sealer {
    inner: ArcSealer<RsaKey<Sha256>, Ready>,
    domain: String,
    selector: String,
}

impl fmt::Debug for Sealer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sealer")
            .field("domain", &self.domain)
            .field("selector", &self.selector)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArcError {
    Unreadable { path: PathBuf, why: String },
    NotAKey { path: PathBuf, why: String },
    NotRsa { path: PathBuf },
}

impl fmt::Display for ArcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArcError::Unreadable { path, why } => write!(
                f,
                "{} cannot be read as {}: {why}",
                path.display(),
                crate::tls::current_user()
            ),
            ArcError::NotAKey { path, why } => write!(
                f,
                "{} is not a private key in PEM form: {why}",
                path.display()
            ),
            ArcError::NotRsa { path } => write!(
                f,
                "{} is not an RSA key. Ed25519 is in the ARC specification and is \
                 not validated by every large receiver, so mxhop signs with RSA \
                 only: `openssl genrsa -out {} 2048`",
                path.display(),
                path.display()
            ),
        }
    }
}

impl Sealer {
    pub fn open(domain: &str, selector: &str, key_file: &Path) -> Result<Self, ArcError> {
        let der = PrivateKeyDer::from_pem_file(key_file).map_err(|e| {
            let why = e.to_string();
            if why.contains("No such file") || why.contains("denied") || why.contains("Os ") {
                ArcError::Unreadable {
                    path: key_file.to_path_buf(),
                    why,
                }
            } else {
                ArcError::NotAKey {
                    path: key_file.to_path_buf(),
                    why,
                }
            }
        })?;

        let key = RsaKey::<Sha256>::from_key_der(der).map_err(|_| ArcError::NotRsa {
            path: key_file.to_path_buf(),
        })?;

        Ok(Self {
            inner: ArcSealer::from_key(key)
                .domain(domain)
                .selector(selector)
                .headers(SIGNED_HEADERS.iter().map(|h| h.to_string())),
            domain: domain.to_string(),
            selector: selector.to_string(),
        })
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn selector(&self) -> &str {
        &self.selector
    }

    pub fn inner(&self) -> &ArcSealer<RsaKey<Sha256>, Ready> {
        &self.inner
    }

    pub fn record_name(&self) -> String {
        format!("{}._domainkey.{}", self.selector, self.domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join("mxhop-arc")
            .join(crate::spool::new_id());
        std::fs::create_dir_all(&dir).expect("a directory");
        dir.join(name)
    }

    fn rsa_pem() -> String {
        let pair = mail_auth::dkim::generate::DkimKeyPair::generate_rsa(2048).expect("a key pair");
        let body = encode(pair.private_key());
        format!("-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----\n")
    }

    fn encode(bytes: &[u8]) -> String {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b = [
                chunk[0],
                chunk.get(1).copied().unwrap_or(0),
                chunk.get(2).copied().unwrap_or(0),
            ];
            let word = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            for (i, shift) in [18, 12, 6, 0].into_iter().enumerate() {
                if i <= chunk.len() {
                    out.push(A[((word >> shift) & 0x3f) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out.as_bytes()
            .chunks(64)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn a_missing_key_names_the_path_and_the_user() {
        let path = scratch("absent.key");
        let e = Sealer::open("tooling.ninja", "arc1", &path).expect_err("no file there");

        assert!(matches!(e, ArcError::Unreadable { .. }), "{e:?}");
        assert!(e.to_string().contains(&path.display().to_string()));
    }

    #[test]
    fn something_that_is_not_a_key_says_so_rather_than_signing_nothing() {
        let path = scratch("rubbish.key");
        std::fs::write(&path, b"this is not a key\n").expect("write");

        let e = Sealer::open("tooling.ninja", "arc1", &path).expect_err("not a key");

        assert!(!matches!(e, ArcError::NotRsa { .. }), "{e:?}");
        assert!(e.to_string().contains("PEM"), "{e}");
    }

    #[test]
    fn an_rsa_key_opens_and_names_the_record_an_operator_has_to_publish() {
        let path = scratch("arc.key");
        std::fs::write(&path, rsa_pem()).expect("write");

        let sealer = Sealer::open("tooling.ninja", "arc1", &path).expect("an rsa key opens");

        assert_eq!(sealer.domain(), "tooling.ninja");
        assert_eq!(sealer.selector(), "arc1");
        assert_eq!(sealer.record_name(), "arc1._domainkey.tooling.ninja");
    }

    #[test]
    fn the_signed_headers_cover_what_a_receiver_checks_alignment_on() {
        assert!(
            SIGNED_HEADERS.contains(&"From"),
            "From is the DMARC identity"
        );
        assert!(SIGNED_HEADERS.contains(&"Subject"));
        assert!(SIGNED_HEADERS.contains(&"Date"));
        assert!(SIGNED_HEADERS.contains(&"Message-ID"));
    }
}
