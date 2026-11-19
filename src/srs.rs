use std::fmt;

use ring::hmac;

use crate::routing::Mailbox;

pub const DEFAULT_MAX_AGE_DAYS: u32 = 7;

pub const MAX_AGE_DAYS_CEILING: u32 = 365;

pub const MAX_LOCAL_PART_OCTETS: usize = 64;

pub const MIN_SECRET_BYTES: usize = 16;

const DAYS: u32 = 1024;

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const MAC_CHARS: usize = 8;

const PREFIX: &str = "SRS0";

#[derive(Clone)]
pub struct Srs {
    domain: String,
    keys: Vec<Vec<u8>>,
    max_age_days: u32,
}

impl fmt::Debug for Srs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Srs")
            .field("domain", &self.domain)
            .field("keys", &self.keys.len())
            .field("max_age_days", &self.max_age_days)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    NotSrs,
    BadSignature,
    Expired,
    Undeliverable(String),
}

impl Refusal {
    pub fn reply(&self) -> &'static str {
        match self {
            Refusal::Expired => "550 5.1.1 expired",
            Refusal::NotSrs | Refusal::BadSignature | Refusal::Undeliverable(_) => {
                "550 5.1.1 not an address we issued"
            }
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::NotSrs => f.write_str("not in the SRS shape"),
            Refusal::BadSignature => f.write_str("signed with no key we hold"),
            Refusal::Expired => f.write_str("older than the expiry window"),
            Refusal::Undeliverable(what) => write!(f, "decodes to something undeliverable: {what}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretError {
    Empty,
    TooShort { line: usize, len: usize },
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretError::Empty => write!(
                f,
                "holds no key: put one line of at least {MIN_SECRET_BYTES} \
                 characters in it, for example with \
                 `head -c 32 /dev/urandom | base64 > srs.key && chmod 600 srs.key`"
            ),
            SecretError::TooShort { line, len } => write!(
                f,
                "the key on line {line} is {len} characters, and a signing key has to be \
                 at least {MIN_SECRET_BYTES} — without it the signature stops being the \
                 thing that keeps this host from being an open relay; replace it with \
                 `head -c 32 /dev/urandom | base64`"
            ),
        }
    }
}

impl Srs {
    pub fn new(domain: &str, keys: Vec<Vec<u8>>, max_age_days: u32) -> Self {
        Self {
            domain: domain.to_ascii_lowercase(),
            keys,
            max_age_days,
        }
    }

    pub fn keys_from(contents: &str) -> Result<Vec<Vec<u8>>, SecretError> {
        let mut keys = Vec::new();
        for (i, line) in contents.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if line.len() < MIN_SECRET_BYTES {
                return Err(SecretError::TooShort {
                    line: i + 1,
                    len: line.len(),
                });
            }
            keys.push(line.as_bytes().to_vec());
        }
        if keys.is_empty() {
            return Err(SecretError::Empty);
        }
        Ok(keys)
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn max_age_days(&self) -> u32 {
        self.max_age_days
    }

    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    pub fn is_ours(&self, domain: &str) -> bool {
        domain.eq_ignore_ascii_case(&self.domain)
    }

    pub fn wrappable(&self, sender: &str) -> Result<(), crate::routing::MailboxError> {
        Mailbox::parse(sender).map(|_| ())
    }

    pub fn rewrite(&self, sender: Option<&str>, day: u32) -> Option<String> {
        let mailbox = Mailbox::parse(sender?).ok()?;
        if self.is_ours(mailbox.domain()) {
            return None;
        }
        let tt = base32_day(day);
        let mac = self.sign(&payload(&tt, mailbox.domain(), mailbox.local()));
        Some(format!(
            "{PREFIX}={mac}={tt}={}={}@{}",
            mailbox.domain(),
            mailbox.local(),
            self.domain
        ))
    }

    pub fn verify(&self, local: &str, day: u32) -> Result<Mailbox, Refusal> {
        let mut parts = local.splitn(5, '=');
        let prefix = parts.next().ok_or(Refusal::NotSrs)?;
        if !prefix.eq_ignore_ascii_case(PREFIX) {
            return Err(Refusal::NotSrs);
        }
        let (Some(mac), Some(tt), Some(domain), Some(orig)) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(Refusal::NotSrs);
        };
        if mac.len() != MAC_CHARS || tt.len() != 2 || domain.is_empty() || orig.is_empty() {
            return Err(Refusal::NotSrs);
        }
        let issued = day_of_base32(tt).ok_or(Refusal::NotSrs)?;

        if !self.verifies(&payload(tt, domain, orig), mac) {
            return Err(Refusal::BadSignature);
        }
        if !self.in_date(issued, day) {
            return Err(Refusal::Expired);
        }

        Mailbox::parse(&format!("{orig}@{domain}"))
            .map_err(|e| Refusal::Undeliverable(format!("{orig}@{domain} {e}")))
    }

    fn in_date(&self, issued: u32, now: u32) -> bool {
        let age = (now % DAYS + DAYS - issued % DAYS) % DAYS;
        age <= self.max_age_days || age == DAYS - 1
    }

    fn sign(&self, payload: &str) -> String {
        let key = self.keys.first().map(Vec::as_slice).unwrap_or(&[]);
        mac_chars(key, payload)
    }

    fn verifies(&self, payload: &str, offered: &str) -> bool {
        self.keys
            .iter()
            .any(|key| mac_chars(key, payload).eq_ignore_ascii_case(offered))
    }
}

fn payload(tt: &str, domain: &str, local: &str) -> String {
    format!("{tt}={domain}={local}").to_ascii_lowercase()
}

fn mac_chars(key: &[u8], payload: &str) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    base64_head(hmac::sign(&key, payload.as_bytes()).as_ref())
}

fn base64_head(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(MAC_CHARS);
    let head = &bytes[..6.min(bytes.len())];
    for chunk in head.chunks(3) {
        let mut word = 0u32;
        for (i, byte) in chunk.iter().enumerate() {
            word |= u32::from(*byte) << (16 - 8 * i);
        }
        for shift in [18, 12, 6, 0] {
            if out.len() == MAC_CHARS {
                return out;
            }
            out.push(BASE64[((word >> shift) & 0x3f) as usize] as char);
        }
    }
    out
}

fn base32_day(day: u32) -> String {
    let day = day % DAYS;
    let mut s = String::with_capacity(2);
    s.push(BASE32[(day / 32) as usize] as char);
    s.push(BASE32[(day % 32) as usize] as char);
    s
}

fn day_of_base32(tt: &str) -> Option<u32> {
    let mut day = 0u32;
    for c in tt.chars() {
        let c = c.to_ascii_uppercase() as u8;
        day = day * 32 + BASE32.iter().position(|b| *b == c)? as u32;
    }
    Some(day % DAYS)
}

pub fn open(settings: &crate::config::SrsSettings) -> Result<Srs, String> {
    let contents = std::fs::read_to_string(&settings.secret_file).map_err(|e| {
        format!(
            "the srs secret file {} cannot be read: {e} — generate one with \
             `head -c 32 /dev/urandom | base64 > {} && chmod 600 {}`",
            settings.secret_file.display(),
            settings.secret_file.display(),
            settings.secret_file.display()
        )
    })?;
    let keys = Srs::keys_from(&contents).map_err(|e| {
        format!(
            "the srs secret file {}: {e}",
            settings.secret_file.display()
        )
    })?;
    Ok(Srs::new(&settings.domain, keys, settings.max_age_days))
}

pub fn today() -> u32 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    ((secs / 86_400) % u64::from(DAYS)) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(tag: &str) -> Vec<u8> {
        format!("mxhop-test-key-{tag}-{}", "x".repeat(16)).into_bytes()
    }

    fn srs() -> Srs {
        Srs::new("srs.tooling.ninja", vec![key("a")], DEFAULT_MAX_AGE_DAYS)
    }

    fn local_of(address: &str) -> String {
        address.rsplit_once('@').expect("an address").0.to_string()
    }

    #[test]
    fn forward_and_reverse_round_trip_the_original_address() {
        let srs = srs();
        let wrapped = srs
            .rewrite(Some("Someone@elsewhere.test"), 100)
            .expect("an ordinary sender is rewritten");

        assert!(
            wrapped.ends_with("@srs.tooling.ninja"),
            "the rewritten sender has to be at the domain whose SPF record is us: {wrapped}"
        );
        assert_eq!(
            srs.verify(&local_of(&wrapped), 100)
                .expect("our own address verifies")
                .to_string(),
            "Someone@elsewhere.test",
            "the bounce has to reach the person who wrote the message, \
             with the local part's case as they sent it"
        );
    }

    #[test]
    fn the_hash_covers_timestamp_domain_and_local() {
        let srs = srs();
        let wrapped = local_of(&srs.rewrite(Some("a@elsewhere.test"), 100).unwrap());
        let parts: Vec<&str> = wrapped.splitn(5, '=').collect();
        let (mac, tt, domain, local) = (parts[1], parts[2], parts[3], parts[4]);

        for forged in [
            format!("SRS0={mac}=CC={domain}={local}"),
            format!("SRS0={mac}={tt}=victim.test={local}"),
            format!("SRS0={mac}={tt}={domain}=someone-else"),
        ] {
            assert_eq!(
                srs.verify(&forged, 100),
                Err(Refusal::BadSignature),
                "{forged} must not verify"
            );
        }
    }

    #[test]
    fn verification_ignores_case_in_hash_and_timestamp() {
        let srs = srs();
        let wrapped = local_of(&srs.rewrite(Some("a@elsewhere.test"), 100).unwrap());

        assert!(
            srs.verify(&wrapped.to_ascii_lowercase(), 100).is_ok(),
            "a lowercased copy of our own address must still verify"
        );
        assert!(
            srs.verify(&wrapped.to_ascii_uppercase(), 100).is_ok(),
            "and an uppercased one"
        );
    }

    #[test]
    fn a_rotated_secret_still_verifies_yesterdays_addresses() {
        let old = Srs::new("srs.tooling.ninja", vec![key("old")], DEFAULT_MAX_AGE_DAYS);
        let yesterday = local_of(&old.rewrite(Some("a@elsewhere.test"), 99).unwrap());

        let rotated = Srs::new(
            "srs.tooling.ninja",
            vec![key("new"), key("old")],
            DEFAULT_MAX_AGE_DAYS,
        );
        assert!(
            rotated.verify(&yesterday, 100).is_ok(),
            "a bounce signed with the retired key still has to come home"
        );

        let fresh = local_of(&rotated.rewrite(Some("a@elsewhere.test"), 100).unwrap());
        assert!(
            old.verify(&fresh, 100).is_err(),
            "and the new addresses have to be signed with the new key, \
             or rotation changed nothing"
        );
    }

    #[test]
    fn an_address_older_than_max_age_is_refused() {
        let srs = srs();
        let wrapped = local_of(&srs.rewrite(Some("a@elsewhere.test"), 100).unwrap());

        assert!(
            srs.verify(&wrapped, 100 + DEFAULT_MAX_AGE_DAYS).is_ok(),
            "the last day of the window is still inside it"
        );
        assert_eq!(
            srs.verify(&wrapped, 100 + DEFAULT_MAX_AGE_DAYS + 1),
            Err(Refusal::Expired)
        );
    }

    #[test]
    fn one_day_in_the_future_is_tolerated() {
        let srs = srs();
        let tomorrow = local_of(&srs.rewrite(Some("a@elsewhere.test"), 101).unwrap());

        assert!(srs.verify(&tomorrow, 100).is_ok());
        let later = local_of(&srs.rewrite(Some("a@elsewhere.test"), 105).unwrap());
        assert_eq!(
            srs.verify(&later, 100),
            Err(Refusal::Expired),
            "five days in the future is a broken clock, not skew"
        );
    }

    #[test]
    fn day_1023_wraps() {
        let srs = srs();
        let wrapped = local_of(&srs.rewrite(Some("a@elsewhere.test"), 1023).unwrap());

        assert!(srs.verify(&wrapped, 2).is_ok(), "three days old");
        assert_eq!(
            srs.verify(&wrapped, 1023 + DEFAULT_MAX_AGE_DAYS + 1),
            Err(Refusal::Expired),
            "and still expires on the other side of the wrap"
        );
    }

    #[test]
    fn the_null_sender_is_not_rewritten() {
        assert_eq!(srs().rewrite(None, 100), None);
    }

    #[test]
    fn our_own_srs_address_is_not_wrapped_again() {
        let srs = srs();
        let once = srs.rewrite(Some("a@elsewhere.test"), 100).unwrap();

        assert_eq!(
            srs.rewrite(Some(&once), 100),
            None,
            "a wrapper per hop grows the local part until it is not an address"
        );
        assert_eq!(
            srs.rewrite(Some(&once.to_ascii_uppercase()), 100),
            None,
            "SMTP domains are case insensitive, and so is this test"
        );
    }

    #[test]
    fn a_secret_file_keeps_its_line_order_and_refuses_a_short_key() {
        let two = format!("{}\n\n{}\n", "a".repeat(32), "b".repeat(32));
        assert_eq!(
            Srs::keys_from(&two).unwrap(),
            vec!["a".repeat(32).into_bytes(), "b".repeat(32).into_bytes()],
            "the first line signs, so the order is load bearing"
        );

        assert_eq!(Srs::keys_from("\n  \n"), Err(SecretError::Empty));
        assert_eq!(
            Srs::keys_from("short"),
            Err(SecretError::TooShort { line: 1, len: 5 })
        );
    }

    #[test]
    fn the_mac_is_too_long_to_guess_at_any_rate_this_host_can_answer() {
        let srs = srs();
        let wrapped = local_of(&srs.rewrite(Some("a@elsewhere.test"), 100).unwrap());
        let mac = wrapped.split('=').nth(1).expect("a MAC");

        assert!(
            mac.len() >= 8,
            "{} characters of base64 is about {} bits against a case-insensitive \
             comparison, and a sweep of that costs an attacker minutes: {wrapped}",
            mac.len(),
            (mac.len() as f64 * 38f64.log2()).round() as u32
        );
        assert_ne!(
            &mac[..4],
            &mac[4..8],
            "the second half of the MAC has to be a second word of the digest, \
             not the first one printed twice: {wrapped}"
        );
    }

    #[test]
    fn a_local_part_that_is_not_ours_at_all_is_refused() {
        let srs = srs();
        for not_ours in ["postmaster", "SRS0=a=b", "SRS1=aaaa=AA=x.test=y"] {
            assert_eq!(
                srs.verify(not_ours, 100),
                Err(Refusal::NotSrs),
                "{not_ours} is not in the shape we write"
            );
        }
    }

    #[test]
    fn an_original_local_part_containing_an_equals_sign_survives() {
        let srs = srs();
        let wrapped = srs.rewrite(Some("odd=name@elsewhere.test"), 100).unwrap();

        assert_eq!(
            srs.verify(&local_of(&wrapped), 100).unwrap().to_string(),
            "odd=name@elsewhere.test"
        );
    }
}
