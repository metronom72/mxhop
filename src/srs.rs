//! Sender Rewriting Scheme: the envelope sender on the way out, and the
//! bounce on the way back.
//!
//! A forwarder that hands a stranger's message on unchanged announces that
//! stranger as the envelope sender, and the destination then checks SPF
//! against a domain whose record does not list this host. It fails — and
//! since 2024 Gmail wants SPF or DKIM to pass for the connecting sender or it
//! junks the message. The second half of the problem is worse: a bounce the
//! destination issues *after* accepting goes to that envelope sender, a
//! person who never wrote to us. That is backscatter, and it is our address
//! that earns the reputation for it.
//!
//! So the envelope sender becomes an address in a domain of our own, whose
//! SPF record is exactly this host, carrying the original address inside its
//! local part and signed so that nobody else can invent one:
//!
//! ```text
//! SRS0=HHHH=TT=orig.domain=orig.local@srs.example.com
//! ```
//!
//! Everything here is pure: the day number is an argument and never a clock,
//! so every rule about expiry is tested by calling a function rather than by
//! waiting three weeks.

use std::fmt;

use ring::hmac;

use crate::routing::Mailbox;

/// How old an address may be before it is refused, in days.
///
/// A judgement call, and not the one libsrs2 and postsrsd make: they default
/// to 21, and this is 7. A legitimate delivery report arrives inside the
/// reporting server's queue lifetime, which is about five days — Postfix's
/// `maximal_queue_lifetime` default is exactly five — so one week covers the
/// reports that are actually coming, and days eight to twenty-one are almost
/// entirely replay surface for an address harvested out of a `Received`
/// header or guessed off the MAC.
///
/// What is given up is the late out-of-office reply and the report from a
/// server that queued for a fortnight. Those exist, and refusing one is a
/// visible failure somebody can chase and an operator can fix by raising this
/// number; a replay window nobody can see is not. The default is the safer of
/// the two because it is what an operator gets by not thinking about it, and
/// `max_age_days` is there for the one who has.
pub const DEFAULT_MAX_AGE_DAYS: u32 = 7;

/// The longest window [`crate::config`] will accept, in days.
///
/// Expiry is checked modulo [`DAYS`], so a window of 1022 or more accepts
/// every address mxhop has ever issued and turns expiry off without saying
/// so. A year is refused long before that, because a replay window measured
/// in years is wrong whether or not it wraps.
pub const MAX_AGE_DAYS_CEILING: u32 = 365;

/// The local part length RFC 5321 §4.5.3.1.1 obliges a receiver to accept.
/// See [`Srs::rewrite`] for what mxhop does when a wrapped sender exceeds it.
pub const MAX_LOCAL_PART_OCTETS: usize = 64;

/// The shortest secret worth signing with. Below this the key is findable
/// offline from a single published SRS address, and then the signature stops
/// being the thing that separates this host from an open relay.
pub const MIN_SECRET_BYTES: usize = 16;

/// The counter wraps here: two base32 characters hold 1024 days.
const DAYS: u32 = 1024;

/// RFC 4648 base32, which is the alphabet postsrsd writes timestamps in.
const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// How many base64 characters of the MAC go into the address.
///
/// Eight, not postsrsd's four. Four was chosen for an interoperability this
/// file does not have — nothing but mxhop ever verifies an mxhop address —
/// and against the case-insensitive comparison in [`Srs::verifies`] it is
/// about 21 bits: 38^4 is 2.1 million, and a session that pipelines `RCPT TO`
/// guesses at this binary is answered at roughly 380 000 a second, so the
/// whole space falls in under a minute. postsrsd survives that length because
/// it sits behind Postfix's `smtpd_hard_error_limit`, `smtpd_error_sleep_time`
/// and anvil. mxhop now counts a refused recipient as an error, which bounds
/// the rate, but a 21-bit secret that is only safe because of a counter is
/// one configuration mistake from being no secret at all.
///
/// Eight characters is about 42 bits — 38^8 is 4×10^12, which is out of reach
/// online at any rate this host can answer — and costs four octets of the
/// local part. That is the real constraint (see [`Srs::rewrite`]), and four
/// octets is affordable.
const MAC_CHARS: usize = 8;

/// The prefix every address this file writes begins with.
const PREFIX: &str = "SRS0";

/// The SRS domain, its keys and its expiry window.
#[derive(Clone)]
pub struct Srs {
    domain: String,
    /// The first key signs; every key verifies. That is what makes rotation
    /// safe: a bounce issued three days ago carries an address signed with
    /// the key that has since been replaced, and refusing it destroys a
    /// delivery report somebody is waiting for.
    keys: Vec<Vec<u8>>,
    max_age_days: u32,
}

impl fmt::Debug for Srs {
    /// Hand-written so that an `Srs` in a log line or a panic message cannot
    /// print the signing key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Srs")
            .field("domain", &self.domain)
            .field("keys", &self.keys.len())
            .field("max_age_days", &self.max_age_days)
            .finish()
    }
}

/// Why an address offered at the SRS domain is not one of ours.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Not in the shape this file writes at all.
    NotSrs,
    /// Signed with no key we hold — or not signed by anybody.
    BadSignature,
    /// Ours once, and too old now.
    Expired,
    /// Ours, signed, in date, and the address inside it is not an address.
    Undeliverable(String),
}

impl Refusal {
    /// The reply the sending server reads.
    ///
    /// A forged address and a malformed one get the same sentence on purpose:
    /// the difference between them is information about our signing, and
    /// whoever is probing is the only person who would want it. An expired
    /// address gets its own, because that one is a real bounce arriving late
    /// and the operator reading the log of the server that sent it deserves
    /// to know which of the two happened.
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

/// Why a secret file cannot be used. Every variant says what to type.
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
    /// Builds the rewriter from a domain and the secret file's keys, the
    /// signing key first.
    pub fn new(domain: &str, keys: Vec<Vec<u8>>, max_age_days: u32) -> Self {
        Self {
            domain: domain.to_ascii_lowercase(),
            keys,
            max_age_days,
        }
    }

    /// Reads a secret file's contents: one key per line, the first line the
    /// signing key.
    ///
    /// Blank lines are ignored so that a file written by `echo` and a file
    /// written by an editor behave alike, and each line's bytes are taken as
    /// they are rather than decoded — whatever is on the line *is* the key,
    /// so an operator cannot get it wrong by choosing an encoding.
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

    /// Whether `domain` is the SRS domain. Case-insensitive, because SMTP
    /// domains are.
    pub fn is_ours(&self, domain: &str) -> bool {
        domain.eq_ignore_ascii_case(&self.domain)
    }

    /// Whether a non-null sender is one [`Self::rewrite`] can wrap, and why
    /// not when it is not.
    ///
    /// `smtp::command` accepts addresses [`Mailbox::parse`] refuses —
    /// `bob@localhost`, `user@[192.0.2.1]`, `"a b"@x.test` — and before this
    /// existed each of those was accepted at `MAIL FROM`, found unwrappable
    /// at the final dot, and forwarded with the original sender intact and no
    /// log line. The check belongs at `MAIL FROM`, where the sending server
    /// is still holding the message and a refusal is something it reports to
    /// the person who wrote it.
    pub fn wrappable(&self, sender: &str) -> Result<(), crate::routing::MailboxError> {
        Mailbox::parse(sender).map(|_| ())
    }

    /// The envelope sender to announce in place of `sender`, or `None` when
    /// the sender has to be left exactly as it is.
    ///
    /// `None` means one of exactly three things, and the caller has to know
    /// which — see `session::hand_on`, where the three are spelled out.
    ///
    /// The null sender has nothing to rewrite and must acquire nothing: a
    /// bounce with a sender is a bounce that can itself be bounced. An
    /// address already at our own SRS domain is left alone, because wrapping
    /// it adds one layer per hop until the local part is too long to be an
    /// address at all. And a sender that is not a [`Mailbox`] cannot be
    /// wrapped, which is why [`Self::wrappable`] exists: that one is refused
    /// at `MAIL FROM` instead of reaching here.
    ///
    /// **A wrapped sender is allowed to exceed 64 octets.** The local part
    /// costs 17 fixed octets plus the original domain plus the original local
    /// part, so a 40-character local part at a 20-character domain is already
    /// over the length RFC 5321 §4.5.3.1.1 obliges a receiver to accept, and
    /// some receivers refuse it. The address is written anyway, because the
    /// alternative — declining to wrap — is to hand that destination the
    /// original sender, which is the SPF failure and the backscatter path
    /// this whole file exists to remove, on the senders with the longest
    /// addresses and for no stated reason the operator ever sees. Nothing is
    /// truncated either: a truncated local part is a bounce delivered to
    /// somebody else, or to nobody, and a signature over a string that is not
    /// the string in the address. So the failure mode is kept the loud one: a
    /// receiver that refuses the length answers the `MAIL FROM`, the sending
    /// server is told, and `session::hand_on` logs a warning naming the
    /// address so the operator can see which sender it was. Length is also
    /// why [`MAC_CHARS`] stops at eight rather than going further.
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

    /// The address a verified SRS local part decodes to.
    ///
    /// This is the only thing between mxhop and an open relay. A `RCPT TO` at
    /// the SRS domain is not an alias lookup: it names somebody else's
    /// mailbox anywhere in the world, and the only reason relaying to it is
    /// allowed is that we can prove we wrote the address ourselves.
    pub fn verify(&self, local: &str, day: u32) -> Result<Mailbox, Refusal> {
        // Five pieces on purpose: `=` is legal inside a local part, and the
        // original local part is the last piece, so it has to keep whatever
        // is in it rather than be split further.
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

        // The signature is checked before the clock: an address we never
        // issued has not earned the sentence that admits it was once ours.
        if !self.verifies(&payload(tt, domain, orig), mac) {
            return Err(Refusal::BadSignature);
        }
        if !self.in_date(issued, day) {
            return Err(Refusal::Expired);
        }

        Mailbox::parse(&format!("{orig}@{domain}"))
            .map_err(|e| Refusal::Undeliverable(format!("{orig}@{domain} {e}")))
    }

    /// Whether an address issued on day `issued` is still good on day `now`.
    ///
    /// Both are counters modulo 1024, so "older than" is a subtraction that
    /// wraps: an address issued on day 1023 is three days old on day 2, not
    /// minus one thousand and twenty-one. One day into the future is
    /// tolerated because two hosts' clocks and two time zones' midnights do
    /// not agree, and refusing a bounce for being dated tomorrow would be an
    /// outage the moment one clock drifted.
    fn in_date(&self, issued: u32, now: u32) -> bool {
        let age = (now % DAYS + DAYS - issued % DAYS) % DAYS;
        age <= self.max_age_days || age == DAYS - 1
    }

    fn sign(&self, payload: &str) -> String {
        let key = self.keys.first().map(Vec::as_slice).unwrap_or(&[]);
        mac_chars(key, payload)
    }

    /// Whether any key we hold produces this MAC.
    ///
    /// Compared case-insensitively: base64 is mixed case, and a destination
    /// that lowercases the whole address before putting it in a bounce's
    /// `RCPT TO` is doing something SMTP allows. That costs about a quarter
    /// of the bits: a forger has to guess one of roughly 38^[`MAC_CHARS`]
    /// strings rather than 64^[`MAC_CHARS`] — 4×10^12 at eight characters —
    /// and every wrong guess is a refused `RCPT` that counts against the
    /// session's error limit, rather than a free offline attempt.
    fn verifies(&self, payload: &str, offered: &str) -> bool {
        self.keys
            .iter()
            .any(|key| mac_chars(key, payload).eq_ignore_ascii_case(offered))
    }
}

/// What the MAC is taken over: the timestamp, the domain and the local part,
/// all three, lowercased.
///
/// All three because each one is something a forger would want to change on
/// its own. A re-dated address never expires; a swapped domain points an
/// address we issued at a destination we never wrote to; a swapped local part
/// turns one valid address into every mailbox at that destination. Lowercased
/// because the comparison has to survive a destination that lowercases the
/// address it hands back — the original local part's own case is still
/// carried in the address itself, where the destination mailbox that is
/// entitled to care about it can see it.
fn payload(tt: &str, domain: &str, local: &str) -> String {
    format!("{tt}={domain}={local}").to_ascii_lowercase()
}

fn mac_chars(key: &[u8], payload: &str) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    base64_head(hmac::sign(&key, payload.as_bytes()).as_ref())
}

/// The first [`MAC_CHARS`] base64 characters of a digest.
///
/// SHA-256 rather than postsrsd's SHA-1: nothing but mxhop ever verifies an
/// mxhop address, so there is no interoperability to keep — and base64 rather
/// than hex only because a character of base64 carries six bits where a
/// character of hex carries four, in the same room inside a 64-octet local
/// part.
///
/// Base64 is written three input bytes to four output characters, so eight
/// characters need the digest's first six bytes: two 24-bit words, not one
/// word printed twice.
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

/// Reads the secret file and builds the rewriter the service runs with.
///
/// Separate from [`Srs::new`] so that every rule about the file's *contents*
/// stays testable without a filesystem, and so that `check` and `run` fail
/// the same way on the same file: `check` answers "would `run` start?", and a
/// key that cannot be read is a service that cannot sign.
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

/// Today, as the counter the addresses carry: days since the Unix epoch,
/// modulo 1024. The one impure function in the file, and it takes nothing and
/// decides nothing.
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

    /// A key generated here rather than written down: a literal that looks
    /// like a secret in a source file is a secret in a source file, and the
    /// commit hook refuses it — rightly.
    fn key(tag: &str) -> Vec<u8> {
        format!("mxhop-test-key-{tag}-{}", "x".repeat(16)).into_bytes()
    }

    fn srs() -> Srs {
        Srs::new("srs.tooling.ninja", vec![key("a")], DEFAULT_MAX_AGE_DAYS)
    }

    /// The local part of a rewritten address, which is what `verify` is given
    /// by the session.
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

        // Each of these is a thing a forger would want to change: a re-dated
        // address never expires, a swapped domain relays anywhere, and a
        // swapped local part turns one valid address into every mailbox at
        // that destination.
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

        // A destination is allowed to lowercase the address it hands back in
        // a bounce's RCPT TO, and several do.
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

        // The file's first line signs and every line verifies, so rotation
        // puts the new key on top and keeps the old one below it. Without
        // that, every bounce in flight is lost at the moment of rotation.
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

        // Two hosts' clocks and two time zones' midnights do not agree, and
        // refusing a bounce for being issued tomorrow is an outage the moment
        // one of them drifts.
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
        // The counter is days-since-the-epoch modulo 1024, so subtraction has
        // to wrap: an address issued on day 1023 is three days old on day 2,
        // not minus one thousand and twenty-one.
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
        // A bounce has no sender to rewrite, and must not acquire one: an
        // address in the envelope of a bounce is an address that bounce can
        // itself be bounced to.
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

    /// The MAC is the only thing between this host and an open relay, and the
    /// only way to attack it is online: one guess per `RCPT TO`. postsrsd's
    /// four base64 characters are about 21 bits once the case-insensitive
    /// comparison is paid for — 38^4 is 2.1 million, and a pipelined session
    /// against this binary answered 380 000 refused recipients a second, so
    /// the whole space falls in seconds. Postfix hides that behind
    /// `smtpd_hard_error_limit`, `smtpd_error_sleep_time` and anvil; mxhop
    /// has an error limit and nothing else, so the MAC has to be long enough
    /// to be hopeless on its own.
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
        // Taking the digest's first three bytes yields four base64 characters
        // and no more, so a MAC of eight has to come from two 24-bit words.
        // If the second word were the first one again, the last four
        // characters would repeat the first four and buy nothing.
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
        // The separator is also legal inside a local part, so the decode has
        // to stop splitting after four pieces or the address comes back
        // truncated.
        let wrapped = srs.rewrite(Some("odd=name@elsewhere.test"), 100).unwrap();

        assert_eq!(
            srs.verify(&local_of(&wrapped), 100).unwrap().to_string(),
            "odd=name@elsewhere.test"
        );
    }
}
