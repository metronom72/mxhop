//! What the message's own domains say about it: SPF, DKIM, DMARC.
//!
//! The split in this file is deliberate and is the same one `policy.rs` makes.
//! [`Auth`] is a verdict and nothing else — a plain value with no resolver, no
//! clock and no borrow of anything from `mail-auth` — so the decision table in
//! [`crate::policy::decide`] stays a pure function a test can call with a
//! literal, and so `policy.rs` gains no dependency on a crypto crate. The
//! adapter that talks to DNS is [`Verifier`], at the bottom, and it is the
//! only thing here that can block.
//!
//! Why any of it runs at all: after SRS every message mxhop forwards passes
//! SPF at the destination, because the envelope sender is at a domain whose
//! SPF record is exactly this host. That is the point of SRS, and it is also
//! the hole — a forged `From: service@paypal.com` arriving here is handed to
//! Gmail with a clean envelope and our address on it, and Gmail's refusal is
//! counted against *our* reputation every time. With two destinations it is
//! worse than a refusal: the lax one accepts, we answer 250, and Gmail's
//! refusal becomes a lost copy with nobody to report it to. The domain owner
//! already asked every receiver to reject that message. The one moment the
//! refusal costs nobody anything is while the sending server still holds it,
//! which is end-of-DATA.
//!
//! Authentication is identity, not intent: none of this says anything about a
//! correctly signed message from a throwaway domain. Content filtering stays
//! out of a forwarder.

use std::fmt::Write as _;
use std::net::IpAddr;

use crate::policy::{is_safe_address, name_or_unknown};
use crate::routing::is_qualified;

/// How long every lookup this file makes may take, all together.
///
/// Twenty seconds because that is RFC 7208 §4.6.4's own ceiling for one SPF
/// evaluation, and because the sending server is holding its connection open
/// on the final dot while this happens. It is charged against the session's
/// relay budget rather than added to it: see [`crate::smtp::session`].
pub const AUTH_BUDGET: std::time::Duration = std::time::Duration::from_secs(20);

/// An SPF result (RFC 7208 §2.6), as this file's own enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Spf {
    /// No record, or a domain that is not a name.
    #[default]
    None,
    Pass,
    /// `-all` matched: the domain says this host is not allowed to send for
    /// it.
    Fail,
    /// `~all` matched, which means "do not reject".
    SoftFail,
    Neutral,
    /// DNS did not answer.
    TempError,
    /// A record that could not be read, or a lookup limit reached.
    PermError,
}

impl Spf {
    fn word(self) -> &'static str {
        match self {
            Spf::None => "none",
            Spf::Pass => "pass",
            Spf::Fail => "fail",
            Spf::SoftFail => "softfail",
            Spf::Neutral => "neutral",
            Spf::TempError => "temperror",
            Spf::PermError => "permerror",
        }
    }
}

/// One DKIM signature's result (RFC 6376).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DkimVerdict {
    Pass,
    /// The cryptographic check failed.
    Fail,
    /// The signature could not be evaluated at all — malformed, expired, an
    /// unsupported algorithm, a body hash that does not match.
    Neutral,
    TempError,
    PermError,
}

impl DkimVerdict {
    fn word(self) -> &'static str {
        match self {
            DkimVerdict::Pass => "pass",
            DkimVerdict::Fail => "fail",
            DkimVerdict::Neutral => "neutral",
            DkimVerdict::TempError => "temperror",
            DkimVerdict::PermError => "permerror",
        }
    }
}

/// What one `DKIM-Signature` header turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dkim {
    /// The `d=` signing domain.
    pub domain: String,
    /// The `s=` selector.
    pub selector: String,
    /// The first eight base64 characters of `b=`, which is how RFC 8601 §2.7.1
    /// names one signature among several without copying the whole of it.
    pub b8: String,
    pub result: DkimVerdict,
}

/// A DMARC result (RFC 7489 §4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DmarcVerdict {
    /// DMARC does not apply: no usable `From` domain, or no record.
    #[default]
    None,
    Pass,
    /// Neither an aligned SPF pass nor an aligned DKIM pass.
    Fail,
    /// A lookup that could have produced either answer did not come back.
    TempError,
    /// RFC 7489 §6.6.3: treated as if no record were published.
    PermError,
}

impl DmarcVerdict {
    fn word(self) -> &'static str {
        match self {
            DmarcVerdict::None => "none",
            DmarcVerdict::Pass => "pass",
            DmarcVerdict::Fail => "fail",
            DmarcVerdict::TempError => "temperror",
            DmarcVerdict::PermError => "permerror",
        }
    }
}

/// The `p=` (or `sp=`/`np=`) the published record asks for, after `t=y` has
/// lowered it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// Monitoring only.
    None,
    Quarantine,
    Reject,
}

impl Policy {
    fn word(self) -> &'static str {
        match self {
            Policy::None => "none",
            Policy::Quarantine => "quarantine",
            Policy::Reject => "reject",
        }
    }
}

/// The DMARC half of the verdict.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Dmarc {
    /// The `From:` header's domain, which is the identity DMARC is about.
    pub from_domain: String,
    pub result: DmarcVerdict,
    /// The effective policy of the record that was applied, or `None` when no
    /// record was applied at all.
    ///
    /// The distinction carries the whole of the temporary-failure rule, so it
    /// is a separate field rather than a `Policy::None`: "the domain publishes
    /// `p=none`" and "we never found out what the domain publishes" are
    /// opposite answers, and only the second one is a reason to defer.
    pub policy: Option<Policy>,
}

/// Everything the message's own domains said, and nothing else.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Auth {
    /// SPF for the `MAIL FROM` identity — the original envelope sender, before
    /// SRS rewriting: here mxhop is the receiver, not the sender.
    pub spf_mail: Spf,
    /// SPF for the HELO identity, which is checked separately so that the
    /// header can report both. RFC 7208 §2.3 allows either.
    pub spf_helo: Spf,
    /// The envelope sender the `spf_mail` result belongs to, as it arrived.
    /// Carried here so that the header is a function of the verdict alone and
    /// not of the session as well.
    pub mail_from: Option<String>,
    /// The HELO name the `spf_helo` result belongs to. A claim, and printed as
    /// one: see [`Auth::header`].
    pub helo: Option<String>,
    /// One entry per `DKIM-Signature` header, in the order they appeared.
    pub dkim: Vec<Dkim>,
    pub dmarc: Dmarc,
    /// Whether any of this was looked up. `false` is what `enabled = false`
    /// produces, and it is the one state in which no header is written and
    /// nothing can be refused.
    pub checked: bool,
}

impl Auth {
    /// The verdict when the check is switched off.
    ///
    /// Every field is at its default, which is `none` throughout — not
    /// `temperror`. A disabled check has not failed to find anything out; it
    /// was never asked, and `checked` is what says so.
    pub fn not_checked() -> Self {
        Self::default()
    }

    /// The verdict when nothing answered in time.
    ///
    /// Everything is `temperror`, which is the honest report: nothing was
    /// found out, and saying so is not the same as saying a domain published
    /// nothing. `policy` is `None`, which after the narrowing in
    /// [`crate::policy`] means this forwards with `dmarc=temperror` in the
    /// header rather than deferring — see the comment on that arm for why an
    /// expired clock of ours must not cost somebody else their mail.
    ///
    /// The `From` domain is read out of the body rather than taken from the
    /// envelope sender. They are routinely different — forwarded mail and
    /// mailing lists are nothing but that — and the DMARC identity is the
    /// `From` header's, so a header reading
    /// `dmarc=temperror header.from=<the MAIL FROM domain>` was a statement
    /// about an identity nothing had examined. `AuthenticatedMessage::parse`
    /// is pure and costs no lookups, so there is no reason to guess; when it
    /// cannot read a single `From` domain the field is left empty, and
    /// [`Auth::header`] then omits `header.from` altogether instead of
    /// naming the wrong thing.
    pub fn timed_out(mail_from: Option<&str>, helo: &str, body: &[u8]) -> Self {
        let from_domain = mail_auth::AuthenticatedMessage::parse(body)
            .map(|message| {
                let mut domains: Vec<String> = message
                    .from_addresses()
                    .iter()
                    .filter_map(|from| from.rsplit_once('@').map(|(_, d)| d.to_ascii_lowercase()))
                    .collect();
                domains.sort();
                domains.dedup();
                // Zero or several `From` domains have no single DMARC
                // identity, exactly as in `Verifier::check` — and picking one
                // of two would be the same wrong claim in a new place.
                match domains.len() {
                    1 => domains.remove(0),
                    _ => String::new(),
                }
            })
            .unwrap_or_default();

        Self {
            spf_mail: Spf::TempError,
            spf_helo: Spf::TempError,
            mail_from: mail_from.map(ToString::to_string),
            helo: Some(helo.to_string()),
            dkim: Vec::new(),
            dmarc: Dmarc {
                from_domain,
                result: DmarcVerdict::TempError,
                policy: None,
            },
            checked: true,
        }
    }

    /// The `Authentication-Results` header, CRLF-terminated and folded, ready
    /// to go in front of the stored message.
    ///
    /// Written here rather than with `mail-auth`'s own builder, for three
    /// reasons. It is then a pure function of the verdict, which is what makes
    /// the header testable without a resolver. It can say `dkim=none`, where
    /// the builder emits nothing at all for an unsigned message — and silence
    /// is the one thing a header like this must not do, because a reader
    /// cannot tell it from a check that was never run. And it sanitises
    /// exactly the way [`crate::policy::Trace::header`] does: every value is
    /// domain-shaped or dropped, so a CRLF typed into a HELO name cannot end
    /// this header and start an `Authentication-Results` of the client's own.
    ///
    /// `authserv_id` is this host's name — the identity a downstream reader
    /// uses to decide whether this header is ours.
    pub fn header(&self, authserv_id: &str) -> String {
        let mut parts = vec![format!(
            "Authentication-Results: {}",
            name_or_unknown(Some(authserv_id))
        )];

        let mut spf = format!("spf={}", self.spf_mail.word());
        if let Some(address) = &self.mail_from_property() {
            let _ = write!(spf, " smtp.mailfrom={address}");
        }
        parts.push(spf);

        let mut helo = format!("spf={}", self.spf_helo.word());
        if let Some(name) = &self.helo_property() {
            let _ = write!(helo, " smtp.helo={name}");
        }
        parts.push(helo);

        if self.dkim.is_empty() {
            parts.push("dkim=none".to_string());
        } else {
            for signature in &self.dkim {
                let mut line = format!("dkim={}", signature.result.word());
                if is_qualified(&signature.domain) {
                    let _ = write!(line, " header.d={}", signature.domain);
                }
                if is_token(&signature.selector) {
                    let _ = write!(line, " header.s={}", signature.selector);
                }
                if is_base64(&signature.b8) && !signature.b8.is_empty() {
                    let _ = write!(line, " header.b={}", signature.b8);
                }
                parts.push(line);
            }
        }

        let mut dmarc = format!("dmarc={}", self.dmarc.result.word());
        if let Some(policy) = self.dmarc.policy {
            // Both forms on purpose. The parenthesised one is a comment a
            // human reads in "Show original"; `policy.dmarc` is the RFC 8601
            // §2.3 property a downstream filter can act on, and the whole
            // reason a quarantine failure is forwarded rather than refused is
            // that the destination has a spam folder and mxhop does not.
            let _ = write!(dmarc, " ({}) policy.dmarc={}", policy.word(), policy.word());
        }
        if is_qualified(&self.dmarc.from_domain) {
            let _ = write!(dmarc, " header.from={}", self.dmarc.from_domain);
        }
        parts.push(dmarc);

        // The `;` separates properties and belongs at the end of every clause
        // but the last, wherever the folding put it.
        let last = parts.len() - 1;
        for part in &mut parts[..last] {
            part.push(';');
        }

        let mut header = parts.join("\r\n        ");
        header.push_str("\r\n");
        header
    }

    /// The `smtp.mailfrom` value, when there is one fit to print.
    fn mail_from_property(&self) -> Option<String> {
        let address = self.mail_from.as_deref()?;
        is_safe_address(address).then(|| address.to_string())
    }

    fn helo_property(&self) -> Option<String> {
        let helo = self.helo.as_deref()?;
        is_qualified(helo).then(|| helo.to_string())
    }
}

/// Whether a string is safe to write as a `header.s` value: a DKIM selector is
/// whatever the signer put in the header, so it is printed only when it is
/// made of the characters a selector is allowed to be made of.
fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

fn is_base64(s: &str) -> bool {
    s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

// ------------------------------------------------- RFC 8601 §5: ours only

/// The name whose forged copies are spliced out of an arriving message.
const HEADER_NAME: &[u8] = b"authentication-results";

/// Removes every `Authentication-Results` header in the first header block
/// whose authserv-id is ours, and returns the message without them.
///
/// `None` means nothing matched, so the caller keeps the bytes it already has
/// rather than paying for a copy of a 25 MiB message to change nothing.
///
/// RFC 8601 §5 requires this, and it is the one place in mxhop where the bytes
/// of a message change. That is worth stating plainly: it is the deletion of
/// one header, not a re-encoding — nothing else is touched, nothing is
/// rewrapped, and a DKIM signature that covered a forged header of ours
/// deserves to break. Without it a sender simply writes
/// `Authentication-Results: mx.tooling.ninja; dmarc=pass header.from=paypal.com`
/// into its own message, and neither the destination nor a future ARC seal of
/// ours can tell that header from the one we are about to write.
///
/// Only *our* authserv-id is removed. Another host's results are somebody
/// else's record of a hop that really happened, and deleting them would throw
/// away the evidence a human reads when mail goes wrong.
pub fn strip_forged_results(message: &[u8], authserv_id: &str) -> Option<Vec<u8>> {
    let authserv_id = authserv_id.trim().to_ascii_lowercase();
    let mut cuts: Vec<std::ops::Range<usize>> = Vec::new();

    for (range, header) in headers_of(message) {
        let lowered = header.to_ascii_lowercase();
        if !lowered.as_bytes().starts_with(HEADER_NAME) {
            continue;
        }
        // RFC 5322 §4.5.8 (obsolete syntax) allows whitespace between a field
        // name and its colon, and lenient parsers downstream accept it. So
        // `Authentication-Results : mx.tooling.ninja;` has to be matched too:
        // a strip that insisted on the strict spelling would leave behind a
        // header that those parsers still read as ours.
        let rest = header[HEADER_NAME.len()..].trim_start_matches([' ', '\t']);
        let Some(value) = rest.strip_prefix(':') else {
            continue;
        };
        if claims(value, &authserv_id) {
            cuts.push(range);
        }
    }

    if cuts.is_empty() {
        return None;
    }

    let mut out = Vec::with_capacity(message.len());
    let mut at = 0;
    for cut in cuts {
        out.extend_from_slice(&message[at..cut.start]);
        at = cut.end;
    }
    out.extend_from_slice(&message[at..]);
    Some(out)
}

/// Whether an unfolded `Authentication-Results` value claims `authserv_id`.
///
/// The authserv-id is the first token of the value (RFC 8601 §2.2), and the
/// comparison is case-insensitive because a domain name is. The token ends at
/// whitespace, at the `;` that begins the first result, or at a `(` — a header
/// whose id is written `mx.tooling.ninja;dkim=pass` or `mx.tooling.ninja(x)`
/// is the same claim and has to be caught too.
///
/// RFC 8601 §2.2 writes the value as `[CFWS] authserv-id`, and RFC 5322 CFWS
/// includes parenthesised comments. So `(x) mx.tooling.ninja; dmarc=pass` is a
/// *valid* header claiming this host whose first token is not this host's
/// name, and a token taken before comments are dropped does not match it. The
/// header then survives the strip, and the planned ARC seal — or any filter
/// that trusts headers under our name — reads the sender's own claim as our
/// finding. Dropping comments first is what closes that, and it must not go
/// the other way: a comment that merely *contains* our name
/// (`(mx.tooling.ninja) other.example`) belongs to somebody else's header,
/// which is not ours to delete.
fn claims(value: &str, authserv_id: &str) -> bool {
    let mut rest = value;
    loop {
        rest = rest.trim_start_matches([' ', '\t']);
        match rest.strip_prefix('(') {
            Some(after) => rest = skip_comment(after),
            None => break,
        }
    }

    let token = rest.split([' ', '\t', ';', '(']).next().unwrap_or("");
    token.eq_ignore_ascii_case(authserv_id)
}

/// What follows the `)` matching a comment whose opening `(` has already been
/// consumed.
///
/// Comments nest and a backslash quotes the character after it (RFC 5322
/// §3.2.1–3.2.2), and neither can be skipped over naively: scanning to the
/// first `)` would leave `((x)) mx.tooling.ninja` sitting behind a stray `)`
/// and the claim unseen. An unterminated comment runs to the end of the
/// value, which leaves no token at all — nothing is claimed, so nothing is
/// cut, which is the safe direction for a malformed header.
fn skip_comment(mut rest: &str) -> &str {
    let mut depth = 1usize;
    while let Some(c) = rest.chars().next() {
        rest = &rest[c.len_utf8()..];
        match c {
            '\\' => {
                if let Some(quoted) = rest.chars().next() {
                    rest = &rest[quoted.len_utf8()..];
                }
            }
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return rest;
                }
            }
            _ => {}
        }
    }
    rest
}

/// Each header of the first block, as the byte range it occupies and its
/// unfolded text.
///
/// `policy::Head::scan` reads the same block but needs only the text, so its
/// iterator yields strings and throws the offsets away. This one keeps them,
/// because a header cannot be spliced out of a message without knowing where
/// it starts and stops — including its folded continuations and its own line
/// ending, or the splice leaves a stray line in the middle of the header block.
fn headers_of(message: &[u8]) -> Vec<(std::ops::Range<usize>, String)> {
    let mut found = Vec::new();
    let mut at = 0usize;

    while at < message.len() {
        let start = at;
        let mut text = String::new();
        loop {
            let line_end = message[at..]
                .iter()
                .position(|b| *b == b'\n')
                .map_or(message.len(), |n| at + n + 1);
            let line = &message[at..line_end];
            let bare = strip_eol(line);
            if bare.is_empty() {
                // The blank line that ends the header block. Anything below
                // it is the body: an `Authentication-Results` quoted in a
                // forwarded message somebody pasted is theirs, not a claim,
                // and splicing it would corrupt the message it is part of.
                return found;
            }
            at = line_end;
            text.push_str(&String::from_utf8_lossy(bare));
            if !matches!(message.get(at), Some(b' ' | b'\t')) {
                break;
            }
            // A fold belongs to the header above it, so it is joined rather
            // than read as a header of its own — and the range grows to cover
            // it, because half a spliced header is a syntax error.
            text.push(' ');
        }
        found.push((start..at, text));
    }

    found
}

/// One line without its terminator, whichever of the two it has. A message
/// that arrived over SMTP is CRLF-terminated, and one built in a test or read
/// off a disk may not be.
fn strip_eol(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

// --------------------------------------------- the part that talks to DNS

/// One message's worth of question: everything the checks need, and nothing
/// the session has that they do not.
///
/// The `mail_from` here is the sender **as it arrived**, before SRS rewriting.
/// For these checks mxhop is the receiver, not the sender: SPF is being
/// evaluated on somebody else's behalf, and evaluating it against our own
/// rewritten envelope would ask whether this host is allowed to send for
/// itself, which it always is.
#[derive(Debug, Clone, Copy)]
pub struct Probe<'a> {
    pub ip: IpAddr,
    pub helo: &'a str,
    pub mail_from: Option<&'a str>,
    pub body: &'a [u8],
}

/// The resolver side: `mail-auth`'s verifiers, and the conversion into
/// [`Auth`].
///
/// A second DNS client beside [`crate::dns::Hickory`], with a cache of its
/// own. That is not ideal and is not avoidable: `mail-auth` takes a resolver of
/// its own making and exposes no trait to hand it ours. The caches do not
/// overlap much in practice — delivery looks up MX and address records,
/// these look up TXT — so the duplication costs memory rather than queries.
pub struct Verifier {
    inner: mail_auth::MessageAuthenticator,
    /// This host's name, which SPF macro expansion calls the `r` macro and
    /// which becomes the header's authserv-id.
    hostname: String,
}

impl std::fmt::Debug for Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Verifier")
            .field("hostname", &self.hostname)
            .finish_non_exhaustive()
    }
}

impl Verifier {
    /// Builds one from the system's own resolver configuration, for the same
    /// reason [`crate::dns::Hickory::from_system`] does: a forwarder that
    /// invented its own resolver list would stop agreeing with the `dig` an
    /// operator runs on the host.
    pub fn from_system(hostname: &str) -> Result<Self, String> {
        mail_auth::MessageAuthenticator::new_system_conf()
            .map(|inner| Self {
                inner,
                hostname: hostname.to_string(),
            })
            .map_err(|e| e.to_string())
    }

    /// A verifier that asks exactly one nameserver, for the tests.
    ///
    /// The mapping this file depends on most — which DNS failures become
    /// `temperror` and which become "no record" — is made inside hickory by
    /// the rcode a nameserver answers with, so a table of records cannot
    /// express the difference and only a real server can. Shaped after
    /// `dns::Hickory::against`, which exists for the same reason.
    #[cfg(test)]
    fn against(server: std::net::SocketAddr, hostname: &str) -> Self {
        use mail_auth::hickory_resolver::config::{
            ConnectionConfig, NameServerConfig, ResolverConfig, ResolverOpts,
        };

        let mut udp = ConnectionConfig::udp();
        udp.port = server.port();
        let config = ResolverConfig::from_parts(
            None,
            Vec::new(),
            vec![{
                let mut ns = NameServerConfig::udp(server.ip());
                ns.connections = vec![udp];
                ns
            }],
        );
        let mut options = ResolverOpts::default();
        // One question, one answer: no retries, no fallback to TCP and no
        // cache, so the test reads back exactly what it scripted.
        options.attempts = 0;
        options.try_tcp_on_error = false;
        options.cache_size = 0;

        Self {
            inner: mail_auth::MessageAuthenticator::new(config, options).expect("a resolver"),
            hostname: hostname.to_string(),
        }
    }

    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    /// Runs all three checks and converts the answers into an [`Auth`].
    ///
    /// There is no clock here: `mail-auth` has no timeout of its own, so the
    /// only one is the caller's `timeout(AUTH_BUDGET, …)`. That is why
    /// [`Auth::timed_out`] exists and why it reports `temperror` rather than
    /// `none` — our own expired budget is a question that was not answered,
    /// which is precisely what `temperror` means.
    pub async fn check(&self, probe: Probe<'_>) -> Auth {
        use mail_auth::dmarc::verify::DmarcParameters;
        use mail_auth::spf::verify::SpfParameters;

        let sender = probe.mail_from.unwrap_or("");
        // RFC 7208 §2.4: a null reverse-path is checked as
        // `postmaster@<helo>`, so the domain SPF — and DMARC alignment after
        // it — is about is the HELO domain.
        let mail_from_domain = sender
            .rsplit_once('@')
            .map_or(probe.helo, |(_, domain)| domain);

        // Two `check_host` runs rather than one `verify_spf`, which returns
        // whichever of the two identities it decided was interesting. Both go
        // into the header, and a reader of it needs to know which identity a
        // result belongs to: `spf=pass` is a different fact about a message
        // depending on whether it is about the envelope sender or the name the
        // client typed in HELO.
        let spf_helo = self
            .inner
            .check_host(SpfParameters::helo(probe.ip, probe.helo, &self.hostname))
            .await;
        let spf_mail = self
            .inner
            .check_host(SpfParameters::mail_from(
                probe.ip,
                probe.helo,
                &self.hostname,
                sender,
            ))
            .await;

        let mut auth = Auth {
            spf_mail: spf(spf_mail.result()),
            spf_helo: spf(spf_helo.result()),
            mail_from: probe.mail_from.map(ToString::to_string),
            helo: Some(probe.helo.to_string()),
            dkim: Vec::new(),
            dmarc: Dmarc::default(),
            checked: true,
        };

        let Some(message) = mail_auth::AuthenticatedMessage::parse(probe.body) else {
            // A message whose header block cannot be read has no `From` to
            // align against, so DMARC does not apply. `permerror` rather than
            // `none`, because "we could not read it" is a permanent fact about
            // this message and not a statement that the domain published
            // nothing — and both are forwarded, so it costs the sender
            // nothing either way.
            auth.dmarc.result = DmarcVerdict::PermError;
            return auth;
        };

        let dkim = self.inner.verify_dkim(&message).await;
        auth.dkim = dkim
            .iter()
            .filter_map(|output| {
                let signature = output.signature()?;
                Some(Dkim {
                    domain: signature.d.clone(),
                    selector: signature.s.clone(),
                    b8: base64_prefix(&signature.b),
                    result: dkim_verdict(output.result()),
                })
            })
            .collect();

        // Zero or several distinct `From` domains: there is no single identity
        // for DMARC to be about. `mail-auth` answers with a default output,
        // which is indistinguishable from "no record", so it is named here
        // instead — a `permerror`, which forwards.
        let mut domains: Vec<String> = message
            .from_addresses()
            .iter()
            .filter_map(|from| from.rsplit_once('@').map(|(_, d)| d.to_ascii_lowercase()))
            .collect();
        domains.sort();
        domains.dedup();
        if domains.len() != 1 {
            auth.dmarc.result = DmarcVerdict::PermError;
            return auth;
        }

        let dmarc = self
            .inner
            .verify_dmarc(DmarcParameters::new(
                &message,
                &dkim,
                mail_from_domain,
                &spf_mail,
            ))
            .await;

        auth.dmarc = Dmarc {
            from_domain: dmarc.domain().to_string(),
            result: dmarc_verdict(&dmarc.result()),
            // The presence of a record, not the value of `policy()`, is what
            // says whether a policy is known: with no record `policy()` is
            // `Policy::None`, which is also what a published `p=none` gives,
            // and the deferral rule turns on telling those two apart.
            policy: dmarc.record().map(|_| policy(dmarc.policy())),
        };
        auth
    }
}

fn spf(result: mail_auth::SpfResult) -> Spf {
    match result {
        mail_auth::SpfResult::Pass => Spf::Pass,
        mail_auth::SpfResult::Fail => Spf::Fail,
        mail_auth::SpfResult::SoftFail => Spf::SoftFail,
        mail_auth::SpfResult::Neutral => Spf::Neutral,
        mail_auth::SpfResult::TempError => Spf::TempError,
        mail_auth::SpfResult::PermError => Spf::PermError,
        mail_auth::SpfResult::None => Spf::None,
    }
}

fn dkim_verdict(result: &mail_auth::DkimResult) -> DkimVerdict {
    match result {
        mail_auth::DkimResult::Pass => DkimVerdict::Pass,
        mail_auth::DkimResult::Fail(_) => DkimVerdict::Fail,
        mail_auth::DkimResult::Neutral(_) => DkimVerdict::Neutral,
        mail_auth::DkimResult::TempError(_) => DkimVerdict::TempError,
        mail_auth::DkimResult::PermError(_) => DkimVerdict::PermError,
        mail_auth::DkimResult::None => DkimVerdict::Neutral,
    }
}

fn dmarc_verdict(result: &mail_auth::DmarcResult) -> DmarcVerdict {
    match result {
        mail_auth::DmarcResult::Pass => DmarcVerdict::Pass,
        mail_auth::DmarcResult::Fail(_) => DmarcVerdict::Fail,
        // `mail-auth` maps only `DnsError::Resolver` — a SERVFAIL or a timeout
        // — to a temporary error. NXDOMAIN and an empty answer are "no
        // record", and a record that will not parse is permanent. That
        // mapping is the one the deferral rule rests on, and
        // `a_servfail_on_dmarc_is_a_temperror_and_nxdomain_is_not` holds it
        // down through a real nameserver.
        mail_auth::DmarcResult::TempError(_) => DmarcVerdict::TempError,
        mail_auth::DmarcResult::PermError(_) => DmarcVerdict::PermError,
        mail_auth::DmarcResult::None => DmarcVerdict::None,
    }
}

fn policy(policy: mail_auth::dmarc::Policy) -> Policy {
    match policy {
        mail_auth::dmarc::Policy::Reject => Policy::Reject,
        mail_auth::dmarc::Policy::Quarantine => Policy::Quarantine,
        // `Unspecified` is a record with no `p=` tag at all, which RFC 7489
        // §6.3 reads as a record that requests nothing.
        mail_auth::dmarc::Policy::None | mail_auth::dmarc::Policy::Unspecified => Policy::None,
    }
}

/// The first eight base64 characters of a signature, which is how RFC 8601
/// §2.7.1 names one signature among several.
///
/// Eight characters is six octets, so no padding is ever written: the shortest
/// signature any DKIM algorithm produces is 32 octets, and a shorter `b=` than
/// that is a malformed header whose eight characters nobody will read.
/// Hand-rolled rather than pulled in with a crate, for the same reason
/// `policy::email_date` is: it is six bytes of arithmetic used in one place.
fn base64_prefix(b: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(8);
    for chunk in b.chunks(3).take(2) {
        let [a, b, c] = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let bits = (u32::from(a) << 16) | (u32::from(b) << 8) | u32::from(c);
        for shift in [18, 12, 6, 0].into_iter().take(chunk.len() + 1) {
            out.push(ALPHABET[((bits >> shift) & 0x3f) as usize] as char);
        }
    }
    out
}
#[cfg(test)]
mod tests {
    use super::*;

    fn pass() -> Auth {
        Auth {
            spf_mail: Spf::Pass,
            spf_helo: Spf::Pass,
            mail_from: Some("alice@gmail.test".into()),
            helo: Some("mail-ed1-f54.google.test".into()),
            dkim: vec![Dkim {
                domain: "gmail.test".into(),
                selector: "20230601".into(),
                b8: "AbCdEfGh".into(),
                result: DkimVerdict::Pass,
            }],
            dmarc: Dmarc {
                from_domain: "gmail.test".into(),
                result: DmarcVerdict::Pass,
                policy: Some(Policy::None),
            },
            checked: true,
        }
    }

    /// Every line of this header after the first has to begin with
    /// whitespace. It is prepended to somebody else's message, so a clause
    /// that lands in column one is not a long header — it is a new one, and
    /// every header below it has been pushed into a block that starts with
    /// something unparseable.
    #[test]
    fn the_header_is_one_folded_header_whatever_is_in_it() {
        let header = pass().header("mx.tooling.ninja");

        assert!(header.ends_with("\r\n"), "{header:?}");
        for line in header.trim_end_matches("\r\n").split("\r\n").skip(1) {
            assert!(
                line.starts_with(' ') || line.starts_with('\t'),
                "a continuation line has to be folded, not freestanding: {line:?}"
            );
        }
        assert!(
            header.starts_with("Authentication-Results: mx.tooling.ninja;"),
            "{header}"
        );
        assert!(
            header.contains("spf=pass smtp.mailfrom=alice@gmail.test;"),
            "{header}"
        );
        assert!(
            header.contains("spf=pass smtp.helo=mail-ed1-f54.google.test;"),
            "{header}"
        );
        assert!(
            header.contains("dkim=pass header.d=gmail.test header.s=20230601 header.b=AbCdEfGh;"),
            "{header}"
        );
        assert!(header.contains("dmarc=pass (none)"), "{header}");
        assert!(header.contains("header.from=gmail.test"), "{header}");
    }

    /// `mail-auth`'s own builder writes nothing at all for a message with no
    /// signatures, and a reader cannot tell that silence from a check that
    /// never ran. An unsigned message is a fact, and the header has to state
    /// it — DMARC's whole answer for a forgery rests on there being no
    /// aligned signature.
    #[test]
    fn an_unsigned_message_says_dkim_none_rather_than_nothing() {
        let header = Auth {
            dkim: Vec::new(),
            ..pass()
        }
        .header("mx.tooling.ninja");

        assert!(header.contains("dkim=none"), "{header}");
    }

    /// The one security bug this header can carry, and the same one
    /// `Trace::header` has a test for. A HELO name is whatever the client
    /// typed; copied in verbatim with a CRLF in it, it ends our header and
    /// begins an `Authentication-Results` of the client's own — which the
    /// destination then believes, because it arrived under our name.
    #[test]
    fn a_helo_with_a_newline_cannot_forge_a_result() {
        let header = Auth {
            helo: Some("evil.test\r\n        dmarc=pass header.from=paypal.test".into()),
            ..pass()
        }
        .header("mx.tooling.ninja");

        assert!(
            !header.contains("paypal.test"),
            "a crafted HELO name must not reach the header at all: {header:?}"
        );
        assert!(
            header.contains("spf=pass;"),
            "and the clause is written without the property rather than with a \
             sanitised version of it, because a reader cannot tell a cleaned-up \
             name from a real one: {header}"
        );
    }

    /// The same hole through the envelope sender, which is also the client's
    /// to choose.
    #[test]
    fn a_mail_from_with_a_newline_cannot_forge_a_result() {
        let header = Auth {
            mail_from: Some("a@b.test\r\n        dmarc=pass".into()),
            ..pass()
        }
        .header("mx.tooling.ninja");

        assert!(
            !header.contains("a@b.test"),
            "an address that cannot be written into a header is dropped whole, \
             not trimmed: {header:?}"
        );
        assert!(header.contains("spf=pass;"), "{header:?}");
    }

    /// A selector and a `b=` come out of a header the signer wrote, so they
    /// are claims too.
    #[test]
    fn a_crafted_selector_or_signature_is_dropped_from_the_header() {
        let header = Auth {
            dkim: vec![Dkim {
                domain: "gmail.test".into(),
                selector: "s\r\n        dmarc=pass".into(),
                b8: "b\r\n x".into(),
                result: DkimVerdict::Pass,
            }],
            ..pass()
        }
        .header("mx.tooling.ninja");

        assert!(
            header.contains("dkim=pass header.d=gmail.test;"),
            "the domain is printable and the two claims are not: {header:?}"
        );
    }

    /// No record and a published `p=none` are different answers, and the
    /// header must not blur them: the policy is the thing that tells a reader
    /// whether the domain has an opinion at all.
    #[test]
    fn a_domain_with_no_record_gets_no_policy_in_the_header() {
        let header = Auth {
            dmarc: Dmarc {
                from_domain: "nowhere.test".into(),
                result: DmarcVerdict::None,
                policy: None,
            },
            ..pass()
        }
        .header("mx.tooling.ninja");

        assert!(
            header.contains("dmarc=none header.from=nowhere.test"),
            "{header}"
        );
        assert!(!header.contains("policy.dmarc="), "{header}");
    }

    /// Forwarding a quarantine failure is the right call — we have no spam
    /// folder and the destination does — but only if the destination is told.
    /// Without the policy in the header it reads as an ordinary failure and
    /// the domain owner's request is lost on the way.
    #[test]
    fn a_quarantine_failure_names_the_policy_a_destination_should_apply() {
        let header = Auth {
            dmarc: Dmarc {
                from_domain: "paypal.test".into(),
                result: DmarcVerdict::Fail,
                policy: Some(Policy::Quarantine),
            },
            ..pass()
        }
        .header("mx.tooling.ninja");

        assert!(
            header.contains("dmarc=fail (quarantine) policy.dmarc=quarantine"),
            "{header}"
        );
    }

    const FORGED: &[u8] = b"Received: from a.test by mx.elsewhere.test\r\n\
        Authentication-Results: mx.tooling.ninja; dmarc=pass header.from=paypal.test\r\n\
        Subject: your account\r\n\
        \r\n\
        body\r\n";

    /// The forgery this strip exists for. A sender writes the header itself,
    /// under our name, and the destination has no way to tell it from ours —
    /// so a message that fails DMARC arrives at Gmail carrying our word that
    /// it passed.
    #[test]
    fn a_result_claiming_our_own_name_is_spliced_out() {
        let stripped = strip_forged_results(FORGED, "mx.tooling.ninja").expect("a change");

        assert_eq!(
            String::from_utf8_lossy(&stripped),
            "Received: from a.test by mx.elsewhere.test\r\n\
             Subject: your account\r\n\
             \r\n\
             body\r\n",
            "one header is removed and nothing else is touched"
        );
    }

    /// A domain name is case-insensitive, so a forgery spelled in capitals is
    /// the same forgery. Comparing the raw bytes is how it gets through.
    #[test]
    fn the_authserv_id_is_matched_without_regard_to_case() {
        let message = b"Authentication-Results: MX.Tooling.Ninja; dmarc=pass\r\n\r\nbody\r\n";

        assert_eq!(
            strip_forged_results(message, "mx.tooling.ninja"),
            Some(b"\r\nbody\r\n".to_vec())
        );
    }

    /// Every real header of this shape is folded, because it carries several
    /// results. A strip that read only the first line of a header would find
    /// the id, remove that line, and leave the rest of the forgery behind as
    /// freestanding lines that the destination reads as headers of their own.
    #[test]
    fn a_folded_forgery_is_removed_whole() {
        let message = b"Authentication-Results: mx.tooling.ninja;\r\n\
            \tspf=pass smtp.mailfrom=service@paypal.test;\r\n\
            \tdmarc=pass header.from=paypal.test\r\n\
            Subject: hi\r\n\
            \r\n\
            body\r\n";

        let stripped = strip_forged_results(message, "mx.tooling.ninja").expect("a change");

        assert_eq!(
            String::from_utf8_lossy(&stripped),
            "Subject: hi\r\n\r\nbody\r\n",
            "all three lines of one header, and only them"
        );
    }

    /// Another host's results are its record of a hop that really happened,
    /// and a reader chasing a delivery problem needs them. Removing every
    /// `Authentication-Results` header would be easier and would destroy that.
    #[test]
    fn another_hosts_results_are_left_alone() {
        let message = b"Authentication-Results: mx.elsewhere.test; dmarc=fail\r\n\r\nbody\r\n";

        assert_eq!(
            strip_forged_results(message, "mx.tooling.ninja"),
            None,
            "nothing matched, so the message is handed on as the bytes that arrived"
        );
    }

    /// A lookalike is not us. `mx.tooling.ninja.example` is somebody else's
    /// host, and a prefix comparison would delete its headers.
    #[test]
    fn a_host_whose_name_merely_begins_with_ours_is_not_us() {
        let message = b"Authentication-Results: mx.tooling.ninja.example; dmarc=pass\r\n\r\nx\r\n";

        assert_eq!(strip_forged_results(message, "mx.tooling.ninja"), None);
    }

    /// An id written with no space before the `;` is the same claim. RFC 8601
    /// allows it, and a token split on whitespace alone would miss it.
    #[test]
    fn an_authserv_id_jammed_against_the_semicolon_is_still_a_claim() {
        let message = b"Authentication-Results: mx.tooling.ninja;dmarc=pass\r\n\r\nx\r\n";

        assert_eq!(
            strip_forged_results(message, "mx.tooling.ninja"),
            Some(b"\r\nx\r\n".to_vec())
        );
    }

    /// **A budget expiry must not name an identity nobody looked at.** The
    /// DMARC identity is the `From` header's, and for forwarded mail and
    /// every mailing list it is a different domain from the envelope sender.
    /// Taking it from `MAIL FROM` put `dmarc=temperror header.from=<envelope
    /// domain>` in the header — a statement about an identity the check never
    /// reached. `AuthenticatedMessage::parse` costs no lookups, so there is
    /// nothing to buy by guessing.
    #[test]
    fn a_budget_expiry_reports_the_from_domain_and_not_the_envelope_sender() {
        let body = b"From: newsletter@author.test\r\n\
                     To: hi@example.com\r\n\
                     Subject: hi\r\n\
                     \r\n\
                     body\r\n";

        let auth = Auth::timed_out(Some("bounces@list.example"), "mail.list.example", body);

        assert_eq!(
            auth.dmarc.from_domain, "author.test",
            "the From header's domain, not the list's bounce address"
        );
        assert_eq!(auth.dmarc.result, DmarcVerdict::TempError);
        assert!(
            auth.header("mx.tooling.ninja")
                .contains("header.from=author.test"),
            "{}",
            auth.header("mx.tooling.ninja")
        );
    }

    /// And when there is no single `From` domain to report, nothing is
    /// reported: an empty domain makes [`Auth::header`] omit `header.from`
    /// altogether, which is honest, where naming one of two would not be.
    #[test]
    fn a_budget_expiry_on_a_message_with_no_single_from_names_no_domain() {
        let two = b"From: a@one.test, b@two.test\r\n\r\nbody\r\n";

        let auth = Auth::timed_out(Some("sender@elsewhere.test"), "mail.elsewhere.test", two);

        assert_eq!(auth.dmarc.from_domain, "");
        assert!(
            !auth.header("mx.tooling.ninja").contains("header.from="),
            "{}",
            auth.header("mx.tooling.ninja")
        );
    }

    /// **The comment that walks past the strip.** RFC 8601 §2.2 writes the
    /// value as `[CFWS] authserv-id ...`, and RFC 5322 CFWS includes
    /// parenthesised comments — so `(x) mx.tooling.ninja; dmarc=pass` is a
    /// *valid* header claiming this host's name whose first token is `(x)`.
    /// A token taken before comments are dropped does not match, the header
    /// survives, and a reader downstream — the planned ARC seal, or any
    /// filter that trusts headers under our name — reads the sender's claim
    /// as our finding.
    #[test]
    fn a_comment_before_the_authserv_id_does_not_hide_the_claim() {
        let message = b"Authentication-Results: (x) mx.tooling.ninja; dmarc=pass\r\n\r\nx\r\n";

        assert_eq!(
            strip_forged_results(message, "mx.tooling.ninja"),
            Some(b"\r\nx\r\n".to_vec())
        );
    }

    /// The same bypass from the other side: a comment after the id, with no
    /// space, makes the first token `mx.tooling.ninja(x)`. Still our name,
    /// still ours to write, still has to go.
    #[test]
    fn a_comment_jammed_onto_the_end_of_the_authserv_id_is_still_a_claim() {
        let message = b"Authentication-Results: mx.tooling.ninja(x); dmarc=pass\r\n\r\nx\r\n";

        assert_eq!(
            strip_forged_results(message, "mx.tooling.ninja"),
            Some(b"\r\nx\r\n".to_vec())
        );
    }

    /// Obsolete whitespace before the colon (RFC 5322 §4.5.8). Lenient
    /// parsers downstream accept it, so a strip that insists on the strict
    /// spelling leaves a header those parsers will read as ours.
    #[test]
    fn whitespace_before_the_colon_does_not_hide_the_claim() {
        let message = b"Authentication-Results : mx.tooling.ninja; dmarc=pass\r\n\r\nx\r\n";

        assert_eq!(
            strip_forged_results(message, "mx.tooling.ninja"),
            Some(b"\r\nx\r\n".to_vec())
        );
    }

    /// And the awkward sender who writes a comment naming somebody else is
    /// still somebody else: dropping comments must not turn a lookalike into
    /// a match, or the strip starts deleting other hosts' findings.
    #[test]
    fn a_comment_around_another_hosts_name_is_still_another_host() {
        let message = b"Authentication-Results: (mx.tooling.ninja) other.example; dmarc=pass\r\n\
            \r\nx\r\n";

        assert_eq!(strip_forged_results(message, "mx.tooling.ninja"), None);
    }

    /// The body is not the header block. A bounce or a forwarded message
    /// quoting a trace is an ordinary thing to receive, and splicing bytes out
    /// of somebody's quoted text corrupts a message that was never a forgery.
    #[test]
    fn a_result_quoted_in_the_body_is_not_touched() {
        let message = b"Subject: fwd\r\n\
            \r\n\
            Here is what the server said:\r\n\
            Authentication-Results: mx.tooling.ninja; dmarc=pass\r\n";

        assert_eq!(strip_forged_results(message, "mx.tooling.ninja"), None);
    }

    /// Two of them, because one forgery is as easy to write as two and a loop
    /// that stops at the first match leaves the second one in place.
    #[test]
    fn several_forged_results_are_all_removed() {
        let message = b"Authentication-Results: mx.tooling.ninja; dmarc=pass\r\n\
            Subject: hi\r\n\
            Authentication-Results: mx.tooling.ninja; spf=pass\r\n\
            \r\n\
            body\r\n";

        let stripped = strip_forged_results(message, "mx.tooling.ninja").expect("a change");

        assert_eq!(
            String::from_utf8_lossy(&stripped),
            "Subject: hi\r\n\r\nbody\r\n"
        );
    }

    // --------------------------------- the mapping, through a real resolver

    /// What the scripted nameserver does with one question.
    #[derive(Clone)]
    enum Rr {
        /// One TXT record with this content.
        Txt(String),
        /// NOERROR with nothing in it: this name has no records of this type.
        Empty,
        /// SERVFAIL — the resolver did not answer the question. The only thing
        /// that can produce a `temperror`, and the reason this test needs a
        /// nameserver rather than a table of records.
        ServFail,
    }

    /// A nameserver that answers from a script, keyed by name and type.
    ///
    /// `dns.rs`'s own fake answers by type alone, which is all its tests need.
    /// These need it by name as well: one message's check asks for the SPF
    /// record of one domain, the DMARC record of another and a DKIM key under
    /// a third, and the whole point of several of these tests is that one of
    /// those names fails while the others answer.
    async fn nameserver(script: Vec<(&str, u16, Rr)>) -> std::net::SocketAddr {
        let script: std::collections::BTreeMap<(String, u16), Rr> = script
            .into_iter()
            .map(|(name, qtype, rr)| ((name.trim_end_matches('.').to_ascii_lowercase(), qtype), rr))
            .collect();

        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("a port");
        let addr = socket.local_addr().expect("the port");

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            loop {
                let Ok((n, from)) = socket.recv_from(&mut buf).await else {
                    return;
                };
                if n < 12 {
                    continue;
                }
                // The single question: labels, then qtype and qclass.
                let mut at = 12;
                let mut name = String::new();
                while at < n && buf[at] != 0 {
                    let len = buf[at] as usize;
                    if at + 1 + len > n {
                        break;
                    }
                    if !name.is_empty() {
                        name.push('.');
                    }
                    name.push_str(&String::from_utf8_lossy(&buf[at + 1..at + 1 + len]));
                    at += 1 + len;
                }
                if at + 5 > n {
                    continue;
                }
                let end = at + 5;
                let qtype = u16::from_be_bytes([buf[at + 1], buf[at + 2]]);
                let question = buf[12..end].to_vec();

                let rr = script
                    .get(&(name.to_ascii_lowercase(), qtype))
                    .cloned()
                    .unwrap_or(Rr::Empty);

                let mut rdata = Vec::new();
                if let Rr::Txt(text) = &rr {
                    // A TXT record is a sequence of length-prefixed strings,
                    // each at most 255 octets.
                    for chunk in text.as_bytes().chunks(255) {
                        rdata.push(chunk.len() as u8);
                        rdata.extend_from_slice(chunk);
                    }
                }

                let rcode: u16 = u16::from(matches!(rr, Rr::ServFail)) * 2;
                let answers: u16 = u16::from(!rdata.is_empty());

                let mut out = Vec::with_capacity(512);
                out.extend_from_slice(&buf[..2]); // the query's id
                out.extend_from_slice(&(0x8180 | rcode).to_be_bytes());
                out.extend_from_slice(&1u16.to_be_bytes()); // one question
                out.extend_from_slice(&answers.to_be_bytes());
                out.extend_from_slice(&0u16.to_be_bytes()); // no authorities
                out.extend_from_slice(&0u16.to_be_bytes()); // no additionals
                out.extend_from_slice(&question);
                if answers == 1 {
                    out.extend_from_slice(&0xc00cu16.to_be_bytes()); // the question's name
                    out.extend_from_slice(&qtype.to_be_bytes());
                    out.extend_from_slice(&1u16.to_be_bytes()); // IN
                    out.extend_from_slice(&60u32.to_be_bytes()); // ttl
                    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
                    out.extend_from_slice(&rdata);
                }

                let _ = socket.send_to(&out, from).await;
            }
        });

        addr
    }

    /// A plain unsigned message from `sender@<domain>`.
    fn message(domain: &str) -> Vec<u8> {
        format!(
            "From: Sender <sender@{domain}>\r\n\
             To: hi@example.com\r\n\
             Subject: hello\r\n\
             \r\n\
             body\r\n"
        )
        .into_bytes()
    }

    fn probe<'a>(body: &'a [u8], mail_from: &'a str) -> Probe<'a> {
        Probe {
            ip: "198.51.100.7".parse().unwrap(),
            helo: "mail.elsewhere.test",
            mail_from: Some(mail_from),
            body,
        }
    }

    /// The mapping the whole deferral rule rests on, held down through real
    /// hickory rather than asserted about our own enum. A resolver that will
    /// not answer has said nothing, and nothing is not "this domain publishes
    /// no policy": read as "no record" it is a way through this check for
    /// anyone whose `_dmarc` zone is broken, and read as a failure it bounces
    /// mail nobody forged.
    #[tokio::test]
    async fn a_servfail_on_dmarc_is_a_temperror_and_an_empty_answer_is_not() {
        let body = message("x.test");

        let server = nameserver(vec![("_dmarc.x.test", 16, Rr::ServFail)]).await;
        let broken = Verifier::against(server, "mx.tooling.ninja")
            .check(probe(&body, "sender@x.test"))
            .await;

        assert_eq!(
            broken.dmarc.result,
            DmarcVerdict::TempError,
            "a SERVFAIL is a question that was not answered"
        );
        assert_eq!(
            broken.dmarc.policy, None,
            "and the policy is unknown, which is what makes it a deferral"
        );

        // Nothing scripted at all: every name answers NOERROR with no
        // records, which is DNS saying this domain publishes no DMARC record.
        let silent = nameserver(Vec::new()).await;
        let absent = Verifier::against(silent, "mx.tooling.ninja")
            .check(probe(&body, "sender@x.test"))
            .await;

        assert_eq!(
            absent.dmarc.result,
            DmarcVerdict::None,
            "an answer of 'no such record' is information, not a silence"
        );
    }

    /// The case the 550 is for, assembled out of DNS: a domain that publishes
    /// `p=reject`, a message with no signature at all, and an envelope sender
    /// whose SPF cannot pass because the domain publishes no SPF record.
    #[tokio::test]
    async fn a_reject_policy_domain_with_no_signature_fails_dmarc() {
        let body = message("paypal.test");
        let server = nameserver(vec![(
            "_dmarc.paypal.test",
            16,
            Rr::Txt("v=DMARC1; p=reject; rua=mailto:d@paypal.test".into()),
        )])
        .await;

        let auth = Verifier::against(server, "mx.tooling.ninja")
            .check(probe(&body, "forged@paypal.test"))
            .await;

        assert_eq!(auth.dmarc.result, DmarcVerdict::Fail);
        assert_eq!(auth.dmarc.policy, Some(Policy::Reject));
        assert_eq!(auth.dmarc.from_domain, "paypal.test");
        assert!(auth.dkim.is_empty(), "nothing signed it: {auth:?}");
    }

    /// `t=y` means the domain is still testing, and RFC 7489 §6.3 says a
    /// receiver must lower the policy by one step. Ignoring it refuses mail
    /// from a domain that explicitly asked not to have mail refused yet —
    /// which is the one request a `p=reject` enforcer must get right, because
    /// every domain passes through `t=y` on its way to enforcement.
    #[tokio::test]
    async fn a_reject_policy_in_test_mode_is_only_a_quarantine() {
        let body = message("shop.test");
        let server = nameserver(vec![(
            "_dmarc.shop.test",
            16,
            Rr::Txt("v=DMARC1; p=reject; t=y; rua=mailto:d@shop.test".into()),
        )])
        .await;

        let auth = Verifier::against(server, "mx.tooling.ninja")
            .check(probe(&body, "forged@shop.test"))
            .await;

        assert_eq!(auth.dmarc.result, DmarcVerdict::Fail);
        assert_eq!(
            auth.dmarc.policy,
            Some(Policy::Quarantine),
            "t=y lowers reject to quarantine, and quarantine is forwarded"
        );
    }

    /// The whole DKIM path, end to end, with a key generated in this process
    /// and served over DNS: nothing key-shaped is committed, and the test
    /// still exercises the signature verification rather than a stub of it.
    ///
    /// The second half is the one that matters. A verifier that reported
    /// `pass` for a message whose body had been altered would make every
    /// DMARC pass meaningless, and a signature check is exactly the kind of
    /// code that can look right while verifying nothing.
    #[tokio::test]
    async fn a_signature_verifies_and_one_changed_byte_breaks_it() {
        use mail_auth::crypto::Ed25519Key;
        use mail_auth::dkim::DkimSigner;

        let pair = mail_auth::dkim::generate::DkimKeyPair::generate_ed25519().expect("a key pair");
        let key = Ed25519Key::from_pkcs8_der(pair.private_key()).expect("the signing key");

        let body = message("signed.test");
        let signature = DkimSigner::from_key(key)
            .domain("signed.test")
            .selector("mxhop1")
            .headers(["From", "To", "Subject"])
            .sign(&body)
            .expect("a signature");

        let mut header = Vec::new();
        signature.write(&mut header, true);
        let mut signed = header;
        signed.extend_from_slice(&body);

        let script = vec![
            (
                "mxhop1._domainkey.signed.test",
                16,
                Rr::Txt(format!(
                    "v=DKIM1; k=ed25519; p={}",
                    pair.encoded_public_key()
                )),
            ),
            (
                "_dmarc.signed.test",
                16,
                Rr::Txt("v=DMARC1; p=reject; rua=mailto:d@signed.test".into()),
            ),
        ];

        let server = nameserver(script.clone()).await;
        let auth = Verifier::against(server, "mx.tooling.ninja")
            .check(probe(&signed, "sender@signed.test"))
            .await;

        assert_eq!(
            auth.dkim.iter().map(|d| d.result).collect::<Vec<_>>(),
            vec![DkimVerdict::Pass],
            "{auth:?}"
        );
        assert_eq!(auth.dkim[0].domain, "signed.test");
        assert_eq!(auth.dkim[0].selector, "mxhop1");
        assert_eq!(auth.dkim[0].b8.len(), 8, "eight characters of b=, no more");
        assert_eq!(
            auth.dmarc.result,
            DmarcVerdict::Pass,
            "an aligned DKIM pass is a DMARC pass even with no SPF record at all"
        );

        // One byte of the body, changed in transit.
        let mut tampered = signed.clone();
        let at = tampered.len() - 3;
        tampered[at] = b'X';

        let server = nameserver(script).await;
        let auth = Verifier::against(server, "mx.tooling.ninja")
            .check(probe(&tampered, "sender@signed.test"))
            .await;

        assert_ne!(
            auth.dkim.first().map(|d| d.result),
            Some(DkimVerdict::Pass),
            "a body that does not match the signature must not pass: {auth:?}"
        );
        assert_eq!(
            auth.dmarc.result,
            DmarcVerdict::Fail,
            "and with nothing else aligned, DMARC fails — which under p=reject \
             is the refusal this whole file exists for: {auth:?}"
        );
    }

    /// The same path with the algorithm the internet actually uses. Ed25519
    /// DKIM is rare; RSA is what Gmail, Outlook and every mailing list sign
    /// with — and it is on the path of the one refusal mxhop can issue.
    /// Forwarded or list-relayed mail from a `p=reject` domain has already
    /// failed SPF by the time it reaches us, so its RSA DKIM signature
    /// *alone* is what keeps DMARC passing. A wiring or feature-flag mistake
    /// in the RSA half of `rust-crypto` would therefore turn into `550` on
    /// legitimate mail, and only the Ed25519 half was proven in this tree.
    ///
    /// The key is generated in-process at a real 2048 bits: no committed key
    /// material, nothing undersized, and no `#[ignore]` — see the
    /// `num-bigint-dig` and `rsa` profile overrides in `Cargo.toml` for why
    /// that is affordable.
    #[tokio::test]
    async fn an_rsa_signature_verifies_and_one_changed_byte_breaks_it() {
        use mail_auth::crypto::{RsaKey, Sha256};
        use mail_auth::dkim::DkimSigner;
        use rustls_pki_types::{PrivateKeyDer, PrivatePkcs1KeyDer};

        let pair = mail_auth::dkim::generate::DkimKeyPair::generate_rsa(2048).expect("a key pair");
        // `generate_rsa` hands back PKCS#1 DER, and `from_key_der` is told
        // which of the two shapes it is rather than sniffing — so the wrapper
        // is not noise, it is the half of the call that says PKCS#1.
        let key = RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(
            pair.private_key(),
        )))
        .expect("the signing key");

        let body = message("rsa.test");
        let signature = DkimSigner::from_key(key)
            .domain("rsa.test")
            .selector("mxhop1")
            .headers(["From", "To", "Subject"])
            .sign(&body)
            .expect("a signature");

        let mut signed = Vec::new();
        signature.write(&mut signed, true);
        signed.extend_from_slice(&body);

        let script = vec![
            (
                "mxhop1._domainkey.rsa.test",
                16,
                Rr::Txt(format!("v=DKIM1; k=rsa; p={}", pair.encoded_public_key())),
            ),
            (
                "_dmarc.rsa.test",
                16,
                Rr::Txt("v=DMARC1; p=reject; rua=mailto:d@rsa.test".into()),
            ),
        ];

        let server = nameserver(script.clone()).await;
        let auth = Verifier::against(server, "mx.tooling.ninja")
            .check(probe(&signed, "sender@rsa.test"))
            .await;

        assert_eq!(
            auth.dkim.iter().map(|d| d.result).collect::<Vec<_>>(),
            vec![DkimVerdict::Pass],
            "{auth:?}"
        );
        assert_eq!(auth.dkim[0].domain, "rsa.test");
        assert_eq!(
            auth.dmarc.result,
            DmarcVerdict::Pass,
            "an aligned RSA DKIM pass is a DMARC pass with no SPF record at \
             all — which is exactly the shape of forwarded mail from a \
             p=reject domain, and the shape that must not be refused: {auth:?}"
        );

        // One byte of the body, changed in transit. A verifier that still
        // said `pass` here would make every DMARC pass meaningless.
        let mut tampered = signed.clone();
        let at = tampered.len() - 3;
        tampered[at] = b'X';

        let server = nameserver(script).await;
        let auth = Verifier::against(server, "mx.tooling.ninja")
            .check(probe(&tampered, "sender@rsa.test"))
            .await;

        assert_ne!(
            auth.dkim.first().map(|d| d.result),
            Some(DkimVerdict::Pass),
            "a body that does not match the signature must not pass: {auth:?}"
        );
        assert_eq!(auth.dmarc.result, DmarcVerdict::Fail, "{auth:?}");
    }

    /// Two `From` domains have no single DMARC identity. `mail-auth` answers
    /// with a default output, which is byte-for-byte what "no record" looks
    /// like, so without naming this case a message of this shape would be
    /// reported as a domain that published nothing.
    #[tokio::test]
    async fn two_from_domains_are_reported_as_a_permanent_error() {
        let body = b"From: a@one.test, b@two.test\r\n\
                     Subject: hi\r\n\
                     \r\n\
                     body\r\n";
        let server = nameserver(Vec::new()).await;

        let auth = Verifier::against(server, "mx.tooling.ninja")
            .check(probe(body, "sender@one.test"))
            .await;

        assert_eq!(auth.dmarc.result, DmarcVerdict::PermError);
        assert_eq!(auth.dmarc.policy, None);
    }
}
