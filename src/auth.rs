use std::fmt::Write as _;
use std::net::IpAddr;

use tracing::warn;

use crate::policy::{is_safe_address, name_or_unknown};
use crate::routing::is_qualified;

pub const AUTH_BUDGET: std::time::Duration = std::time::Duration::from_secs(20);

const SPF_SHARE: u32 = 8;
const DKIM_SHARE: u32 = 6;
const TOTAL_SHARES: u32 = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    pub spf: std::time::Duration,
    pub dkim: std::time::Duration,
    pub dmarc: std::time::Duration,
}

impl Budget {
    pub fn of(total: std::time::Duration) -> Self {
        let total = total.min(AUTH_BUDGET);
        let spf = total * SPF_SHARE / TOTAL_SHARES;
        let dkim = total * DKIM_SHARE / TOTAL_SHARES;
        Self {
            spf,
            dkim,
            dmarc: total.saturating_sub(spf).saturating_sub(dkim),
        }
    }

    pub fn total(&self) -> std::time::Duration {
        self.spf + self.dkim + self.dmarc
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Spf {
    #[default]
    None,
    Pass,
    Fail,
    SoftFail,
    Neutral,
    TempError,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DkimVerdict {
    Pass,
    Fail,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dkim {
    pub domain: String,
    pub selector: String,
    pub b8: String,
    pub result: DkimVerdict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DmarcVerdict {
    #[default]
    None,
    Pass,
    Fail,
    TempError,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
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

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Dmarc {
    pub from_domain: String,
    pub result: DmarcVerdict,
    pub policy: Option<Policy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Auth {
    pub spf_mail: Spf,
    pub spf_helo: Spf,
    pub mail_from: Option<String>,
    pub helo: Option<String>,
    pub dkim: Vec<Dkim>,
    pub dmarc: Dmarc,
    pub checked: bool,
    pub dkim_timed_out: bool,
}

impl Auth {
    pub fn not_checked() -> Self {
        Self::default()
    }

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
            dkim_timed_out: false,
        }
    }

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
            let _ = write!(dmarc, " ({}) policy.dmarc={}", policy.word(), policy.word());
        }
        if is_qualified(&self.dmarc.from_domain) {
            let _ = write!(dmarc, " header.from={}", self.dmarc.from_domain);
        }
        parts.push(dmarc);

        let last = parts.len() - 1;
        for part in &mut parts[..last] {
            part.push(';');
        }

        let mut header = parts.join("\r\n        ");
        header.push_str("\r\n");
        header
    }

    fn mail_from_property(&self) -> Option<String> {
        let address = self.mail_from.as_deref()?;
        is_safe_address(address).then(|| address.to_string())
    }

    fn helo_property(&self) -> Option<String> {
        let helo = self.helo.as_deref()?;
        is_qualified(helo).then(|| helo.to_string())
    }
}

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

const HEADER_NAME: &[u8] = b"authentication-results";

pub fn strip_forged_results(message: &[u8], authserv_id: &str) -> Option<Vec<u8>> {
    let authserv_id = authserv_id.trim().to_ascii_lowercase();
    let mut cuts: Vec<std::ops::Range<usize>> = Vec::new();

    for (range, header) in headers_of(message) {
        let lowered = header.to_ascii_lowercase();
        if !lowered.as_bytes().starts_with(HEADER_NAME) {
            continue;
        }
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
                return found;
            }
            at = line_end;
            text.push_str(&String::from_utf8_lossy(bare));
            if !matches!(message.get(at), Some(b' ' | b'\t')) {
                break;
            }
            text.push(' ');
        }
        found.push((start..at, text));
    }

    found
}

fn strip_eol(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

#[derive(Debug, Clone, Copy)]
pub struct Probe<'a> {
    pub ip: IpAddr,
    pub helo: &'a str,
    pub mail_from: Option<&'a str>,
    pub body: &'a [u8],
}

pub struct Verifier {
    inner: mail_auth::MessageAuthenticator,
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
    pub fn from_system(hostname: &str) -> Result<Self, String> {
        mail_auth::MessageAuthenticator::new_system_conf()
            .map(|inner| Self {
                inner,
                hostname: hostname.to_string(),
            })
            .map_err(|e| e.to_string())
    }

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
        options.attempts = 0;
        options.try_tcp_on_error = false;
        options.cache_size = 0;
        options.timeout = std::time::Duration::from_secs(60);

        Self {
            inner: mail_auth::MessageAuthenticator::new(config, options).expect("a resolver"),
            hostname: hostname.to_string(),
        }
    }

    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    pub async fn check(&self, probe: Probe<'_>, budget: Budget) -> Auth {
        use mail_auth::dmarc::verify::DmarcParameters;
        use mail_auth::spf::verify::SpfParameters;

        let started = std::time::Instant::now();
        let sender = probe.mail_from.unwrap_or("");
        let mail_from_domain = sender
            .rsplit_once('@')
            .map_or(probe.helo, |(_, domain)| domain);

        let both = tokio::time::timeout(budget.spf, async {
            let helo = self
                .inner
                .check_host(SpfParameters::helo(probe.ip, probe.helo, &self.hostname))
                .await;
            let mail = self
                .inner
                .check_host(SpfParameters::mail_from(
                    probe.ip,
                    probe.helo,
                    &self.hostname,
                    sender,
                ))
                .await;
            (helo, mail)
        })
        .await;

        let (spf_helo, spf_mail) = match both {
            Ok(pair) => pair,
            Err(_) => {
                warn!(
                    helo = %probe.helo,
                    seconds = budget.spf.as_secs(),
                    "SPF did not finish inside its own budget; both identities \
                     are reported as temporary and DMARC is still checked"
                );
                (
                    mail_auth::SpfOutput::new(probe.helo.to_string())
                        .with_result(mail_auth::SpfResult::TempError),
                    mail_auth::SpfOutput::new(mail_from_domain.to_string())
                        .with_result(mail_auth::SpfResult::TempError),
                )
            }
        };

        let mut auth = Auth {
            spf_mail: spf(spf_mail.result()),
            spf_helo: spf(spf_helo.result()),
            mail_from: probe.mail_from.map(ToString::to_string),
            helo: Some(probe.helo.to_string()),
            dkim: Vec::new(),
            dmarc: Dmarc::default(),
            checked: true,
            dkim_timed_out: false,
        };

        let Some(message) = mail_auth::AuthenticatedMessage::parse(probe.body) else {
            auth.dmarc.result = DmarcVerdict::PermError;
            return auth;
        };

        let dkim = match tokio::time::timeout(budget.dkim, self.inner.verify_dkim(&message)).await {
            Ok(dkim) => dkim,
            Err(_) => {
                warn!(
                    helo = %probe.helo,
                    seconds = budget.dkim.as_secs(),
                    "DKIM did not finish inside its own budget; DMARC is \
                     checked as though the message were unsigned, and a \
                     failure under p=reject will be deferred rather than \
                     refused"
                );
                auth.dkim_timed_out = true;
                Vec::new()
            }
        };
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

        let for_dmarc = budget
            .total()
            .saturating_sub(started.elapsed())
            .max(budget.dmarc);

        let dmarc = match tokio::time::timeout(
            for_dmarc,
            self.inner.verify_dmarc(DmarcParameters::new(
                &message,
                &dkim,
                mail_from_domain,
                &spf_mail,
            )),
        )
        .await
        {
            Ok(dmarc) => dmarc,
            Err(_) => {
                warn!(
                    helo = %probe.helo,
                    seconds = for_dmarc.as_secs(),
                    "DMARC did not finish inside its own budget; the message \
                     is forwarded with dmarc=temperror in its header"
                );
                auth.dmarc = Dmarc {
                    from_domain: domains.remove(0),
                    result: DmarcVerdict::TempError,
                    policy: None,
                };
                return auth;
            }
        };

        auth.dmarc = Dmarc {
            from_domain: dmarc.domain().to_string(),
            result: dmarc_verdict(&dmarc.result()),
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
        mail_auth::DmarcResult::TempError(_) => DmarcVerdict::TempError,
        mail_auth::DmarcResult::PermError(_) => DmarcVerdict::PermError,
        mail_auth::DmarcResult::None => DmarcVerdict::None,
    }
}

fn policy(policy: mail_auth::dmarc::Policy) -> Policy {
    match policy {
        mail_auth::dmarc::Policy::Reject => Policy::Reject,
        mail_auth::dmarc::Policy::Quarantine => Policy::Quarantine,
        mail_auth::dmarc::Policy::None | mail_auth::dmarc::Policy::Unspecified => Policy::None,
    }
}

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
            dkim_timed_out: false,
        }
    }

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

    #[test]
    fn an_unsigned_message_says_dkim_none_rather_than_nothing() {
        let header = Auth {
            dkim: Vec::new(),
            ..pass()
        }
        .header("mx.tooling.ninja");

        assert!(header.contains("dkim=none"), "{header}");
    }

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

    #[test]
    fn the_authserv_id_is_matched_without_regard_to_case() {
        let message = b"Authentication-Results: MX.Tooling.Ninja; dmarc=pass\r\n\r\nbody\r\n";

        assert_eq!(
            strip_forged_results(message, "mx.tooling.ninja"),
            Some(b"\r\nbody\r\n".to_vec())
        );
    }

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

    #[test]
    fn another_hosts_results_are_left_alone() {
        let message = b"Authentication-Results: mx.elsewhere.test; dmarc=fail\r\n\r\nbody\r\n";

        assert_eq!(
            strip_forged_results(message, "mx.tooling.ninja"),
            None,
            "nothing matched, so the message is handed on as the bytes that arrived"
        );
    }

    #[test]
    fn a_host_whose_name_merely_begins_with_ours_is_not_us() {
        let message = b"Authentication-Results: mx.tooling.ninja.example; dmarc=pass\r\n\r\nx\r\n";

        assert_eq!(strip_forged_results(message, "mx.tooling.ninja"), None);
    }

    #[test]
    fn an_authserv_id_jammed_against_the_semicolon_is_still_a_claim() {
        let message = b"Authentication-Results: mx.tooling.ninja;dmarc=pass\r\n\r\nx\r\n";

        assert_eq!(
            strip_forged_results(message, "mx.tooling.ninja"),
            Some(b"\r\nx\r\n".to_vec())
        );
    }

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

    #[test]
    fn a_comment_before_the_authserv_id_does_not_hide_the_claim() {
        let message = b"Authentication-Results: (x) mx.tooling.ninja; dmarc=pass\r\n\r\nx\r\n";

        assert_eq!(
            strip_forged_results(message, "mx.tooling.ninja"),
            Some(b"\r\nx\r\n".to_vec())
        );
    }

    #[test]
    fn a_comment_jammed_onto_the_end_of_the_authserv_id_is_still_a_claim() {
        let message = b"Authentication-Results: mx.tooling.ninja(x); dmarc=pass\r\n\r\nx\r\n";

        assert_eq!(
            strip_forged_results(message, "mx.tooling.ninja"),
            Some(b"\r\nx\r\n".to_vec())
        );
    }

    #[test]
    fn whitespace_before_the_colon_does_not_hide_the_claim() {
        let message = b"Authentication-Results : mx.tooling.ninja; dmarc=pass\r\n\r\nx\r\n";

        assert_eq!(
            strip_forged_results(message, "mx.tooling.ninja"),
            Some(b"\r\nx\r\n".to_vec())
        );
    }

    #[test]
    fn a_comment_around_another_hosts_name_is_still_another_host() {
        let message = b"Authentication-Results: (mx.tooling.ninja) other.example; dmarc=pass\r\n\
            \r\nx\r\n";

        assert_eq!(strip_forged_results(message, "mx.tooling.ninja"), None);
    }

    #[test]
    fn a_result_quoted_in_the_body_is_not_touched() {
        let message = b"Subject: fwd\r\n\
            \r\n\
            Here is what the server said:\r\n\
            Authentication-Results: mx.tooling.ninja; dmarc=pass\r\n";

        assert_eq!(strip_forged_results(message, "mx.tooling.ninja"), None);
    }

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

    #[derive(Clone)]
    enum Rr {
        Txt(String),
        Empty,
        ServFail,
        Hang,
    }

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

                if matches!(rr, Rr::Hang) {
                    continue;
                }

                let mut rdata = Vec::new();
                if let Rr::Txt(text) = &rr {
                    for chunk in text.as_bytes().chunks(255) {
                        rdata.push(chunk.len() as u8);
                        rdata.extend_from_slice(chunk);
                    }
                }

                let rcode: u16 = u16::from(matches!(rr, Rr::ServFail)) * 2;
                let answers: u16 = u16::from(!rdata.is_empty());

                let mut out = Vec::with_capacity(512);
                out.extend_from_slice(&buf[..2]);
                out.extend_from_slice(&(0x8180 | rcode).to_be_bytes());
                out.extend_from_slice(&1u16.to_be_bytes());
                out.extend_from_slice(&answers.to_be_bytes());
                out.extend_from_slice(&0u16.to_be_bytes());
                out.extend_from_slice(&0u16.to_be_bytes());
                out.extend_from_slice(&question);
                if answers == 1 {
                    out.extend_from_slice(&0xc00cu16.to_be_bytes());
                    out.extend_from_slice(&qtype.to_be_bytes());
                    out.extend_from_slice(&1u16.to_be_bytes());
                    out.extend_from_slice(&60u32.to_be_bytes());
                    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
                    out.extend_from_slice(&rdata);
                }

                let _ = socket.send_to(&out, from).await;
            }
        });

        addr
    }

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

    #[tokio::test]
    async fn a_servfail_on_dmarc_is_a_temperror_and_an_empty_answer_is_not() {
        let body = message("x.test");

        let server = nameserver(vec![("_dmarc.x.test", 16, Rr::ServFail)]).await;
        let broken = Verifier::against(server, "mx.tooling.ninja")
            .check(probe(&body, "sender@x.test"), Budget::of(AUTH_BUDGET))
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

        let silent = nameserver(Vec::new()).await;
        let absent = Verifier::against(silent, "mx.tooling.ninja")
            .check(probe(&body, "sender@x.test"), Budget::of(AUTH_BUDGET))
            .await;

        assert_eq!(
            absent.dmarc.result,
            DmarcVerdict::None,
            "an answer of 'no such record' is information, not a silence"
        );
    }

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
            .check(probe(&body, "forged@paypal.test"), Budget::of(AUTH_BUDGET))
            .await;

        assert_eq!(auth.dmarc.result, DmarcVerdict::Fail);
        assert_eq!(auth.dmarc.policy, Some(Policy::Reject));
        assert_eq!(auth.dmarc.from_domain, "paypal.test");
        assert!(auth.dkim.is_empty(), "nothing signed it: {auth:?}");
    }

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
            .check(probe(&body, "forged@shop.test"), Budget::of(AUTH_BUDGET))
            .await;

        assert_eq!(auth.dmarc.result, DmarcVerdict::Fail);
        assert_eq!(
            auth.dmarc.policy,
            Some(Policy::Quarantine),
            "t=y lowers reject to quarantine, and quarantine is forwarded"
        );
    }

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
            .check(
                probe(&signed, "sender@signed.test"),
                Budget::of(AUTH_BUDGET),
            )
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

        let mut tampered = signed.clone();
        let at = tampered.len() - 3;
        tampered[at] = b'X';

        let server = nameserver(script).await;
        let auth = Verifier::against(server, "mx.tooling.ninja")
            .check(
                probe(&tampered, "sender@signed.test"),
                Budget::of(AUTH_BUDGET),
            )
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

    #[tokio::test]
    async fn an_rsa_signature_verifies_and_one_changed_byte_breaks_it() {
        use mail_auth::crypto::{RsaKey, Sha256};
        use mail_auth::dkim::DkimSigner;
        use rustls_pki_types::{PrivateKeyDer, PrivatePkcs1KeyDer};

        let pair = mail_auth::dkim::generate::DkimKeyPair::generate_rsa(2048).expect("a key pair");
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
            .check(probe(&signed, "sender@rsa.test"), Budget::of(AUTH_BUDGET))
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

        let mut tampered = signed.clone();
        let at = tampered.len() - 3;
        tampered[at] = b'X';

        let server = nameserver(script).await;
        let auth = Verifier::against(server, "mx.tooling.ninja")
            .check(probe(&tampered, "sender@rsa.test"), Budget::of(AUTH_BUDGET))
            .await;

        assert_ne!(
            auth.dkim.first().map(|d| d.result),
            Some(DkimVerdict::Pass),
            "a body that does not match the signature must not pass: {auth:?}"
        );
        assert_eq!(auth.dmarc.result, DmarcVerdict::Fail, "{auth:?}");
    }

    fn impatient() -> Budget {
        Budget::of(std::time::Duration::from_millis(500))
    }

    #[test]
    fn the_two_stages_a_sender_chooses_the_names_for_cannot_take_dmarcs_share() {
        let full = Budget::of(AUTH_BUDGET);
        assert_eq!(full.spf.as_secs(), 8);
        assert_eq!(full.dkim.as_secs(), 6);
        assert_eq!(full.dmarc.as_secs(), 6);
        assert_eq!(full.total(), AUTH_BUDGET);

        let half = Budget::of(AUTH_BUDGET / 2);
        assert_eq!(half.spf.as_secs(), 4);
        assert_eq!(half.dkim.as_secs(), 3);
        assert_eq!(half.dmarc.as_secs(), 3);

        assert_eq!(Budget::of(AUTH_BUDGET * 10), full);
    }

    #[tokio::test]
    async fn a_forgery_whose_own_spf_never_answers_is_refused_rather_than_forwarded() {
        let server = nameserver(vec![
            ("bait.test", 16, Rr::Hang),
            ("mail.bait.test", 16, Rr::Hang),
            (
                "_dmarc.paypal.test",
                16,
                Rr::Txt("v=DMARC1; p=reject; rua=mailto:d@paypal.test".into()),
            ),
        ])
        .await;

        let body = b"From: Billing <billing@paypal.test>\r\n\
                     To: hi@example.com\r\n\
                     Subject: your account\r\n\
                     \r\n\
                     body\r\n";

        let started = std::time::Instant::now();
        let auth = Verifier::against(server, "mx.tooling.ninja")
            .check(
                Probe {
                    ip: "198.51.100.7".parse().unwrap(),
                    helo: "mail.bait.test",
                    mail_from: Some("bounce@bait.test"),
                    body,
                },
                impatient(),
            )
            .await;
        let took = started.elapsed();

        assert!(
            took < impatient().total() * 2,
            "the check should end on the SPF stage's clock, not on the \
             resolver's: {took:?}"
        );

        assert_eq!(auth.spf_mail, Spf::TempError, "{auth:?}");
        assert_eq!(auth.spf_helo, Spf::TempError, "{auth:?}");
        assert_eq!(
            auth.dmarc.policy,
            Some(Policy::Reject),
            "the victim's policy has to be in hand despite the attacker \
             having spent his own stage: that is the whole point of the \
             split budget: {auth:?}"
        );
        assert_eq!(auth.dmarc.result, DmarcVerdict::Fail, "{auth:?}");
        assert_eq!(
            crate::policy::authentication_reply(&auth).map(|reply| reply.code),
            Some(550),
            "refused while the sending server still holds it, not forwarded \
             with our envelope on it: {auth:?}"
        );
    }

    #[tokio::test]
    async fn an_honest_senders_own_dead_spf_is_deferred_and_not_refused() {
        let server = nameserver(vec![
            ("slow.test", 16, Rr::Hang),
            (
                "_dmarc.slow.test",
                16,
                Rr::Txt("v=DMARC1; p=reject; rua=mailto:d@slow.test".into()),
            ),
        ])
        .await;

        let body = message("slow.test");
        let auth = Verifier::against(server, "mx.tooling.ninja")
            .check(
                Probe {
                    ip: "198.51.100.7".parse().unwrap(),
                    helo: "slow.test",
                    mail_from: Some("sender@slow.test"),
                    body: &body,
                },
                impatient(),
            )
            .await;

        assert_eq!(auth.spf_mail, Spf::TempError, "{auth:?}");
        assert_eq!(auth.dmarc.policy, Some(Policy::Reject), "{auth:?}");
        assert_eq!(auth.dmarc.result, DmarcVerdict::TempError, "{auth:?}");
        assert_eq!(
            crate::policy::authentication_reply(&auth).map(|reply| reply.code),
            Some(451),
            "a temporary error with the policy in hand is the one case worth \
             a retry, and it must not have become a 550: {auth:?}"
        );
    }

    #[tokio::test]
    async fn a_signature_whose_key_never_arrives_is_deferred_and_not_refused() {
        use mail_auth::crypto::Ed25519Key;
        use mail_auth::dkim::DkimSigner;

        let pair = mail_auth::dkim::generate::DkimKeyPair::generate_ed25519().expect("a key pair");
        let key = Ed25519Key::from_pkcs8_der(pair.private_key()).expect("the signing key");

        let body = message("stalled.test");
        let signature = DkimSigner::from_key(key)
            .domain("stalled.test")
            .selector("mxhop1")
            .headers(["From", "To", "Subject"])
            .sign(&body)
            .expect("a signature");

        let mut signed = Vec::new();
        signature.write(&mut signed, true);
        signed.extend_from_slice(&body);

        let server = nameserver(vec![
            ("mxhop1._domainkey.stalled.test", 16, Rr::Hang),
            (
                "_dmarc.stalled.test",
                16,
                Rr::Txt("v=DMARC1; p=reject; rua=mailto:d@stalled.test".into()),
            ),
        ])
        .await;

        let auth = Verifier::against(server, "mx.tooling.ninja")
            .check(probe(&signed, "sender@stalled.test"), impatient())
            .await;

        assert!(
            auth.dkim_timed_out,
            "the one fact the decision table needs, and the one nothing \
             downstream could reconstruct: {auth:?}"
        );
        assert!(auth.dkim.is_empty(), "{auth:?}");
        assert_eq!(auth.dmarc.policy, Some(Policy::Reject), "{auth:?}");
        assert_eq!(
            auth.dmarc.result,
            DmarcVerdict::Fail,
            "DMARC sees an unsigned message, because that is all an expired \
             DKIM stage can hand it: {auth:?}"
        );
        assert_eq!(
            crate::policy::authentication_reply(&auth).map(|reply| reply.code),
            Some(451),
            "and the flag is what keeps that from being a permanent refusal \
             of a message that was signed all along: {auth:?}"
        );
    }

    #[tokio::test]
    async fn the_same_message_passes_when_its_key_is_answered() {
        use mail_auth::crypto::Ed25519Key;
        use mail_auth::dkim::DkimSigner;

        let pair = mail_auth::dkim::generate::DkimKeyPair::generate_ed25519().expect("a key pair");
        let key = Ed25519Key::from_pkcs8_der(pair.private_key()).expect("the signing key");

        let body = message("stalled.test");
        let signature = DkimSigner::from_key(key)
            .domain("stalled.test")
            .selector("mxhop1")
            .headers(["From", "To", "Subject"])
            .sign(&body)
            .expect("a signature");

        let mut signed = Vec::new();
        signature.write(&mut signed, true);
        signed.extend_from_slice(&body);

        let server = nameserver(vec![
            (
                "mxhop1._domainkey.stalled.test",
                16,
                Rr::Txt(format!(
                    "v=DKIM1; k=ed25519; p={}",
                    pair.encoded_public_key()
                )),
            ),
            (
                "_dmarc.stalled.test",
                16,
                Rr::Txt("v=DMARC1; p=reject; rua=mailto:d@stalled.test".into()),
            ),
        ])
        .await;

        let auth = Verifier::against(server, "mx.tooling.ninja")
            .check(probe(&signed, "sender@stalled.test"), impatient())
            .await;

        assert!(!auth.dkim_timed_out, "{auth:?}");
        assert_eq!(auth.dmarc.result, DmarcVerdict::Pass, "{auth:?}");
        assert_eq!(crate::policy::authentication_reply(&auth), None, "{auth:?}");
    }

    #[tokio::test]
    async fn two_from_domains_are_reported_as_a_permanent_error() {
        let body = b"From: a@one.test, b@two.test\r\n\
                     Subject: hi\r\n\
                     \r\n\
                     body\r\n";
        let server = nameserver(Vec::new()).await;

        let auth = Verifier::against(server, "mx.tooling.ninja")
            .check(probe(body, "sender@one.test"), Budget::of(AUTH_BUDGET))
            .await;

        assert_eq!(auth.dmarc.result, DmarcVerdict::PermError);
        assert_eq!(auth.dmarc.policy, None);
    }
}
