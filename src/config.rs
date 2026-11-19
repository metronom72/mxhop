use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::net::SocketAddr;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use serde::de::{self, Deserializer};
use toml::Spanned;

use crate::policy::Enforce;
use crate::queue::Schedule;
use crate::routing::{CATCH_ALL, Mailbox, Route, Router, is_qualified};

pub const DEFAULT_MAX_MESSAGE_BYTES: u64 = 25 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Config {
    pub hostname: String,
    pub listen: SocketAddr,
    pub spool_dir: PathBuf,
    pub max_message_bytes: u64,
    pub outbound: Outbound,
    pub router: Router,
    pub tls: Option<TlsPaths>,
    pub srs: Option<SrsSettings>,
    pub queue: Schedule,
    pub auth: AuthSettings,
    pub observe: Option<SocketAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthSettings {
    pub enabled: bool,
    pub enforce: Enforce,
}

impl Default for AuthSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            enforce: Enforce::Dmarc,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrsSettings {
    pub domain: String,
    pub secret_file: PathBuf,
    pub max_age_days: u32,
    pub line: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsPaths {
    pub certificate: PathBuf,
    pub key: PathBuf,
    pub line: Option<usize>,
}

#[derive(Debug, Clone, Default)]
pub struct Outbound {
    pub ipv6: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    pub line: Option<usize>,
    pub message: String,
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(line) => write!(f, "line {line}: {}", self.message),
            None => f.write_str(&self.message),
        }
    }
}

pub fn load_file(path: &Path) -> Result<Config, Vec<Problem>> {
    match fs::read_to_string(path) {
        Ok(src) => load_str(&src),
        Err(e) => Err(vec![Problem {
            line: None,
            message: format!("cannot be read: {e}"),
        }]),
    }
}

pub fn load_str(src: &str) -> Result<Config, Vec<Problem>> {
    let raw: Raw = match toml::from_str(src) {
        Ok(raw) => raw,
        Err(e) => return Err(vec![from_toml(src, &e)]),
    };

    let mut problems = Vec::new();

    let hostname = raw.hostname.get_ref().to_ascii_lowercase();
    if !is_qualified(&hostname) {
        problems.push(at(
            src,
            raw.hostname.span(),
            format!(
                "hostname must be a fully qualified name, like mx.example.com — {:?} is not, \
                 and it is the name mxhop announces in HELO",
                raw.hostname.get_ref()
            ),
        ));
    }

    let listen = raw.listen.get_ref().parse::<SocketAddr>().ok();
    if listen.is_none() {
        problems.push(at(
            src,
            raw.listen.span(),
            format!(
                "listen must be an address and a port, like 0.0.0.0:25 — {:?} is not",
                raw.listen.get_ref()
            ),
        ));
    }

    let mut observe = None;
    if let Some(raw_observe) = &raw.observe {
        match raw_observe.listen.get_ref().parse::<SocketAddr>() {
            Ok(address) => observe = Some(address),
            Err(_) => problems.push(at(
                src,
                raw_observe.listen.span(),
                format!(
                    "observe.listen must be an address and a port, like 127.0.0.1:9090 \
                     — {:?} is not",
                    raw_observe.listen.get_ref()
                ),
            )),
        }
        if let Some(address) = observe
            && Some(address) == listen
        {
            problems.push(at(
                src,
                raw_observe.listen.span(),
                format!(
                    "observe.listen is {address}, which is where SMTP listens; metrics \
                     and health must not share a port with mail"
                ),
            ));
        }
    }

    let spool_dir = raw.spool_dir.get_ref().clone();
    if !spool_dir.is_absolute() {
        problems.push(at(
            src,
            raw.spool_dir.span(),
            format!(
                "spool_dir must be an absolute path: {} depends on the working directory, \
                 and a queue that moves loses mail",
                spool_dir.display()
            ),
        ));
    }

    let max_message_bytes = match &raw.max_message_bytes {
        None => DEFAULT_MAX_MESSAGE_BYTES,
        Some(v) if *v.get_ref() == 0 => {
            problems.push(at(
                src,
                v.span(),
                "max_message_bytes must be greater than zero".to_string(),
            ));
            DEFAULT_MAX_MESSAGE_BYTES
        }
        Some(v) => *v.get_ref(),
    };

    let tls = raw.tls.as_ref().map(|tls| {
        for (what, path) in [("certificate", &tls.certificate), ("key", &tls.key)] {
            if !path.get_ref().is_absolute() {
                problems.push(at(
                    src,
                    path.span(),
                    format!(
                        "tls.{what} must be an absolute path: {} is read again on SIGHUP, \
                         from whatever directory the service is in by then",
                        path.get_ref().display()
                    ),
                ));
            }
        }
        TlsPaths {
            certificate: tls.certificate.get_ref().clone(),
            key: tls.key.get_ref().clone(),
            line: line_of_text(src, "[tls]"),
        }
    });

    let srs = raw.srs.as_ref().map(|srs| {
        let domain = srs.domain.get_ref().to_ascii_lowercase();
        if !is_qualified(&domain) {
            problems.push(at(
                src,
                srs.domain.span(),
                format!(
                    "srs.domain must be a fully qualified name, like srs.example.com — \
                     {:?} is not, and it is the domain whose SPF record has to name this \
                     host for forwarded mail to pass SPF",
                    srs.domain.get_ref()
                ),
            ));
        }
        if !srs.secret_file.get_ref().is_absolute() {
            problems.push(at(
                src,
                srs.secret_file.span(),
                format!(
                    "srs.secret_file must be an absolute path: {} depends on the working \
                     directory, and a signing key read from the wrong file means every \
                     bounce in flight stops verifying",
                    srs.secret_file.get_ref().display()
                ),
            ));
        }
        let max_age_days = match &srs.max_age_days {
            None => crate::srs::DEFAULT_MAX_AGE_DAYS,
            Some(v) if *v.get_ref() == 0 => {
                problems.push(at(
                    src,
                    v.span(),
                    "srs.max_age_days must be at least 1: zero expires every rewritten \
                     address at the next midnight, which looks like SRS working until \
                     the first bounce arrives a day late"
                        .to_string(),
                ));
                crate::srs::DEFAULT_MAX_AGE_DAYS
            }
            Some(v) if *v.get_ref() > crate::srs::MAX_AGE_DAYS_CEILING => {
                problems.push(at(
                    src,
                    v.span(),
                    format!(
                        "srs.max_age_days must be at most {}: the day an address carries \
                         wraps every 1024 days, so anything from 1022 upwards accepts \
                         every address ever issued and turns expiry off without saying \
                         so — and {} days is a window in which a harvested address \
                         stays replayable for the better part of {:.1} years",
                        crate::srs::MAX_AGE_DAYS_CEILING,
                        v.get_ref(),
                        f64::from(*v.get_ref()) / 365.0
                    ),
                ));
                crate::srs::DEFAULT_MAX_AGE_DAYS
            }
            Some(v) => *v.get_ref(),
        };
        if raw
            .domains
            .keys()
            .any(|listed| listed.eq_ignore_ascii_case(&domain))
        {
            problems.push(at(
                src,
                srs.domain.span(),
                format!(
                    "{domain} is the srs domain and is also listed in [domains]: \
                     remove it from [domains], or give srs a domain of its own — \
                     the alias table is consulted first, so bounces coming back to a \
                     rewritten sender would be answered by an alias lookup instead of \
                     being decoded"
                ),
            ));
        }
        SrsSettings {
            domain,
            secret_file: srs.secret_file.get_ref().clone(),
            max_age_days,
            line: line_of_text(src, "[srs]"),
        }
    });

    let queue = match &raw.queue {
        None => Schedule::default(),
        Some(table) => {
            let default = Schedule::default();

            let retries = match &table.retry_minutes {
                None => default.retries.clone(),
                Some(stated) if stated.get_ref().is_empty() => {
                    problems.push(at(
                        src,
                        stated.span(),
                        "queue.retry_minutes must state at least one interval: an empty \
                         list is a queue that accepts mail and never tries to deliver \
                         it again"
                            .to_string(),
                    ));
                    default.retries.clone()
                }
                Some(stated) if stated.get_ref().len() > crate::queue::MAX_RETRY_STEPS => {
                    problems.push(at(
                        src,
                        stated.span(),
                        format!(
                            "queue.retry_minutes may state at most {} intervals: the last \
                             one repeats for as long as the message is queued, so a list \
                             longer than that is a schedule nobody is reading",
                            crate::queue::MAX_RETRY_STEPS
                        ),
                    ));
                    default.retries.clone()
                }
                Some(stated) => {
                    let mut problem = None;
                    for minutes in stated.get_ref() {
                        if *minutes == 0 {
                            problem = Some(
                                "queue.retry_minutes must not contain 0: a destination \
                                 that said \"try later\" and is tried again in the same \
                                 instant is a destination that rate-limits us next"
                                    .to_string(),
                            );
                        } else if *minutes > crate::queue::MAX_RETRY_MINUTES {
                            problem = Some(format!(
                                "queue.retry_minutes must not contain {minutes}: no \
                                 interval may be longer than {} minutes, because a day \
                                 between attempts inside a lifetime measured in hours is \
                                 a schedule that retries almost nothing",
                                crate::queue::MAX_RETRY_MINUTES
                            ));
                        }
                    }
                    match problem {
                        Some(message) => {
                            problems.push(at(src, stated.span(), message));
                            default.retries.clone()
                        }
                        None => stated
                            .get_ref()
                            .iter()
                            .map(|m| Duration::from_secs(m * 60))
                            .collect(),
                    }
                }
            };

            let lifetime_hours = match &table.lifetime_hours {
                None => default.lifetime.as_secs() / 3_600,
                Some(v) if *v.get_ref() == 0 => {
                    problems.push(at(
                        src,
                        v.span(),
                        "queue.lifetime_hours must be at least 1: zero gives up on a \
                         message the first time it is looked at, and mxhop cannot yet \
                         tell its sender that it did"
                            .to_string(),
                    ));
                    default.lifetime.as_secs() / 3_600
                }
                Some(v) if *v.get_ref() > crate::queue::MAX_LIFETIME_HOURS => {
                    problems.push(at(
                        src,
                        v.span(),
                        format!(
                            "queue.lifetime_hours must be at most {}: a month of attempts \
                             is a month in which nobody has been told anything, and every \
                             sender's postmaster gave up waiting long before it",
                            crate::queue::MAX_LIFETIME_HOURS
                        ),
                    ));
                    default.lifetime.as_secs() / 3_600
                }
                Some(v) => *v.get_ref(),
            };

            let sweep_seconds = match &table.sweep_seconds {
                None => default.sweep_interval.as_secs(),
                Some(v) if *v.get_ref() == 0 => {
                    problems.push(at(
                        src,
                        v.span(),
                        "queue.sweep_seconds must be at least 1: a queue read in a tight \
                         loop is a destination connected to in a tight loop"
                            .to_string(),
                    ));
                    default.sweep_interval.as_secs()
                }
                Some(v) if *v.get_ref() > crate::queue::MAX_SWEEP_SECONDS => {
                    problems.push(at(
                        src,
                        v.span(),
                        format!(
                            "queue.sweep_seconds must be at most {}: the schedule lives in \
                             the envelopes, and reading them less often than that makes \
                             every interval in it longer than it says",
                            crate::queue::MAX_SWEEP_SECONDS
                        ),
                    ));
                    default.sweep_interval.as_secs()
                }
                Some(v) => *v.get_ref(),
            };

            Schedule {
                retries,
                lifetime: Duration::from_secs(lifetime_hours * 3_600),
                sweep_interval: Duration::from_secs(sweep_seconds),
            }
        }
    };

    if let Some(srs) = &srs {
        let lifetime_hours = queue.lifetime.as_secs() / 3_600;
        let window_hours = u64::from(srs.max_age_days) * 24;
        if lifetime_hours > window_hours {
            let message = format!(
                "queue.lifetime_hours ({lifetime_hours}) must not exceed \
                 srs.max_age_days ({} days, {window_hours} hours): a message still being \
                 retried after that leaves with a rewritten sender that has already \
                 expired, so the destination's bounce comes back to an address mxhop no \
                 longer recognises and the report is lost",
                srs.max_age_days
            );
            problems.push(
                match raw.queue.as_ref().and_then(|q| q.lifetime_hours.as_ref()) {
                    Some(v) => at(src, v.span(), message),
                    None => Problem {
                        line: line_of_text(src, "[srs]"),
                        message,
                    },
                },
            );
        }
    }

    let auth = match &raw.auth {
        None => AuthSettings::default(),
        Some(table) => {
            let enforce = match &table.enforce {
                None => Enforce::Dmarc,
                Some(word) => match word.get_ref().as_str() {
                    "dmarc" => Enforce::Dmarc,
                    "off" => Enforce::Off,
                    other => {
                        problems.push(at(
                            src,
                            word.span(),
                            format!(
                                "auth.enforce must be \"dmarc\" or \"off\" — {other:?} is \
                                 neither; \"dmarc\" refuses a DMARC failure whose domain \
                                 publishes p=reject, and \"off\" evaluates and stamps the \
                                 header without ever refusing or deferring"
                            ),
                        ));
                        Enforce::Dmarc
                    }
                },
            };
            let enabled = table.enabled.as_ref().is_none_or(|v| *v.get_ref());
            if let Some(word) = table.enforce.as_ref().filter(|_| !enabled) {
                problems.push(at(
                    src,
                    word.span(),
                    "auth.enforce has no meaning with auth.enabled = false: nothing is \
                     looked up, so there is no result to enforce. Remove one of them — \
                     enabled = false writes no header either, and enforce = \"off\" \
                     writes the header and never refuses"
                        .to_string(),
                ));
            }
            AuthSettings { enabled, enforce }
        }
    };

    if raw.domains.is_empty() {
        problems.push(Problem {
            line: None,
            message: "no domains are configured, so there is nothing to forward".to_string(),
        });
    }

    let mut router = Router::default();
    let mut entry_lines: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut destinations: Vec<(usize, Mailbox)> = Vec::new();

    for (domain, domain_config) in &raw.domains {
        let name = domain.to_ascii_lowercase();
        if !is_qualified(&name) {
            problems.push(Problem {
                line: line_of_text(src, domain),
                message: format!("{domain:?} is not a domain name mxhop can accept mail for"),
            });
        }
        if domain_config.aliases.is_empty() {
            problems.push(Problem {
                line: line_of_text(src, domain),
                message: format!(
                    "{domain} has no aliases, so every message to it would be refused"
                ),
            });
        }

        for (alias, target) in &domain_config.aliases {
            let line = line_at(src, target.span().start);
            entry_lines.insert((name.clone(), alias.to_ascii_lowercase()), line);

            if alias != CATCH_ALL && !is_usable_local_part(alias) {
                problems.push(Problem {
                    line: Some(line),
                    message: format!(
                        "alias name {alias:?} can never appear in an SMTP envelope, \
                         so it would never match anything"
                    ),
                });
                continue;
            }

            match target.get_ref() {
                RawTarget::Reject { reject } => {
                    if !begins_with_status_code(reject) {
                        problems.push(Problem {
                            line: Some(line),
                            message: format!(
                                "a reject reply must begin with an SMTP status code, like \
                                 \"550 5.1.1 no mail here\" — {reject:?} does not"
                            ),
                        });
                        continue;
                    }
                    router.insert(&name, alias, Route::Reject(reject.clone()));
                }
                RawTarget::Via { to, via } => {
                    let host = via.to_ascii_lowercase();
                    let mailbox = match Mailbox::parse(to) {
                        Ok(mailbox) => mailbox,
                        Err(e) => {
                            problems.push(Problem {
                                line: Some(line),
                                message: format!("{to:?} {e}"),
                            });
                            continue;
                        }
                    };
                    if !is_qualified(&host) {
                        problems.push(Problem {
                            line: Some(line),
                            message: format!(
                                "via = {via:?} is not a fully qualified host name, so \
                                 mail for {mailbox} would have nowhere to go"
                            ),
                        });
                        continue;
                    }
                    if host == hostname.to_ascii_lowercase() {
                        problems.push(Problem {
                            line: Some(line),
                            message: format!(
                                "via = {via:?} is this host, so mail for {mailbox} would \
                                 be delivered to mxhop itself for ever"
                            ),
                        });
                        continue;
                    }
                    router.insert(&name, alias, Route::Via { to: mailbox, host });
                }
                RawTarget::One(one) => match Mailbox::parse(one) {
                    Ok(mailbox) => {
                        destinations.push((line, mailbox.clone()));
                        router.insert(&name, alias, Route::Forward(vec![mailbox]));
                    }
                    Err(e) => problems.push(Problem {
                        line: Some(line),
                        message: format!("{one:?} {e}"),
                    }),
                },
                RawTarget::Many(many) => {
                    if many.is_empty() {
                        problems.push(Problem {
                            line: Some(line),
                            message: format!(
                                "{alias} needs at least one destination, or a \
                                 {{ reject = \"550 …\" }} saying so on purpose"
                            ),
                        });
                        continue;
                    }
                    let mut mailboxes = Vec::with_capacity(many.len());
                    let mut ok = true;
                    for one in many {
                        match Mailbox::parse(one) {
                            Ok(mailbox) => {
                                destinations.push((line, mailbox.clone()));
                                mailboxes.push(mailbox);
                            }
                            Err(e) => {
                                ok = false;
                                problems.push(Problem {
                                    line: Some(line),
                                    message: format!("{one:?} {e}"),
                                });
                            }
                        }
                    }
                    if ok {
                        router.insert(&name, alias, Route::Forward(mailboxes));
                    }
                }
            }
        }
    }

    for (line, mailbox) in &destinations {
        if router.handles_domain(mailbox.domain())
            && router.resolve(mailbox.domain(), mailbox.local()).is_none()
        {
            problems.push(Problem {
                line: Some(*line),
                message: format!(
                    "{mailbox} is handled by mxhop but has no alias there, \
                     so mail forwarded to it would be refused"
                ),
            });
        }
    }

    let mut already_in_a_loop: BTreeSet<(String, String)> = BTreeSet::new();
    for (entry, line) in &entry_lines {
        if already_in_a_loop.contains(entry) {
            continue;
        }
        if let Some(found) = find_loop(&router, &entry.0, &entry.1) {
            already_in_a_loop.extend(found.nodes);
            problems.push(Problem {
                line: Some(*line),
                message: format!("alias loop: {}", found.chain.join(" → ")),
            });
        }
    }

    if !problems.is_empty() {
        problems.sort_by_key(|p| p.line.unwrap_or(0));
        return Err(problems);
    }

    Ok(Config {
        hostname,
        listen: listen.expect("checked above"),
        spool_dir,
        max_message_bytes,
        outbound: Outbound {
            ipv6: raw.outbound.is_some_and(|o| o.ipv6),
        },
        router,
        tls,
        srs,
        queue,
        auth,
        observe,
    })
}

struct Found {
    nodes: Vec<(String, String)>,
    chain: Vec<String>,
}

fn find_loop(router: &Router, domain: &str, local: &str) -> Option<Found> {
    fn go(
        router: &Router,
        domain: &str,
        local: &str,
        path: &mut Vec<(String, String)>,
    ) -> Option<Found> {
        let (matched, route) = router.resolve(domain, local)?;
        let node = (domain.to_ascii_lowercase(), matched.to_ascii_lowercase());

        if let Some(from) = path.iter().position(|seen| *seen == node) {
            let nodes = path[from..].to_vec();
            let chain = nodes
                .iter()
                .chain(std::iter::once(&node))
                .map(|(d, l)| format!("{l}@{d}"))
                .collect();
            return Some(Found { nodes, chain });
        }

        path.push(node);
        if let Route::Forward(mailboxes) = route {
            for mailbox in mailboxes {
                if router.handles_domain(mailbox.domain())
                    && let Some(found) = go(router, mailbox.domain(), mailbox.local(), path)
                {
                    return Some(found);
                }
            }
        }
        path.pop();
        None
    }

    go(router, domain, local, &mut Vec::new())
}

fn is_usable_local_part(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && !s.contains('@')
        && !s.chars().any(|c| c.is_whitespace() || c.is_control())
}

fn begins_with_status_code(reply: &str) -> bool {
    let b = reply.as_bytes();
    b.len() >= 3
        && b[..3].iter().all(u8::is_ascii_digit)
        && matches!(b[0], b'4' | b'5')
        && (b.len() == 3 || b[3] == b' ' || b[3] == b'-')
}

fn line_at(src: &str, offset: usize) -> usize {
    src.as_bytes()[..offset.min(src.len())]
        .iter()
        .filter(|b| **b == b'\n')
        .count()
        + 1
}

fn at(src: &str, span: Range<usize>, message: String) -> Problem {
    Problem {
        line: Some(line_at(src, span.start)),
        message,
    }
}

fn line_of_text(src: &str, needle: &str) -> Option<usize> {
    src.lines()
        .position(|line| line.contains(needle))
        .map(|i| i + 1)
}

fn from_toml(src: &str, e: &toml::de::Error) -> Problem {
    Problem {
        line: e.span().map(|span| line_at(src, span.start)),
        message: e.message().to_string(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    hostname: Spanned<String>,
    listen: Spanned<String>,
    spool_dir: Spanned<PathBuf>,
    max_message_bytes: Option<Spanned<u64>>,
    outbound: Option<RawOutbound>,
    #[serde(default)]
    domains: BTreeMap<String, RawDomain>,
    tls: Option<RawTls>,
    srs: Option<RawSrs>,
    auth: Option<RawAuth>,
    queue: Option<RawQueue>,
    observe: Option<RawObserve>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawObserve {
    listen: Spanned<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawQueue {
    retry_minutes: Option<Spanned<Vec<u64>>>,
    lifetime_hours: Option<Spanned<u64>>,
    sweep_seconds: Option<Spanned<u64>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSrs {
    domain: Spanned<String>,
    secret_file: Spanned<PathBuf>,
    max_age_days: Option<Spanned<u32>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAuth {
    enabled: Option<Spanned<bool>>,
    enforce: Option<Spanned<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTls {
    certificate: Spanned<PathBuf>,
    key: Spanned<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOutbound {
    #[serde(default)]
    ipv6: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDomain {
    #[serde(default)]
    aliases: BTreeMap<String, Spanned<RawTarget>>,
}

#[derive(Debug)]
enum RawTarget {
    One(String),
    Many(Vec<String>),
    Via { to: String, via: String },
    Reject { reject: String },
}

impl<'de> Deserialize<'de> for RawTarget {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Shape {
            One(String),
            Many(Vec<String>),
            Via { to: String, via: String },
            Reject { reject: String },
        }

        match Shape::deserialize(d) {
            Ok(Shape::One(one)) => Ok(RawTarget::One(one)),
            Ok(Shape::Many(many)) => Ok(RawTarget::Many(many)),
            Ok(Shape::Via { to, via }) => Ok(RawTarget::Via { to, via }),
            Ok(Shape::Reject { reject }) => Ok(RawTarget::Reject { reject }),
            Err(_) => Err(de::Error::custom(
                "an alias must be an address (\"me@example.com\"), a list of addresses, \
                 { to = \"me@example.com\", via = \"mx.example.net\" }, \
                 or { reject = \"550 5.1.1 no mail here\" }",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
hostname = "mx.example.com"
listen = "0.0.0.0:25"
spool_dir = "/var/lib/mxhop/spool"

[domains."example.com".aliases]
hi = "me@gmail.com"
"#;

    fn line_with(src: &str, needle: &str) -> usize {
        src.lines()
            .position(|l| l.contains(needle))
            .unwrap_or_else(|| panic!("fixture has no line containing {needle:?}"))
            + 1
    }

    fn problems(src: &str) -> Vec<String> {
        load_str(src)
            .err()
            .unwrap_or_else(|| panic!("expected this configuration to be refused"))
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    fn problem_line(problem: &str) -> usize {
        problem
            .strip_prefix("line ")
            .and_then(|rest| rest.split_once(':'))
            .and_then(|(n, _)| n.parse().ok())
            .unwrap_or_else(|| panic!("this problem names no line: {problem}"))
    }

    fn only_problem(src: &str) -> String {
        let found = problems(src);
        assert_eq!(
            found.len(),
            1,
            "expected exactly one problem, got {found:#?}"
        );
        found.into_iter().next().unwrap()
    }

    #[test]
    fn a_minimal_configuration_loads() {
        let c = load_str(MINIMAL).expect("minimal configuration should load");

        assert_eq!(c.hostname, "mx.example.com");
        assert_eq!(c.listen, "0.0.0.0:25".parse::<SocketAddr>().unwrap());
        assert_eq!(c.spool_dir, PathBuf::from("/var/lib/mxhop/spool"));
        assert_eq!(c.max_message_bytes, DEFAULT_MAX_MESSAGE_BYTES);
        assert!(c.router.route("example.com", "hi").is_some());
    }

    #[test]
    fn outbound_delivery_stays_on_ipv4_unless_the_file_says_otherwise() {
        assert!(!load_str(MINIMAL).expect("the minimal file").outbound.ipv6);
    }

    #[test]
    fn outbound_ipv6_can_be_turned_on() {
        let src = format!("{MINIMAL}\n[outbound]\nipv6 = true\n");
        assert!(
            load_str(&src)
                .expect("ipv6 = true should load")
                .outbound
                .ipv6
        );
    }

    #[test]
    fn a_misspelled_outbound_key_is_refused_rather_than_ignored() {
        let src = format!("{MINIMAL}\n[outbound]\nipv_6 = true\n");
        assert!(
            only_problem(&src).contains("ipv_6"),
            "{}",
            only_problem(&src)
        );
    }

    #[test]
    fn a_destination_may_be_one_address_or_several() {
        let src = r#"
hostname = "mx.example.com"
listen = "0.0.0.0:25"
spool_dir = "/var/lib/mxhop/spool"

[domains."example.com".aliases]
one = "a@gmail.com"
team = ["a@gmail.com", "b@fastmail.com"]
"#;
        let c = load_str(src).expect("both forms should load");

        let Some(Route::Forward(one)) = c.router.route("example.com", "one") else {
            panic!("`one` should forward");
        };
        let Some(Route::Forward(team)) = c.router.route("example.com", "team") else {
            panic!("`team` should forward");
        };
        assert_eq!(one.len(), 1);
        assert_eq!(team.len(), 2);
    }

    #[test]
    fn an_alias_of_the_wrong_shape_says_what_the_shapes_are() {
        let src = MINIMAL.replace(r#"hi = "me@gmail.com""#, "hi = 25");
        let p = only_problem(&src);

        assert!(
            p.contains("reject ="),
            "the reject form should be shown: {p}"
        );
        assert!(p.contains("me@example.com"), "and the plain form too: {p}");
    }

    #[test]
    fn a_reject_entry_refuses_during_the_session() {
        let src = r#"
hostname = "mx.example.com"
listen = "0.0.0.0:25"
spool_dir = "/var/lib/mxhop/spool"

[domains."example.com".aliases]
noreply = { reject = "550 5.1.1 this address does not accept mail" }
"#;
        let c = load_str(src).expect("a reject entry should load");

        assert_eq!(
            c.router.route("example.com", "noreply"),
            Some(&Route::Reject(
                "550 5.1.1 this address does not accept mail".into()
            ))
        );
    }

    #[test]
    fn a_reject_reply_must_begin_with_a_status_code() {
        let src = r#"
hostname = "mx.example.com"
listen = "0.0.0.0:25"
spool_dir = "/var/lib/mxhop/spool"

[domains."example.com".aliases]
noreply = { reject = "go away" }
"#;
        let p = only_problem(src);
        assert!(
            p.contains("status code"),
            "the operator needs to know an SMTP reply starts with a number: {p}"
        );
        assert!(
            p.contains(&format!("line {}", line_with(src, "go away"))),
            "{p}"
        );
    }

    #[test]
    fn a_missing_key_is_reported() {
        let src = r#"
listen = "0.0.0.0:25"
spool_dir = "/var/lib/mxhop/spool"
"#;
        let found = problems(src);
        assert!(
            found.iter().any(|p| p.contains("hostname")),
            "the missing key should be named: {found:#?}"
        );
    }

    #[test]
    fn an_unknown_key_is_reported_with_its_line() {
        let src = r#"
hostname = "mx.example.com"
listen = "0.0.0.0:25"
spooldir = "/var/lib/mxhop/spool"
"#;
        let found = problems(src);
        assert!(
            found.iter().any(|p| p.contains("spooldir")),
            "a typo must not be silently ignored: {found:#?}"
        );
    }

    #[test]
    fn the_hostname_must_be_qualified() {
        let src = MINIMAL.replace("mx.example.com", "mx");
        let p = only_problem(&src);

        assert!(p.contains("hostname"), "{p}");
        assert!(
            p.contains(&format!("line {}", line_with(&src, "hostname"))),
            "{p}"
        );
    }

    #[test]
    fn listen_must_be_an_address_and_a_port() {
        let src = MINIMAL.replace("0.0.0.0:25", "25");
        let p = only_problem(&src);

        assert!(p.contains("listen"), "{p}");
        assert!(
            p.contains("0.0.0.0:25"),
            "the message should show the shape: {p}"
        );
    }

    #[test]
    fn the_spool_directory_must_be_absolute() {
        let src = MINIMAL.replace("/var/lib/mxhop/spool", "spool");
        let p = only_problem(&src);

        assert!(p.contains("absolute"), "{p}");
    }

    #[test]
    fn a_destination_must_be_an_address() {
        let src = MINIMAL.replace("me@gmail.com", "me-at-gmail.com");
        let p = only_problem(&src);

        assert!(p.contains("me-at-gmail.com"), "{p}");
        assert!(
            p.contains(&format!("line {}", line_with(&src, "me-at-gmail.com"))),
            "{p}"
        );
    }

    #[test]
    fn an_alias_needs_at_least_one_destination() {
        let src = MINIMAL.replace(r#"hi = "me@gmail.com""#, "hi = []");
        let p = only_problem(&src);

        assert!(p.contains("destination"), "{p}");
    }

    #[test]
    fn an_alias_name_that_can_never_match_is_reported() {
        let src = MINIMAL.replace(r#"hi = "me@gmail.com""#, r#""two words" = "me@gmail.com""#);
        let p = only_problem(&src);

        assert!(p.contains("never"), "{p}");
    }

    #[test]
    fn an_alias_can_name_the_server_to_deliver_to() {
        let src = r#"
hostname = "mx.dorokhovich.com"
listen = "0.0.0.0:25"
spool_dir = "/var/lib/mxhop/spool"

[domains."dorokhovich.com".aliases]
mikhail = { to = "mikhail@dorokhovich.com", via = "ASPMX.L.GOOGLE.COM" }
"*" = "mikhail@dorokhovich.com"
"#;
        let c = load_str(src).expect("a via target is a leaf, not a loop");
        let Some(Route::Via { to, host }) = c.router.route("dorokhovich.com", "mikhail") else {
            panic!("expected a via route");
        };
        assert_eq!(to.to_string(), "mikhail@dorokhovich.com");
        assert_eq!(host, "aspmx.l.google.com");
    }

    #[test]
    fn a_via_that_is_not_a_host_name_is_reported_with_its_line() {
        let src = r#"
hostname = "mx.dorokhovich.com"
listen = "0.0.0.0:25"
spool_dir = "/var/lib/mxhop/spool"

[domains."dorokhovich.com".aliases]
mikhail = { to = "mikhail@dorokhovich.com", via = "aspmx" }
"#;
        let found = problems(src);
        assert!(
            found.iter().any(|p| p.contains("not a fully qualified")),
            "{found:#?}"
        );
        assert_eq!(problem_line(&found[0]), line_with(src, "aspmx"));
    }

    #[test]
    fn a_via_pointing_at_this_host_is_reported() {
        let src = r#"
hostname = "mx.dorokhovich.com"
listen = "0.0.0.0:25"
spool_dir = "/var/lib/mxhop/spool"

[domains."dorokhovich.com".aliases]
mikhail = { to = "mikhail@dorokhovich.com", via = "MX.dorokhovich.com" }
"#;
        let found = problems(src);
        assert!(
            found.iter().any(|p| p.contains("is this host")),
            "{found:#?}"
        );
    }

    #[test]
    fn without_a_via_the_same_pair_is_still_refused_as_a_loop() {
        let src = r#"
hostname = "mx.dorokhovich.com"
listen = "0.0.0.0:25"
spool_dir = "/var/lib/mxhop/spool"

[domains."dorokhovich.com".aliases]
mikhail = "mikhail@dorokhovich.com"
"#;
        let found = problems(src);
        assert!(found.iter().any(|p| p.contains("loop")), "{found:#?}");
    }

    #[test]
    fn a_via_whose_address_is_not_an_address_is_reported() {
        let src = r#"
hostname = "mx.dorokhovich.com"
listen = "0.0.0.0:25"
spool_dir = "/var/lib/mxhop/spool"

[domains."dorokhovich.com".aliases]
mikhail = { to = "not-an-address", via = "aspmx.l.google.com" }
"#;
        let found = problems(src);
        assert!(found.iter().any(|p| p.contains("no @")), "{found:#?}");
    }

    #[test]
    fn via_hosts_names_every_alias_that_uses_one() {
        let src = r#"
hostname = "mx.dorokhovich.com"
listen = "0.0.0.0:25"
spool_dir = "/var/lib/mxhop/spool"

[domains."dorokhovich.com".aliases]
mikhail = { to = "mikhail@dorokhovich.com", via = "aspmx.l.google.com" }
other = { to = "other@dorokhovich.ru", via = "aspmx.l.google.com" }
"*" = "mikhail@dorokhovich.com"
"#;
        let c = load_str(src).expect("loads");
        let hosts = c.router.via_hosts();
        assert_eq!(hosts.len(), 1);
        assert_eq!(
            hosts["aspmx.l.google.com"],
            vec!["mikhail@dorokhovich.com", "other@dorokhovich.com"]
        );
    }

    #[test]
    fn an_observe_block_is_optional_and_parses_an_address() {
        assert_eq!(load_str(MINIMAL).expect("loads").observe, None);

        let src = format!("{MINIMAL}\n[observe]\nlisten = \"127.0.0.1:9090\"\n");
        assert_eq!(
            load_str(&src).expect("loads").observe,
            Some("127.0.0.1:9090".parse().unwrap())
        );
    }

    #[test]
    fn an_observe_port_shared_with_smtp_is_refused() {
        let src = format!("{MINIMAL}\n[observe]\nlisten = \"0.0.0.0:25\"\n");
        let found = problems(&src);

        assert!(
            found.iter().any(|p| p.contains("where SMTP listens")),
            "an unauthenticated metrics endpoint on the mail port would answer \
             anyone who connects: {found:#?}"
        );
    }

    #[test]
    fn an_observe_listen_that_is_not_an_address_is_reported_with_its_line() {
        let src = format!("{MINIMAL}\n[observe]\nlisten = \"9090\"\n");
        let found = problems(&src);

        assert!(
            found.iter().any(|p| p.contains("observe.listen")),
            "{found:#?}"
        );
        assert_eq!(problem_line(&found[0]), line_with(&src, "9090"));
    }

    #[test]
    fn a_domain_with_no_aliases_is_reported() {
        let src = r#"
hostname = "mx.example.com"
listen = "0.0.0.0:25"
spool_dir = "/var/lib/mxhop/spool"

[domains."example.com"]
"#;
        let p = only_problem(src);
        assert!(p.contains("no aliases"), "{p}");
    }

    #[test]
    fn a_configuration_serving_no_domains_is_refused() {
        let src = r#"
hostname = "mx.example.com"
listen = "0.0.0.0:25"
spool_dir = "/var/lib/mxhop/spool"
"#;
        let p = only_problem(src);
        assert!(
            p.contains("no domains"),
            "a forwarder with nothing to forward is a mistake, not a default: {p}"
        );
    }

    #[test]
    fn an_alias_loop_is_reported_with_its_line() {
        let src = r#"
hostname = "mx.example.com"
listen = "0.0.0.0:25"
spool_dir = "/var/lib/mxhop/spool"

[domains."example.com".aliases]
hi = "loop@example.com"
loop = "hi@example.com"
"#;
        let found = problems(src);
        assert!(
            found.iter().any(|p| p.contains("alias loop")),
            "the loop must be named: {found:#?}"
        );
        let line = line_with(src, "hi = ");
        assert!(
            found.iter().any(|p| p.contains(&format!("line {line}"))),
            "and pointed at: {found:#?}"
        );
        assert_eq!(found.len(), 1, "once, not once per alias on it: {found:#?}");
    }

    #[test]
    fn a_chain_that_ends_in_a_refusal_is_not_a_loop() {
        let src = r#"
hostname = "mx.example.com"
listen = "0.0.0.0:25"
spool_dir = "/var/lib/mxhop/spool"

[domains."first.example".aliases]
a = "b@second.example"
c = { reject = "550 5.1.1 no mail here" }

[domains."second.example".aliases]
b = "c@first.example"
"#;
        load_str(src).expect("a -> b -> c -> refused is a decision, not a loop");
    }

    #[test]
    fn a_loop_through_a_second_domain_is_found() {
        let src = r#"
hostname = "mx.example.com"
listen = "0.0.0.0:25"
spool_dir = "/var/lib/mxhop/spool"

[domains."first.example".aliases]
a = "b@second.example"

[domains."second.example".aliases]
b = "a@first.example"
"#;
        let found = problems(src);
        assert!(
            found.iter().any(|p| p.contains("alias loop")),
            "crossing a domain boundary does not make it less of a loop: {found:#?}"
        );
    }

    #[test]
    fn an_internal_hop_that_leaves_in_the_end_is_fine() {
        let src = r#"
hostname = "mx.example.com"
listen = "0.0.0.0:25"
spool_dir = "/var/lib/mxhop/spool"

[domains."example.com".aliases]
hi = "team@example.com"
team = ["a@gmail.com", "b@fastmail.com"]
"#;
        let c = load_str(src).expect("one internal hop is legitimate");
        assert!(c.router.route("example.com", "hi").is_some());
    }

    #[test]
    fn a_local_destination_with_no_alias_is_reported() {
        let src = MINIMAL.replace("me@gmail.com", "ghost@example.com");
        let p = only_problem(&src);

        assert!(
            p.contains("ghost@example.com"),
            "mail to it would be refused at our own door: {p}"
        );
        assert!(p.contains("no alias"), "{p}");
    }

    #[test]
    fn a_catch_all_makes_an_internal_destination_routable() {
        let src = r#"
hostname = "mx.example.com"
listen = "0.0.0.0:25"
spool_dir = "/var/lib/mxhop/spool"

[domains."example.com".aliases]
hi = "anything@other.example"
"*" = "catch@gmail.com"
"#;
        let c = load_str(src).expect("both aliases leave our domains");
        assert!(c.router.route("example.com", CATCH_ALL).is_some());
        assert!(c.router.route("example.com", "whoever").is_some());
    }

    #[test]
    fn a_catch_all_pointing_into_its_own_domain_is_a_loop() {
        let src = r#"
hostname = "mx.example.com"
listen = "0.0.0.0:25"
spool_dir = "/var/lib/mxhop/spool"

[domains."example.com".aliases]
"*" = "anything@example.com"
"#;
        let found = problems(src);
        assert!(
            found.iter().any(|p| p.contains("alias loop")),
            "this one swallows every message forever: {found:#?}"
        );
    }

    #[test]
    fn every_problem_is_reported_not_just_the_first() {
        let src = r#"
hostname = "mx"
listen = "25"
spool_dir = "spool"

[domains."example.com".aliases]
hi = "me-at-gmail.com"
"#;
        let found = problems(src);
        assert!(
            found.len() >= 4,
            "four things are wrong here and one run of `check` should say so: {found:#?}"
        );
    }

    #[test]
    fn problems_come_out_in_file_order() {
        let src = r#"
hostname = "mx"
listen = "25"
spool_dir = "spool"

[domains."example.com".aliases]
hi = "me-at-gmail.com"
"#;
        let found = problems(src);
        let lines: Vec<usize> = found
            .iter()
            .filter_map(|p| p.strip_prefix("line "))
            .filter_map(|p| p.split(':').next())
            .filter_map(|n| n.parse().ok())
            .collect();
        let mut sorted = lines.clone();
        sorted.sort_unstable();
        assert_eq!(
            lines, sorted,
            "reading top to bottom is how a file is fixed"
        );
    }

    #[test]
    fn the_message_limit_can_be_set() {
        let after_a_table_header = format!("{MINIMAL}\nmax_message_bytes = 1048576\n");
        assert!(
            load_str(&after_a_table_header).is_err(),
            "a key written after a table header belongs to that table, and TOML — \
             not mxhop — is what refuses it"
        );

        let src = MINIMAL.replace(
            r#"spool_dir = "/var/lib/mxhop/spool""#,
            "spool_dir = \"/var/lib/mxhop/spool\"\nmax_message_bytes = 1048576",
        );
        let c = load_str(&src).expect("the limit should load");
        assert_eq!(c.max_message_bytes, 1_048_576);
    }

    #[test]
    fn a_message_limit_of_zero_is_refused() {
        let src = MINIMAL.replace(
            r#"spool_dir = "/var/lib/mxhop/spool""#,
            "spool_dir = \"/var/lib/mxhop/spool\"\nmax_message_bytes = 0",
        );
        let p = only_problem(&src);
        assert!(p.contains("max_message_bytes"), "{p}");
    }

    #[test]
    fn broken_toml_is_reported_as_one_problem_with_its_line() {
        let src = "hostname = \"mx.example.com\"\nlisten = \n";
        let found = problems(src);
        assert_eq!(found.len(), 1, "{found:#?}");
        assert!(found[0].contains("line 2"), "{}", found[0]);
    }

    #[test]
    fn a_file_that_is_not_there_says_so() {
        let found = load_file(Path::new("/nonexistent/mxhop.toml")).unwrap_err();
        assert_eq!(found.len(), 1);
        assert!(found[0].message.contains("cannot be read"), "{found:#?}");
        assert_eq!(found[0].line, None, "there is no line to point at");
    }

    #[test]
    fn a_tls_block_is_optional() {
        let c = load_str(MINIMAL).expect("minimal configuration should load");
        assert!(c.tls.is_none());
    }

    #[test]
    fn a_tls_block_is_read_with_the_line_it_is_on() {
        let src = format!(
            "{MINIMAL}\n[tls]\ncertificate = \"/etc/ssl/mx.crt\"\nkey = \"/etc/ssl/mx.key\"\n"
        );
        let c = load_str(&src).expect("a tls block should load");
        let tls = c.tls.expect("tls should be configured");

        assert_eq!(tls.certificate, PathBuf::from("/etc/ssl/mx.crt"));
        assert_eq!(tls.key, PathBuf::from("/etc/ssl/mx.key"));
        assert_eq!(
            tls.line,
            Some(line_with(&src, "[tls]")),
            "a file problem found later has to be reportable at a line"
        );
    }

    #[test]
    fn tls_paths_must_be_absolute() {
        let src = format!("{MINIMAL}\n[tls]\ncertificate = \"mx.crt\"\nkey = \"mx.key\"\n");
        let found = problems(&src);

        assert_eq!(found.len(), 2, "both paths are wrong: {found:#?}");
        assert!(found[0].contains("tls.certificate"), "{}", found[0]);
        assert!(found[0].contains("read again on SIGHUP"), "{}", found[0]);
        assert!(found[1].contains("tls.key"), "{}", found[1]);
    }

    #[test]
    fn a_tls_block_needs_both_files() {
        let src = format!("{MINIMAL}\n[tls]\ncertificate = \"/etc/ssl/mx.crt\"\n");
        let p = only_problem(&src);

        assert!(
            p.contains("key"),
            "a certificate without its key cannot serve a handshake: {p}"
        );
    }

    const SRS: &str = "\n[srs]\ndomain = \"srs.example.com\"\nsecret_file = \"/run/srs.key\"\n";

    #[test]
    fn an_srs_block_loads_with_the_default_window() {
        let src = format!("{MINIMAL}{SRS}");
        let c = load_str(&src).expect("an srs block should load");
        let srs = c.srs.expect("srs should be configured");

        assert_eq!(srs.domain, "srs.example.com");
        assert_eq!(srs.secret_file, PathBuf::from("/run/srs.key"));
        assert_eq!(srs.max_age_days, crate::srs::DEFAULT_MAX_AGE_DAYS);
        assert_eq!(
            srs.line,
            Some(line_with(&src, "[srs]")),
            "a secret file problem found later has to be reportable at a line"
        );
    }

    #[test]
    fn check_refuses_an_srs_domain_that_also_has_aliases() {
        let src = "
hostname = \"mx.example.com\"
listen = \"0.0.0.0:25\"
spool_dir = \"/var/lib/mxhop/spool\"

[srs]
domain = \"srs.example.com\"
secret_file = \"/run/srs.key\"

[domains.\"srs.example.com\".aliases]
hi = \"me@gmail.com\"
";
        let p = only_problem(src);

        assert!(p.contains("srs.example.com"), "{p}");
        assert!(
            p.contains("[domains]"),
            "the operator has to be told which of the two to remove: {p}"
        );
    }

    #[test]
    fn the_srs_domain_has_to_be_a_domain_and_the_secret_file_absolute() {
        let src = format!("{MINIMAL}\n[srs]\ndomain = \"srs\"\nsecret_file = \"srs.key\"\n");
        let found = problems(&src);

        assert_eq!(found.len(), 2, "both are wrong: {found:#?}");
        assert!(
            found.iter().any(|p| p.contains("fully qualified")),
            "{found:#?}"
        );
        assert!(found.iter().any(|p| p.contains("absolute")), "{found:#?}");
    }

    #[test]
    fn an_srs_expiry_window_of_zero_days_is_refused() {
        let src = format!("{MINIMAL}{SRS}max_age_days = 0\n");
        let p = only_problem(&src);

        assert!(p.contains("max_age_days"), "{p}");
    }

    #[test]
    fn an_srs_expiry_window_longer_than_a_year_is_refused() {
        let src = format!("{MINIMAL}{SRS}max_age_days = 1022\n");
        let p = only_problem(&src);

        assert!(p.contains("max_age_days"), "{p}");
        assert!(
            p.contains("365"),
            "the refusal has to say what the ceiling is: {p}"
        );

        let src = format!("{MINIMAL}{SRS}max_age_days = 366\n");
        let p = only_problem(&src);
        assert!(p.contains("max_age_days"), "{p}");

        let src = format!("{MINIMAL}{SRS}max_age_days = 365\n");
        let c = load_str(&src).expect("a year is allowed, if unwise");
        assert_eq!(c.srs.expect("srs").max_age_days, 365);
    }

    #[test]
    fn an_srs_block_needs_both_the_domain_and_the_secret_file() {
        let src = format!("{MINIMAL}\n[srs]\ndomain = \"srs.example.com\"\n");
        let p = only_problem(&src);

        assert!(
            p.contains("secret_file"),
            "a domain with no key cannot sign anything: {p}"
        );
    }

    #[test]
    fn an_absent_auth_table_means_the_check_is_on_and_enforcing() {
        let c = load_str(MINIMAL).expect("minimal configuration should load");

        assert_eq!(
            c.auth,
            AuthSettings {
                enabled: true,
                enforce: Enforce::Dmarc,
            }
        );
    }

    #[test]
    fn auth_enforce_off_is_read_as_off() {
        let src = format!("{MINIMAL}\n[auth]\nenforce = \"off\"\n");
        let c = load_str(&src).expect("this should load");

        assert_eq!(c.auth.enforce, Enforce::Off);
        assert!(c.auth.enabled, "off is still evaluated and still stamped");
    }

    #[test]
    fn an_enforce_that_is_neither_word_is_refused_naming_both() {
        let src = format!("{MINIMAL}\n[auth]\nenforce = \"none\"\n");
        let problem = only_problem(&src);

        assert!(problem.contains("\"dmarc\""), "{problem}");
        assert!(problem.contains("\"off\""), "{problem}");
        assert_eq!(
            problem.lines().next().map(|l| l.starts_with("line")),
            Some(true),
            "with the line the operator typed it on: {problem}"
        );
    }

    #[test]
    fn enforce_together_with_enabled_false_is_refused() {
        let src = format!("{MINIMAL}\n[auth]\nenabled = false\nenforce = \"dmarc\"\n");
        let problem = only_problem(&src);

        assert!(problem.contains("no meaning"), "{problem}");
        assert!(problem.contains("enabled = false"), "{problem}");
    }

    #[test]
    fn auth_enabled_false_on_its_own_loads() {
        let src = format!("{MINIMAL}\n[auth]\nenabled = false\n");
        let c = load_str(&src).expect("this should load");

        assert!(!c.auth.enabled);
    }

    #[test]
    fn a_misspelled_auth_key_is_refused_rather_than_ignored() {
        let src = format!("{MINIMAL}\n[auth]\nenforced = \"off\"\n");

        assert!(
            !problems(&src).is_empty(),
            "a key nobody reads is a setting that silently does not apply"
        );
    }

    #[test]
    fn a_file_without_a_queue_table_gets_the_default_schedule() {
        let c = load_str(MINIMAL).expect("minimal configuration should load");

        assert_eq!(c.queue, Schedule::default());
    }

    #[test]
    fn a_queue_table_is_read_in_the_units_it_is_written_in() {
        let src = format!(
            "{MINIMAL}\n[queue]\nretry_minutes = [2, 7, 30]\nlifetime_hours = 12\n\
             sweep_seconds = 30\n"
        );

        let c = load_str(&src).expect("a queue table should load");

        assert_eq!(
            c.queue.retries,
            vec![
                Duration::from_secs(120),
                Duration::from_secs(420),
                Duration::from_secs(1_800)
            ]
        );
        assert_eq!(c.queue.lifetime, Duration::from_secs(12 * 3_600));
        assert_eq!(c.queue.sweep_interval, Duration::from_secs(30));
    }

    #[test]
    fn a_partly_stated_queue_table_keeps_the_defaults_for_the_rest() {
        let src = format!("{MINIMAL}\n[queue]\nsweep_seconds = 15\n");

        let c = load_str(&src).expect("a partial queue table should load");

        assert_eq!(c.queue.sweep_interval, Duration::from_secs(15));
        assert_eq!(c.queue.lifetime, Schedule::default().lifetime);
        assert_eq!(c.queue.retries, Schedule::default().retries);
    }

    #[test]
    fn an_empty_retry_list_is_refused() {
        let src = format!("{MINIMAL}\n[queue]\nretry_minutes = []\n");

        let problem = only_problem(&src);

        assert!(
            problem.contains("queue.retry_minutes must state at least one interval"),
            "{problem}"
        );
        assert_eq!(problem_line(&problem), line_with(&src, "retry_minutes"));
    }

    #[test]
    fn a_zero_in_the_retry_list_is_refused_and_the_message_names_it() {
        let src = format!("{MINIMAL}\n[queue]\nretry_minutes = [1, 0, 15]\n");

        let problem = only_problem(&src);

        assert!(problem.contains("must not contain 0"), "{problem}");
    }

    #[test]
    fn an_interval_longer_than_a_day_is_refused() {
        let src = format!("{MINIMAL}\n[queue]\nretry_minutes = [1, 5000]\n");

        let problem = only_problem(&src);

        assert!(problem.contains("must not contain 5000"), "{problem}");
        assert!(
            problem.contains("1440"),
            "the ceiling has to be in the message: {problem}"
        );
    }

    #[test]
    fn a_zero_lifetime_is_refused() {
        let src = format!("{MINIMAL}\n[queue]\nlifetime_hours = 0\n");

        let problem = only_problem(&src);

        assert!(
            problem.contains("queue.lifetime_hours must be at least 1"),
            "{problem}"
        );
        assert_eq!(problem_line(&problem), line_with(&src, "lifetime_hours"));
    }

    #[test]
    fn a_lifetime_of_months_is_refused() {
        let src = format!("{MINIMAL}\n[queue]\nlifetime_hours = 2000\n");

        let problem = only_problem(&src);

        assert!(problem.contains("must be at most 720"), "{problem}");
    }

    #[test]
    fn a_sweep_slower_than_an_hour_is_refused() {
        let src = format!("{MINIMAL}\n[queue]\nsweep_seconds = 7200\n");

        let problem = only_problem(&src);

        assert!(
            problem.contains("queue.sweep_seconds must be at most 3600"),
            "{problem}"
        );
    }

    #[test]
    fn a_lifetime_longer_than_the_srs_window_is_refused() {
        let src = format!("{MINIMAL}{SRS}max_age_days = 1\n[queue]\nlifetime_hours = 48\n");

        let problem = only_problem(&src);

        assert!(
            problem.contains("must not exceed srs.max_age_days"),
            "{problem}"
        );
        assert_eq!(problem_line(&problem), line_with(&src, "lifetime_hours"));
    }

    #[test]
    fn the_defaults_fit_inside_the_default_srs_window() {
        let src = format!("{MINIMAL}{SRS}");

        let c = load_str(&src).expect("the two defaults have to fit inside one another");

        assert_eq!(c.queue.lifetime, Duration::from_secs(48 * 3_600));
    }

    #[test]
    fn an_unknown_key_in_the_queue_table_is_refused() {
        let src = format!("{MINIMAL}\n[queue]\nretry_forever = true\n");

        let problem = only_problem(&src);

        assert!(problem.contains("retry_forever"), "{problem}");
    }
}
