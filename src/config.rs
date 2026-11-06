//! The configuration file, and every check that can be made on it before the
//! service starts listening.
//!
//! A typo in a mail forwarder's configuration is an outage that looks like
//! silence, so `mxhop check` reports *every* problem it can find, each with
//! the line it is on, rather than stopping at the first.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::net::SocketAddr;
use std::ops::Range;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde::de::{self, Deserializer};
use toml::Spanned;

use crate::routing::{CATCH_ALL, Mailbox, Route, Router, is_qualified};

/// Gmail's ceiling, and a sane default: a forwarder that accepts more than the
/// destination will take responsibility for mail it cannot hand over.
pub const DEFAULT_MAX_MESSAGE_BYTES: u64 = 25 * 1024 * 1024;

/// The configuration as the service uses it: parsed, checked, and with the
/// alias table turned into a [`Router`].
#[derive(Debug, Clone)]
pub struct Config {
    pub hostname: String,
    pub listen: SocketAddr,
    pub spool_dir: PathBuf,
    pub max_message_bytes: u64,
    pub router: Router,
    /// Where the certificate lives, when one is configured at all. Absent
    /// means plaintext only, which is a supported way to run an MX.
    pub tls: Option<TlsPaths>,
}

/// The two PEM files, and the line of the `[tls]` table so that a problem
/// found when they are *read* — which happens outside `load_str` — can still
/// be reported where the operator typed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsPaths {
    pub certificate: PathBuf,
    pub key: PathBuf,
    pub line: Option<usize>,
}

/// One thing wrong with the file, and where.
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

/// Reads and checks a configuration file.
pub fn load_file(path: &Path) -> Result<Config, Vec<Problem>> {
    match fs::read_to_string(path) {
        Ok(src) => load_str(&src),
        Err(e) => Err(vec![Problem {
            line: None,
            message: format!("cannot be read: {e}"),
        }]),
    }
}

/// Checks configuration already in memory. Every caller goes through here, so
/// the tests exercise exactly what the service does.
pub fn load_str(src: &str) -> Result<Config, Vec<Problem>> {
    let raw: Raw = match toml::from_str(src) {
        Ok(raw) => raw,
        // A file TOML itself cannot read has one problem worth reporting: that
        // one. Everything after it is guesswork.
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

    if raw.domains.is_empty() {
        problems.push(Problem {
            line: None,
            message: "no domains are configured, so there is nothing to forward".to_string(),
        });
    }

    let mut router = Router::default();
    // Where each alias entry sits, so a loop can be reported at its line, and
    // every local destination, to be checked once the table is whole.
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

    // A destination inside one of our own domains has to land on a real alias,
    // or the hop ends in our own 550.
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

    // Loops. Reported once per cycle, at the first entry that enters it.
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
        router,
        tls,
    })
}

// -------------------------------------------------------------- loop walking

struct Found {
    /// Every alias on the cycle, so the others are not reported again.
    nodes: Vec<(String, String)>,
    /// The cycle as an operator reads it.
    chain: Vec<String>,
}

/// Follows an alias through the table, hop by hop, and reports the first cycle
/// it walks into. Destinations outside our domains end the walk: once the mail
/// leaves, it is not our loop any more.
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

// -------------------------------------------------------------- small checks

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

// ------------------------------------------------------------------- sources

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

/// Best effort for things TOML table keys cannot carry a span for — a domain
/// header. Finds the first line mentioning the name; if the file is strange
/// enough that this misses, the problem is still reported, just without a
/// line.
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

// ---------------------------------------------------------------- raw shapes

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    hostname: Spanned<String>,
    listen: Spanned<String>,
    spool_dir: Spanned<PathBuf>,
    max_message_bytes: Option<Spanned<u64>>,
    #[serde(default)]
    domains: BTreeMap<String, RawDomain>,
    tls: Option<RawTls>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTls {
    certificate: Spanned<PathBuf>,
    key: Spanned<PathBuf>,
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
    Reject { reject: String },
}

impl<'de> Deserialize<'de> for RawTarget {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Shape {
            One(String),
            Many(Vec<String>),
            Reject { reject: String },
        }

        // serde's own message for a failed untagged enum says only that
        // nothing matched, which tells an operator nothing about what to type.
        match Shape::deserialize(d) {
            Ok(Shape::One(one)) => Ok(RawTarget::One(one)),
            Ok(Shape::Many(many)) => Ok(RawTarget::Many(many)),
            Ok(Shape::Reject { reject }) => Ok(RawTarget::Reject { reject }),
            Err(_) => Err(de::Error::custom(
                "an alias must be an address (\"me@example.com\"), a list of addresses, \
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

    /// The line a fixture's marker is on, so the tests never hand-count.
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

    /// TLS is opportunistic: an MX that refused plaintext would lose mail, and
    /// a configuration without a `[tls]` block has to stay a valid one.
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

    /// A relative path works at startup and then breaks on the first SIGHUP,
    /// because the reload reads it again from whatever directory systemd left
    /// the service in.
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
}
