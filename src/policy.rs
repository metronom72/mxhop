use std::collections::BTreeSet;

use tracing::{info, warn};

use crate::auth::{Auth, DmarcVerdict, Policy as AuthPolicy};
use crate::envelope::Envelope;
use crate::routing::{Mailbox, Route, Router, is_qualified};
use crate::smtp::client::{self, Outcome, Reply};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Enforce {
    #[default]
    Dmarc,
    Off,
}

#[derive(Debug, Clone)]
pub struct Limits {
    pub max_received: usize,
    pub max_by_us: usize,
    pub max_internal_depth: usize,
    pub enforce: Enforce,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_received: 25,
            max_by_us: 3,
            max_internal_depth: 8,
            enforce: Enforce::Dmarc,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Head {
    pub received_count: usize,
    pub by_us_count: usize,
}

impl Head {
    pub fn scan(message: &[u8], hostname: &str) -> Head {
        let mut head = Head::default();
        let hostname = hostname.to_ascii_lowercase();

        for line in HeaderLines::new(message) {
            let line = line.to_ascii_lowercase();
            if !line.starts_with("received:") {
                continue;
            }
            head.received_count += 1;
            if names_host(&line, &hostname) {
                head.by_us_count += 1;
            }
        }
        head
    }
}

fn names_host(line: &str, hostname: &str) -> bool {
    if hostname.is_empty() {
        return false;
    }
    let boundary = |c: Option<char>| match c {
        None => true,
        Some(c) => !(c.is_ascii_alphanumeric() || c == '-' || c == '.'),
    };
    line.match_indices(hostname).any(|(at, _)| {
        boundary(line[..at].chars().next_back())
            && boundary(line[at + hostname.len()..].chars().next())
    })
}

struct HeaderLines<'a> {
    rest: &'a [u8],
    done: bool,
}

impl<'a> HeaderLines<'a> {
    fn new(message: &'a [u8]) -> Self {
        Self {
            rest: message,
            done: false,
        }
    }

    fn next_line(&mut self) -> Option<&'a [u8]> {
        if self.rest.is_empty() {
            return None;
        }
        let end = self
            .rest
            .iter()
            .position(|b| *b == b'\n')
            .unwrap_or(self.rest.len());
        let line = &self.rest[..end];
        self.rest = self.rest.get(end + 1..).unwrap_or(&[]);
        Some(line.strip_suffix(b"\r").unwrap_or(line))
    }
}

impl Iterator for HeaderLines<'_> {
    type Item = String;

    fn next(&mut self) -> Option<String> {
        if self.done {
            return None;
        }
        let mut header = String::new();
        loop {
            let Some(line) = self.next_line() else {
                self.done = true;
                break;
            };
            if line.is_empty() && header.is_empty() {
                self.done = true;
                return None;
            }
            header.push_str(&String::from_utf8_lossy(line));
            if !matches!(self.rest.first(), Some(b' ' | b'\t')) {
                break;
            }
            header.push(' ');
        }
        if header.is_empty() {
            None
        } else {
            Some(header)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub domain: String,
    pub recipients: Vec<Mailbox>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub groups: Vec<Group>,
    pub sender: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Refuse(Reply),
    Deliver(Plan),
}

pub fn decide(
    envelope: &Envelope,
    router: &Router,
    head: &Head,
    limits: &Limits,
    auth: &Auth,
) -> Decision {
    if let Some(reply) = check_trace(head, limits) {
        return Decision::Refuse(reply);
    }

    if let Some(reply) = check_authentication(auth, limits.enforce) {
        return Decision::Refuse(reply);
    }

    let mut flat = Vec::new();
    for recipient in &envelope.to {
        let Ok(mailbox) = Mailbox::parse(recipient) else {
            warn!(
                recipient,
                id = %envelope.id,
                "this recipient was accepted at RCPT time and cannot be parsed here, \
                 so its copy is being dropped: RCPT and the alias table disagree \
                 about what an address is"
            );
            continue;
        };
        if expand(router, mailbox, 0, limits, &mut flat).is_err() {
            return Decision::Refuse(Reply {
                code: 550,
                enhanced: Some("5.4.6".into()),
                text: format!("the alias for {recipient} points in a circle"),
                lines: Vec::new(),
            });
        }
    }

    let mut seen = BTreeSet::new();
    flat.retain(|mailbox| seen.insert(mailbox.clone()));

    if flat.is_empty() {
        return Decision::Refuse(Reply {
            code: 550,
            enhanced: Some("5.1.1".into()),
            text: "the alias expands to no deliverable mailbox".into(),
            lines: Vec::new(),
        });
    }

    Decision::Deliver(Plan {
        groups: group_by_domain(flat),
        sender: envelope.from.clone(),
    })
}

pub fn group_by_domain(recipients: Vec<Mailbox>) -> Vec<Group> {
    let mut groups: Vec<Group> = Vec::new();
    for mailbox in recipients {
        match groups.iter_mut().find(|g| g.domain == mailbox.domain()) {
            Some(group) => group.recipients.push(mailbox),
            None => groups.push(Group {
                domain: mailbox.domain().to_string(),
                recipients: vec![mailbox],
            }),
        }
    }
    groups
}

pub fn check_trace(head: &Head, limits: &Limits) -> Option<Reply> {
    if head.received_count >= limits.max_received {
        return Some(Reply {
            code: 554,
            enhanced: Some("5.4.6".into()),
            text: format!(
                "too many hops: the message already carries {} Received headers",
                head.received_count
            ),
            lines: Vec::new(),
        });
    }
    if head.by_us_count >= limits.max_by_us {
        return Some(Reply {
            code: 554,
            enhanced: Some("5.4.6".into()),
            text: "this message has already passed through this host".into(),
            lines: Vec::new(),
        });
    }
    None
}

fn check_authentication(auth: &Auth, enforce: Enforce) -> Option<Reply> {
    if !auth.checked {
        return None;
    }

    if enforce == Enforce::Off {
        if let Some(reply) = authentication_reply(auth) {
            info!(
                domain = %auth.dmarc.from_domain,
                policy = ?auth.dmarc.policy,
                dmarc = ?auth.dmarc.result,
                code = reply.code,
                "enforce is off: this message would have been answered \
                 {} and was forwarded instead — {reply}",
                reply.code
            );
        }
        return None;
    }

    authentication_reply(auth)
}

pub(crate) fn authentication_reply(auth: &Auth) -> Option<Reply> {
    let domain = &auth.dmarc.from_domain;
    match (auth.dmarc.result, auth.dmarc.policy) {
        (DmarcVerdict::Fail, Some(AuthPolicy::Reject)) if auth.dkim_timed_out => Some(Reply {
            code: 451,
            enhanced: Some("4.7.1".into()),
            text: format!(
                "could not finish checking the signatures on this message from \
                 {domain}, which asks for failures to be rejected (p=reject); \
                 try again"
            ),
            lines: Vec::new(),
        }),

        (DmarcVerdict::Fail, Some(AuthPolicy::Reject)) => Some(Reply {
            code: 550,
            enhanced: Some("5.7.1".into()),
            text: format!(
                "message from {domain} fails DMARC and that domain asks for \
                 failures to be rejected"
            ),
            lines: Vec::new(),
        }),

        (DmarcVerdict::TempError, Some(AuthPolicy::Reject)) => Some(Reply {
            code: 451,
            enhanced: Some("4.7.1".into()),
            text: format!(
                "could not finish checking DMARC for {domain}, which asks for \
                 failures to be rejected (p=reject); try again"
            ),
            lines: Vec::new(),
        }),

        _ => None,
    }
}

struct TooDeep;

fn expand(
    router: &Router,
    mailbox: Mailbox,
    depth: usize,
    limits: &Limits,
    out: &mut Vec<Mailbox>,
) -> Result<(), TooDeep> {
    if !router.handles_domain(mailbox.domain()) {
        out.push(mailbox);
        return Ok(());
    }
    if depth >= limits.max_internal_depth {
        return Err(TooDeep);
    }
    match router.resolve(mailbox.domain(), mailbox.local()) {
        Some((_, Route::Forward(targets))) => {
            for target in targets.clone() {
                expand(router, target, depth + 1, limits, out)?;
            }
            Ok(())
        }
        Some((_, Route::Reject(_))) => Ok(()),
        None => {
            warn!(
                recipient = %mailbox,
                "an alias points at a local part of one of our own domains that has \
                 no route, so this copy is being dropped; the alias table disagrees \
                 with itself"
            );
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub reply: Reply,
    pub hold: Vec<(Mailbox, Reply)>,
    pub lost: Vec<(Mailbox, Reply)>,
}

pub fn reply_for(outcomes: &[Outcome], id: &str) -> Verdict {
    let mut accepted = 0usize;
    let mut deferred: Vec<(Option<&str>, &Reply, &Mailbox)> = Vec::new();
    let mut refused: Vec<(Option<&str>, &Reply, &Mailbox)> = Vec::new();

    for outcome in outcomes {
        let host = outcome.host.as_deref();
        for result in &outcome.results {
            match &result.verdict {
                client::Verdict::Accepted => accepted += 1,
                client::Verdict::Deferred(reply) => deferred.push((host, reply, &result.mailbox)),
                client::Verdict::Refused(reply) => refused.push((host, reply, &result.mailbox)),
            }
        }
    }

    if accepted > 0 {
        return Verdict {
            reply: Reply {
                code: 250,
                enhanced: Some("2.0.0".into()),
                text: format!("delivered as {id}"),
                lines: Vec::new(),
            },
            hold: deferred
                .iter()
                .map(|(_, reply, m)| ((*m).clone(), (*reply).clone()))
                .collect(),
            lost: refused
                .iter()
                .map(|(_, reply, m)| ((*m).clone(), (*reply).clone()))
                .collect(),
        };
    }

    let worth = |(_, reply, _): &(Option<&str>, &Reply, &Mailbox)| -> u8 {
        match (reply.code >= 500, reply.text.starts_with("mxhop: ")) {
            (true, _) => 3,
            (false, false) => 2,
            (false, true) => 1,
        }
    };
    let best = if deferred.is_empty() {
        refused.iter().max_by_key(|entry| worth(entry))
    } else {
        deferred.iter().max_by_key(|entry| worth(entry))
    };

    let reply = match best {
        None => Reply {
            code: 451,
            enhanced: Some("4.4.1".into()),
            text: "mxhop: nothing was delivered and nothing said why".into(),
            lines: Vec::new(),
        },
        Some((host, reply, _)) => {
            let relayed = match host {
                Some(host) if !reply.text.starts_with("mxhop: ") => {
                    (*reply).clone().attributed_to(host)
                }
                _ => (*reply).clone(),
            };
            if deferred.is_empty() {
                relayed
            } else {
                let enhanced = match &reply.enhanced {
                    Some(enhanced) if enhanced.starts_with('4') => enhanced.clone(),
                    _ => "4.4.1".to_string(),
                };
                Reply {
                    code: 451,
                    enhanced: Some(enhanced),
                    ..relayed
                }
            }
        }
    };

    Verdict {
        reply,
        hold: Vec::new(),
        lost: Vec::new(),
    }
}

#[derive(Debug, Clone)]
pub struct Trace {
    pub helo: String,
    pub ptr: Option<String>,
    pub ip: String,
    pub by: String,
    pub id: String,
    pub esmtp: bool,
    pub tls: bool,
    pub recipients: Vec<String>,
    pub at_unix_ms: u64,
}

impl Trace {
    pub fn header(&self) -> String {
        let helo = name_or_unknown(Some(&self.helo));
        let ptr = name_or_unknown(self.ptr.as_deref());
        let ip = match self.ip.parse::<std::net::IpAddr>() {
            Ok(ip) => ip.to_string(),
            Err(_) => "unknown".to_string(),
        };
        let proto = match (self.esmtp, self.tls) {
            (true, true) => "ESMTPS",
            (true, false) => "ESMTP",
            (false, _) => "SMTP",
        };

        let mut parts = vec![
            format!("Received: from {helo} ({ptr} [{ip}])"),
            format!("by {} (mxhop) with {proto} id {}", self.by, self.id),
        ];
        if let [only] = &self.recipients[..]
            && is_safe_address(only)
        {
            parts.push(format!("for <{only}>"));
        }
        let last = parts.len() - 1;
        parts[last].push(';');
        parts.push(email_date(self.at_unix_ms));

        let mut header = parts.join("\r\n        ");
        header.push_str("\r\n");
        header
    }
}

pub(crate) fn name_or_unknown(name: Option<&str>) -> String {
    match name {
        Some(name) if is_qualified(name) => name.to_string(),
        _ => "unknown".to_string(),
    }
}

pub(crate) fn is_safe_address(address: &str) -> bool {
    !address.is_empty()
        && address.len() <= 320
        && !address
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == '<' || c == '>')
}

pub fn email_date(unix_ms: u64) -> String {
    const DAY: u64 = 86_400;
    let secs = unix_ms / 1_000;
    let days = (secs / DAY) as i64;
    let (hour, minute, second) = {
        let rest = secs % DAY;
        (rest / 3_600, (rest % 3_600) / 60, rest % 60)
    };

    const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    let weekday = WEEKDAYS[(days.rem_euclid(7)) as usize];

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };

    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!(
        "{weekday}, {day:02} {} {year} {hour:02}:{minute:02}:{second:02} +0000",
        MONTHS[(month - 1) as usize]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn router() -> Router {
        let mut r = Router::default();
        r.insert("example.com", "hi", forward(&["a@gmail.test"]));
        r.insert(
            "example.com",
            "team",
            forward(&["a@gmail.test", "b@fast.test"]),
        );
        r.insert("example.com", "staff", forward(&["team@example.com"]));
        r.insert(
            "example.com",
            "two",
            forward(&["c@gmail.test", "d@fast.test"]),
        );
        r.insert(
            "example.com",
            "noreply",
            Route::Reject("550 5.1.1 no mail here".into()),
        );
        r
    }

    fn forward(to: &[&str]) -> Route {
        Route::Forward(to.iter().map(|m| Mailbox::parse(m).unwrap()).collect())
    }

    fn envelope(to: &[&str]) -> Envelope {
        Envelope {
            id: "0000001762400000-000001-1a2b".into(),
            from: Some("sender@elsewhere.test".into()),
            to: to.iter().map(|s| s.to_string()).collect(),
            helo: "mail.elsewhere.test".into(),
            peer: "198.51.100.7:40000".into(),
            received_at_unix_ms: 1_762_423_302_000,
            size: 10,
            received: String::new(),
            authentication_results: String::new(),
            last_reply: None,
            attempts: 0,
            next_attempt_unix_ms: 0,
        }
    }

    fn plan(decision: Decision) -> Plan {
        match decision {
            Decision::Deliver(plan) => plan,
            Decision::Refuse(reply) => panic!("expected a delivery plan, got {reply}"),
        }
    }

    fn mailboxes(plan: &Plan) -> Vec<String> {
        plan.groups
            .iter()
            .flat_map(|g| g.recipients.iter())
            .map(ToString::to_string)
            .collect()
    }

    #[test]
    fn one_recipient_two_aliases_gets_one_copy() {
        let plan = plan(decide(
            &envelope(&["hi@example.com", "team@example.com"]),
            &router(),
            &Head::default(),
            &Limits::default(),
            &Auth::not_checked(),
        ));

        assert_eq!(
            mailboxes(&plan),
            vec!["a@gmail.test", "b@fast.test"],
            "a@gmail.test is reached by both aliases and must be sent one copy"
        );
    }

    #[test]
    fn an_internal_hop_is_expanded_before_leaving() {
        let plan = plan(decide(
            &envelope(&["staff@example.com"]),
            &router(),
            &Head::default(),
            &Limits::default(),
            &Auth::not_checked(),
        ));

        assert_eq!(mailboxes(&plan), vec!["a@gmail.test", "b@fast.test"]);
        assert!(
            plan.groups.iter().all(|g| g.domain != "example.com"),
            "nothing may leave addressed to a domain we are the MX for: {plan:?}"
        );
    }

    #[test]
    fn recipients_are_grouped_by_destination_domain() {
        let plan = plan(decide(
            &envelope(&["team@example.com", "two@example.com"]),
            &router(),
            &Head::default(),
            &Limits::default(),
            &Auth::not_checked(),
        ));

        assert_eq!(plan.groups.len(), 2, "two domains, two groups: {plan:?}");
        let gmail = plan
            .groups
            .iter()
            .find(|g| g.domain == "gmail.test")
            .expect("a group for gmail.test");
        assert_eq!(
            gmail
                .recipients
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            vec!["a@gmail.test", "c@gmail.test"]
        );
    }

    #[test]
    fn the_null_sender_stays_null() {
        let bounce = Envelope {
            from: None,
            ..envelope(&["hi@example.com"])
        };

        assert_eq!(
            plan(decide(
                &bounce,
                &router(),
                &Head::default(),
                &Limits::default(),
                &Auth::not_checked()
            ))
            .sender,
            None
        );
    }

    #[test]
    fn a_received_count_over_the_limit_is_refused_554() {
        let head = Head {
            received_count: 25,
            by_us_count: 0,
        };
        let decision = decide(
            &envelope(&["hi@example.com"]),
            &router(),
            &head,
            &Limits::default(),
            &Auth::not_checked(),
        );

        match decision {
            Decision::Refuse(reply) => {
                assert_eq!(reply.code, 554);
                assert_eq!(reply.enhanced.as_deref(), Some("5.4.6"));
                assert!(reply.text.contains("hops"), "{reply}");
            }
            Decision::Deliver(plan) => panic!("a 25-hop message must not be relayed: {plan:?}"),
        }
    }

    #[test]
    fn our_own_hostname_three_times_is_a_loop() {
        let head = Head {
            received_count: 4,
            by_us_count: 3,
        };
        let decision = decide(
            &envelope(&["hi@example.com"]),
            &router(),
            &head,
            &Limits::default(),
            &Auth::not_checked(),
        );

        match decision {
            Decision::Refuse(reply) => {
                assert_eq!(reply.code, 554);
                assert_eq!(reply.enhanced.as_deref(), Some("5.4.6"));
                assert!(
                    reply.text.contains("already passed through"),
                    "the operator reading this has to know it is a loop and not a block: {reply}"
                );
            }
            Decision::Deliver(plan) => panic!("a message that has been here twice: {plan:?}"),
        }
    }

    #[test]
    fn a_trace_naming_somebody_else_is_not_us() {
        let message = b"Received: from a.test (a.test [10.0.0.1])\r\n\
                        \tby mx.elsewhere.test with ESMTP id 7\r\n\
                        Subject: hi\r\n\
                        \r\n\
                        Received: from forged.test by mx.test\r\n";
        let head = Head::scan(message, "mx.test");

        assert_eq!(
            head.received_count, 1,
            "one hop folded over two lines is one hop, and the body is not the header block"
        );
        assert_eq!(head.by_us_count, 0);
    }

    #[test]
    fn our_own_name_in_a_folded_by_clause_is_still_us() {
        let message = b"Received: from mail-ed1-f54.google.test (mail-ed1-f54.google.test\r\n\
                        \t[209.85.208.54])\r\n\
                        \tby mx.tooling.ninja (mxhop) with ESMTPS id 7\r\n\
                        \tfor <hi@example.com>; Thu, 06 Nov 2026 10:00:00 +0000\r\n\
                        Subject: hi\r\n\
                        \r\n\
                        body\r\n";
        let head = Head::scan(message, "mx.tooling.ninja");

        assert_eq!(head.received_count, 1, "four lines are one hop");
        assert_eq!(
            head.by_us_count, 1,
            "our own hostname sits on the third line of the fold, which is where \
             every real forwarder writes it"
        );
    }

    #[test]
    fn four_folded_hops_count_as_four() {
        let message = b"Received: from a.test (a.test [10.0.0.1])\r\n\
                        \tby mx.tooling.ninja (mxhop) with ESMTPS id 1;\r\n\
                        \tThu, 06 Nov 2026 10:00:00 +0000\r\n\
                        Received: from b.test (b.test [10.0.0.2])\r\n\
                        \tby mx.elsewhere.test with ESMTP id 2;\r\n\
                        \tThu, 06 Nov 2026 10:00:01 +0000\r\n\
                        Received: from c.test (c.test [10.0.0.3])\r\n\
                        \tby mx.tooling.ninja (mxhop) with ESMTPS id 3;\r\n\
                        \tThu, 06 Nov 2026 10:00:02 +0000\r\n\
                        Received: from d.test (d.test [10.0.0.4])\r\n\
                        \tby mx.other.test with ESMTP id 4;\r\n\
                        \tThu, 06 Nov 2026 10:00:03 +0000\r\n\
                        \r\n\
                        body\r\n";
        let head = Head::scan(message, "mx.tooling.ninja");

        assert_eq!(
            head,
            Head {
                received_count: 4,
                by_us_count: 2,
            }
        );
    }

    #[test]
    fn a_folded_last_header_does_not_let_the_body_count_as_a_trace() {
        let message = b"Received: from a.test by mx.elsewhere.test with ESMTP id 1\r\n\
                        Content-Type: multipart/mixed;\r\n\
                        \tboundary=\"----=_Part_1\"\r\n\
                        \r\n\
                        Here is the bounce you asked about:\r\n\
                        Received: from x.test by mx.tooling.ninja with ESMTP id 9\r\n\
                        Received: from y.test by mx.tooling.ninja with ESMTP id 8\r\n\
                        Received: from z.test by mx.tooling.ninja with ESMTP id 7\r\n";
        let head = Head::scan(message, "mx.tooling.ninja");

        assert_eq!(
            head,
            Head {
                received_count: 1,
                by_us_count: 0,
            },
            "the blank line ends the header block even when the header before it \
             was folded, or quoting a trace is enough to get a message refused"
        );
    }

    #[test]
    fn a_hostname_that_merely_contains_ours_is_not_ours() {
        let message = b"Received: from a.test\r\n\
                        \tby backup-mx.tooling.ninja with ESMTP id 1\r\n\
                        Received: from b.test\r\n\
                        \tby mx.tooling.ninja.example with ESMTP id 2\r\n\
                        \r\n\
                        body\r\n";
        let head = Head::scan(message, "mx.tooling.ninja");

        assert_eq!(head.received_count, 2);
        assert_eq!(
            head.by_us_count, 0,
            "neither host is this one, however much of our name is spelled inside it"
        );
    }

    #[test]
    fn a_trace_naming_us_is_counted_as_ours() {
        let message = b"Received: from a.test by mx.test with ESMTP id 7\r\n\r\nbody\r\n";
        let head = Head::scan(message, "MX.test");

        assert_eq!(head.received_count, 1);
        assert_eq!(head.by_us_count, 1, "the comparison is case-insensitive");
    }

    fn trace(helo: &str, recipients: &[&str]) -> Trace {
        Trace {
            helo: helo.into(),
            ptr: Some("mail.elsewhere.test".into()),
            ip: "198.51.100.7".into(),
            by: "mx.tooling.ninja".into(),
            id: "0000001762400000-000001-1a2b".into(),
            esmtp: true,
            tls: false,
            recipients: recipients.iter().map(|s| s.to_string()).collect(),
            at_unix_ms: 1_762_423_302_000,
        }
    }

    #[test]
    fn received_has_for_only_with_one_recipient() {
        let one = trace("mail.elsewhere.test", &["hi@example.com"]).header();
        assert!(one.contains("for <hi@example.com>;"), "{one}");

        let two = trace(
            "mail.elsewhere.test",
            &["hi@example.com", "team@example.com"],
        )
        .header();
        assert!(
            !two.contains("for <"),
            "two recipients means no for clause at all: {two}"
        );
        assert!(two.contains("ESMTP id"), "{two}");
    }

    #[test]
    fn a_helo_with_a_newline_cannot_forge_a_header() {
        let header = trace(
            "evil.test\r\nAuthentication-Results: mx.tooling.ninja; dkim=pass",
            &["hi@example.com"],
        )
        .header();

        assert!(
            !header
                .to_ascii_lowercase()
                .contains("authentication-results"),
            "a crafted HELO must not reach the header at all: {header:?}"
        );
        for line in header.trim_end_matches("\r\n").split("\r\n").skip(1) {
            assert!(
                line.starts_with(' ') || line.starts_with('\t'),
                "a continuation line has to be folded, not freestanding: {line:?}"
            );
        }
        assert!(
            header.starts_with("Received: from unknown ("),
            "a name that is not domain-shaped is reported as unknown: {header}"
        );
    }

    #[test]
    fn a_session_inside_tls_says_esmtps() {
        let encrypted = Trace {
            tls: true,
            ..trace("x.test", &["one@example.com"])
        };

        assert!(
            encrypted.header().contains("with ESMTPS id"),
            "{}",
            encrypted.header()
        );
        assert!(
            !trace("x.test", &["one@example.com"])
                .header()
                .contains("ESMTPS"),
            "and a plaintext session must not claim it"
        );
    }

    #[test]
    fn helo_says_smtp_when_the_client_said_helo() {
        let header = Trace {
            esmtp: false,
            ..trace("mail.elsewhere.test", &["hi@example.com"])
        }
        .header();

        assert!(header.contains("with SMTP id"), "{header}");
        assert!(!header.contains("ESMTP"), "{header}");
    }

    #[test]
    fn a_peer_without_reverse_dns_is_unknown_not_blank() {
        let header = Trace {
            ptr: None,
            ..trace("mail.elsewhere.test", &["hi@example.com"])
        }
        .header();

        assert!(
            header.contains("(unknown [198.51.100.7])"),
            "an empty bracket is unparseable to everything downstream: {header}"
        );
    }

    #[test]
    fn the_date_is_rfc_5322_in_utc() {
        assert_eq!(
            email_date(1_762_423_302_000),
            "Thu, 06 Nov 2025 10:01:42 +0000"
        );
        assert_eq!(email_date(0), "Thu, 01 Jan 1970 00:00:00 +0000");
        assert_eq!(
            email_date(1_709_164_800_000),
            "Thu, 29 Feb 2024 00:00:00 +0000",
            "a leap day, which is where this arithmetic goes wrong"
        );
    }

    fn mailbox(s: &str) -> Mailbox {
        Mailbox::parse(s).unwrap()
    }

    fn outcome(host: &str, results: &[(&str, client::Verdict)]) -> Outcome {
        Outcome {
            host: Some(host.to_string()),
            results: results
                .iter()
                .map(|(m, verdict)| client::RecipientResult {
                    mailbox: mailbox(m),
                    verdict: verdict.clone(),
                })
                .collect(),
        }
    }

    fn their(code: u16, enhanced: &str, text: &str) -> Reply {
        Reply {
            code,
            enhanced: Some(enhanced.to_string()),
            text: text.to_string(),
            lines: Vec::new(),
        }
    }

    #[test]
    fn all_accepted_is_250() {
        let verdict = reply_for(
            &[outcome(
                "mx.gmail.test",
                &[("a@gmail.test", client::Verdict::Accepted)],
            )],
            "an-id",
        );

        assert_eq!(verdict.reply.code, 250);
        assert_eq!(verdict.reply.enhanced.as_deref(), Some("2.0.0"));
        assert!(
            verdict.reply.text.contains("an-id"),
            "the id joins our log to the sender's: {}",
            verdict.reply
        );
        assert!(verdict.hold.is_empty());
    }

    #[test]
    fn all_refused_carries_the_destinations_text() {
        let verdict = reply_for(
            &[outcome(
                "gmail-smtp-in.l.google.test",
                &[(
                    "a@gmail.test",
                    client::Verdict::Refused(their(
                        550,
                        "5.1.1",
                        "The email account that you tried to reach does not exist.",
                    )),
                )],
            )],
            "an-id",
        );

        assert_eq!(verdict.reply.code, 550);
        assert_eq!(verdict.reply.enhanced.as_deref(), Some("5.1.1"));
        assert_eq!(
            verdict.reply.text,
            "gmail-smtp-in.l.google.test said: The email account that you tried to reach \
             does not exist."
        );
        assert!(verdict.hold.is_empty(), "a refusal is nobody's to retry");
    }

    #[test]
    fn all_deferred_is_451_and_nothing_is_held() {
        let verdict = reply_for(
            &[outcome(
                "mx.gmail.test",
                &[(
                    "a@gmail.test",
                    client::Verdict::Deferred(their(451, "4.4.1", "try later")),
                )],
            )],
            "an-id",
        );

        assert_eq!(verdict.reply.code, 451);
        assert_eq!(verdict.reply.enhanced.as_deref(), Some("4.4.1"));
        assert!(
            verdict.hold.is_empty(),
            "nothing is stored: the sender keeps it and retries"
        );
    }

    #[test]
    fn mixed_is_250_and_holds_the_rest() {
        let verdict = reply_for(
            &[
                outcome(
                    "mx.gmail.test",
                    &[("a@gmail.test", client::Verdict::Accepted)],
                ),
                outcome(
                    "mx.fast.test",
                    &[(
                        "b@fast.test",
                        client::Verdict::Deferred(their(451, "4.4.1", "come back")),
                    )],
                ),
            ],
            "an-id",
        );

        assert_eq!(verdict.reply.code, 250);
        assert_eq!(
            verdict
                .hold
                .iter()
                .map(|(mailbox, _)| mailbox.to_string())
                .collect::<Vec<_>>(),
            vec!["b@fast.test"]
        );
    }

    #[test]
    fn each_held_recipient_keeps_its_own_reason() {
        let verdict = reply_for(
            &[
                outcome(
                    "mx.gmail.test",
                    &[("a@gmail.test", client::Verdict::Accepted)],
                ),
                outcome(
                    "mx.fast.test",
                    &[(
                        "b@fast.test",
                        client::Verdict::Deferred(their(451, "4.3.2", "mailbox is busy")),
                    )],
                ),
                outcome(
                    "mx.slow.test",
                    &[(
                        "c@slow.test",
                        client::Verdict::Deferred(their(421, "4.4.5", "disk is full")),
                    )],
                ),
            ],
            "an-id",
        );

        assert_eq!(
            verdict
                .hold
                .iter()
                .map(|(mailbox, reply)| format!("{mailbox}: {reply}"))
                .collect::<Vec<_>>(),
            vec![
                "b@fast.test: 451 4.3.2 mailbox is busy",
                "c@slow.test: 421 4.4.5 disk is full",
            ]
        );
    }

    #[test]
    fn a_refusal_in_a_mixed_outcome_is_named_as_lost() {
        let verdict = reply_for(
            &[
                outcome(
                    "mx.gmail.test",
                    &[("a@gmail.test", client::Verdict::Accepted)],
                ),
                outcome(
                    "mx.fast.test",
                    &[(
                        "b@fast.test",
                        client::Verdict::Refused(their(550, "5.1.1", "no such user")),
                    )],
                ),
            ],
            "an-id",
        );

        assert_eq!(verdict.reply.code, 250);
        assert!(
            verdict.hold.is_empty(),
            "a permanently refused recipient is not retried, it is lost until DSNs exist"
        );
        assert_eq!(
            verdict
                .lost
                .iter()
                .map(|(mailbox, reply)| format!("{mailbox}: {reply}"))
                .collect::<Vec<_>>(),
            vec!["b@fast.test: 550 5.1.1 no such user"],
            "the recipient and the destination's own words, because this copy is \
             about to be thrown away and these are the only record of it"
        );
    }

    #[test]
    fn the_most_informative_refusal_is_the_one_relayed() {
        let verdict = reply_for(
            &[
                outcome(
                    "mx.a.test",
                    &[(
                        "a@gmail.test",
                        client::Verdict::Refused(their(550, "5.0.0", "mxhop: nobody answered")),
                    )],
                ),
                outcome(
                    "mx.b.test",
                    &[(
                        "b@fast.test",
                        client::Verdict::Refused(their(550, "5.7.1", "we do not like you")),
                    )],
                ),
            ],
            "an-id",
        );

        assert_eq!(verdict.reply.code, 550);
        assert!(
            verdict.reply.text.contains("we do not like you"),
            "the destination's own sentence is the informative one: {}",
            verdict.reply
        );
        assert!(
            verdict.reply.text.contains("mx.b.test said"),
            "and it is attributed, or the sender cannot tell our words from theirs: {}",
            verdict.reply
        );
    }

    #[test]
    fn a_downgraded_code_does_not_carry_a_permanent_sentence() {
        let verdict = reply_for(
            &[
                outcome(
                    "mx.a.test",
                    &[(
                        "a@gmail.test",
                        client::Verdict::Refused(their(550, "5.1.1", "no such user")),
                    )],
                ),
                outcome(
                    "mx.b.test",
                    &[(
                        "b@fast.test",
                        client::Verdict::Deferred(their(451, "4.3.2", "greylisted, come back")),
                    )],
                ),
            ],
            "an-id",
        );

        assert_eq!(verdict.reply.code, 451);
        assert!(
            verdict.reply.text.contains("greylisted"),
            "the sentence has to be one that a retry can satisfy: {}",
            verdict.reply
        );
        assert!(
            !verdict.reply.text.contains("no such user"),
            "the permanent sentence belongs to a recipient the sender cannot help \
             by retrying, and under a 451 it only contradicts the code: {}",
            verdict.reply
        );
    }

    #[test]
    fn a_plan_that_expands_to_nothing_is_refused_rather_than_silently_dropped() {
        let mut r = Router::default();
        r.insert("example.com", "hi", forward(&["ghost@example.com"]));

        match decide(
            &envelope(&["hi@example.com"]),
            &r,
            &Head::default(),
            &Limits::default(),
            &Auth::not_checked(),
        ) {
            Decision::Refuse(reply) => assert_eq!(reply.code, 550),
            Decision::Deliver(plan) => panic!("nowhere to deliver, yet a plan: {plan:?}"),
        }
    }

    #[test]
    fn an_internal_hop_deeper_than_the_bound_is_refused() {
        let mut r = Router::default();
        r.insert("example.com", "a", forward(&["b@example.com"]));
        r.insert("example.com", "b", forward(&["a@example.com"]));

        match decide(
            &envelope(&["a@example.com"]),
            &r,
            &Head::default(),
            &Limits::default(),
            &Auth::not_checked(),
        ) {
            Decision::Refuse(reply) => assert_eq!(reply.code, 550),
            Decision::Deliver(plan) => panic!("a cycle expanded into a plan: {plan:?}"),
        }
    }

    #[test]
    fn an_internal_hop_onto_a_rejected_address_is_dropped() {
        let mut r = Router::default();
        r.insert(
            "example.com",
            "both",
            forward(&["noreply@example.com", "a@gmail.test"]),
        );
        r.insert(
            "example.com",
            "noreply",
            Route::Reject("550 5.1.1 no mail here".into()),
        );

        let plan = plan(decide(
            &envelope(&["both@example.com"]),
            &r,
            &Head::default(),
            &Limits::default(),
            &Auth::not_checked(),
        ));
        assert_eq!(mailboxes(&plan), vec!["a@gmail.test"]);
    }

    use crate::auth::{Dkim, DkimVerdict, Dmarc, DmarcVerdict, Policy, Spf};

    fn verdict(from: &str, result: DmarcVerdict, policy: Option<Policy>) -> Auth {
        Auth {
            spf_mail: Spf::Fail,
            spf_helo: Spf::Fail,
            mail_from: Some("sender@elsewhere.test".into()),
            helo: Some("mail.elsewhere.test".into()),
            dkim: Vec::new(),
            dmarc: Dmarc {
                from_domain: from.to_string(),
                result,
                policy,
            },
            checked: true,
            dkim_timed_out: false,
        }
    }

    fn decided(auth: &Auth) -> Decision {
        decide(
            &envelope(&["hi@example.com"]),
            &router(),
            &Head::default(),
            &Limits::default(),
            auth,
        )
    }

    fn refusal(decision: Decision) -> Reply {
        match decision {
            Decision::Refuse(reply) => reply,
            Decision::Deliver(plan) => panic!("expected a refusal, got a plan: {plan:?}"),
        }
    }

    #[test]
    fn a_forged_from_of_a_reject_policy_domain_is_refused_550() {
        let reply = refusal(decided(&verdict(
            "paypal.test",
            DmarcVerdict::Fail,
            Some(Policy::Reject),
        )));

        assert_eq!(reply.code, 550);
        assert_eq!(reply.enhanced.as_deref(), Some("5.7.1"));
        assert!(
            reply.text.contains("paypal.test"),
            "the sender has to be told which domain, or the refusal is unactionable: {reply}"
        );
        assert!(
            reply.text.contains("DMARC"),
            "and why, so it is not read as a block on the connecting host: {reply}"
        );
    }

    #[test]
    fn a_dmarc_answer_that_never_came_defers_rather_than_refusing_or_accepting() {
        let reply = refusal(decided(&verdict(
            "paypal.test",
            DmarcVerdict::TempError,
            Some(Policy::Reject),
        )));

        assert_eq!(reply.code, 451, "{reply}");
        assert_eq!(reply.enhanced.as_deref(), Some("4.7.1"));
        assert!(reply.text.contains("paypal.test"), "{reply}");
        assert!(
            reply.text.contains("reject"),
            "the house rule is that a refusal names the domain *and* the \
             policy it is enforcing; this arm always has `p=reject` in hand, \
             so there is no excuse for leaving it out: {reply}"
        );
    }

    #[test]
    fn a_temperror_with_no_policy_in_hand_is_forwarded_with_temperror_in_the_header() {
        let auth = verdict("lame.test", DmarcVerdict::TempError, None);
        let decision = decided(&auth);

        assert!(
            matches!(decision, Decision::Deliver(_)),
            "a resolver that did not answer must not cost this message its \
             delivery: {decision:?}"
        );
        assert_eq!(
            auth.dmarc.result,
            DmarcVerdict::TempError,
            "and the finding is still reported honestly, so the header the \
             destination reads says `dmarc=temperror` rather than claiming a \
             pass we did not see"
        );
    }

    #[test]
    fn a_domain_with_no_dmarc_record_is_forwarded() {
        let decision = decided(&verdict("elsewhere.test", DmarcVerdict::None, None));

        assert!(
            matches!(decision, Decision::Deliver(_)),
            "a domain with no DMARC record has asked for nothing: {decision:?}"
        );
    }

    #[test]
    fn a_dmarc_record_that_cannot_be_read_is_forwarded() {
        let decision = decided(&verdict(
            "broken.test",
            DmarcVerdict::PermError,
            Some(Policy::Reject),
        ));

        assert!(matches!(decision, Decision::Deliver(_)), "{decision:?}");
    }

    #[test]
    fn a_quarantine_failure_is_forwarded_rather_than_refused() {
        let auth = verdict("shop.test", DmarcVerdict::Fail, Some(Policy::Quarantine));
        let decision = decided(&auth);

        assert!(matches!(decision, Decision::Deliver(_)), "{decision:?}");
        assert!(
            auth.header("mx.tooling.ninja")
                .contains("policy.dmarc=quarantine"),
            "and the destination is told, or the request is lost on the way: {}",
            auth.header("mx.tooling.ninja")
        );
    }

    #[test]
    fn a_failure_under_p_none_is_forwarded() {
        let decision = decided(&verdict(
            "gmail.test",
            DmarcVerdict::Fail,
            Some(Policy::None),
        ));

        assert!(matches!(decision, Decision::Deliver(_)), "{decision:?}");
    }

    #[test]
    fn an_spf_hardfail_with_an_aligned_dkim_pass_is_forwarded() {
        let auth = Auth {
            spf_mail: Spf::Fail,
            dkim: vec![Dkim {
                domain: "list.test".into(),
                selector: "s1".into(),
                b8: "AAAAAAAA".into(),
                result: DkimVerdict::Pass,
            }],
            ..verdict("list.test", DmarcVerdict::Pass, Some(Policy::Reject))
        };

        assert!(
            matches!(decided(&auth), Decision::Deliver(_)),
            "a DMARC pass is a pass however it was reached"
        );
    }

    #[test]
    fn an_spf_softfail_on_its_own_is_forwarded() {
        let auth = Auth {
            spf_mail: Spf::SoftFail,
            ..verdict("elsewhere.test", DmarcVerdict::None, None)
        };

        assert!(matches!(decided(&auth), Decision::Deliver(_)));
    }

    #[test]
    fn an_spf_hardfail_with_no_dmarc_record_is_forwarded_and_recorded() {
        let auth = Auth {
            spf_mail: Spf::Fail,
            ..verdict("elsewhere.test", DmarcVerdict::None, None)
        };

        assert!(matches!(decided(&auth), Decision::Deliver(_)));
        assert!(
            auth.header("mx.tooling.ninja").contains("spf=fail"),
            "{}",
            auth.header("mx.tooling.ninja")
        );
    }

    #[test]
    fn an_unchecked_signature_is_deferred_where_a_missing_one_is_refused() {
        let unsigned = verdict("paypal.test", DmarcVerdict::Fail, Some(Policy::Reject));
        let stalled = Auth {
            dkim_timed_out: true,
            ..verdict("paypal.test", DmarcVerdict::Fail, Some(Policy::Reject))
        };

        assert_eq!(
            authentication_reply(&unsigned).map(|reply| reply.code),
            Some(550)
        );
        assert_eq!(
            authentication_reply(&stalled).map(|reply| reply.code),
            Some(451),
            "a retry can fetch the key; a bounce cannot be taken back"
        );

        assert!(matches!(decided(&stalled), Decision::Refuse(_)));
    }

    #[test]
    fn a_temperror_under_p_none_is_forwarded() {
        let decision = decided(&verdict(
            "gmail.test",
            DmarcVerdict::TempError,
            Some(Policy::None),
        ));

        assert!(matches!(decision, Decision::Deliver(_)), "{decision:?}");
    }

    #[test]
    fn enforce_off_forwards_a_reject_failure_and_the_header_still_says_fail() {
        let auth = verdict("paypal.test", DmarcVerdict::Fail, Some(Policy::Reject));
        let decision = decide(
            &envelope(&["hi@example.com"]),
            &router(),
            &Head::default(),
            &Limits {
                enforce: Enforce::Off,
                ..Limits::default()
            },
            &auth,
        );

        assert!(matches!(decision, Decision::Deliver(_)), "{decision:?}");
        assert!(
            auth.header("mx.tooling.ninja").contains("dmarc=fail"),
            "the operator's choice does not make the header lie: {}",
            auth.header("mx.tooling.ninja")
        );
    }

    #[test]
    fn a_verdict_that_was_never_checked_refuses_nothing() {
        let decision = decided(&Auth::not_checked());

        assert!(matches!(decision, Decision::Deliver(_)), "{decision:?}");
    }

    #[test]
    fn a_message_with_two_from_domains_is_forwarded_as_a_permerror() {
        let decision = decided(&verdict("", DmarcVerdict::PermError, None));

        assert!(matches!(decision, Decision::Deliver(_)), "{decision:?}");
    }
}
