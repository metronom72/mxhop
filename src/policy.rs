//! Who gets a copy, and what the sending server is told.
//!
//! Everything here is a pure function: an envelope, the alias table and what
//! the message's own first header block says go in, a decision comes out.
//! There is no clock, no socket and no disk in this file on purpose — every
//! rule about who a message is copied to, and every rule about which reply a
//! stranger's mail server reads, is then decided by something a test can call
//! directly instead of by something a test has to simulate a network for.

use std::collections::BTreeSet;

use crate::envelope::Envelope;
use crate::routing::{Mailbox, Route, Router, is_qualified};
use crate::smtp::client::{self, Outcome, Reply};

/// The bounds mxhop puts on a message's trace, and on its own alias table.
#[derive(Debug, Clone)]
pub struct Limits {
    /// How many `Received` headers a message may already carry.
    pub max_received: usize,
    /// How many of those may name this host.
    pub max_by_us: usize,
    /// How deep an alias may point at another of our own domains.
    pub max_internal_depth: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            // Postfix allows 50 and Exim 25. 25 is the right one for a
            // forwarder: a forwarder's own job adds a hop to somebody else's
            // path, so the loop it is likeliest to be part of is short and
            // fast (us → Gmail → a filter → us), and the cost of stopping one
            // hop early is one unusual message refused with an explanation
            // rather than a mail storm between two hosts. This was a
            // judgement call, not a specified number.
            max_received: 25,
            // Three, not one: a message legitimately passing through this
            // host twice is conceivable (a list that expands to a second of
            // our aliases), and three sightings of our own name cannot be.
            max_by_us: 3,
            // `config::check` already refuses a table with a loop in it, so
            // this bound should never be reached. It exists because the table
            // may be reloadable at runtime later, and a bound is cheaper than
            // trusting that whatever installed the table had validated it.
            max_internal_depth: 8,
        }
    }
}

/// What the message's own first header block says about where it has been.
///
/// Headers are the sender's claims rather than facts, which is why this is a
/// separate input: the rules below are about what the trace *claims*, and a
/// forged claim can only make mxhop more cautious, never less.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Head {
    pub received_count: usize,
    pub by_us_count: usize,
}

impl Head {
    /// Reads the first header block of a message as it arrived.
    ///
    /// Stops at the blank line that ends the headers: a `Received:` line in
    /// the body belongs to a forwarded copy somebody pasted, and counting it
    /// would refuse mail for a quotation.
    pub fn scan(message: &[u8], hostname: &str) -> Head {
        let mut head = Head::default();
        let hostname = hostname.to_ascii_lowercase();

        for line in HeaderLines::new(message) {
            let line = line.to_ascii_lowercase();
            if !line.starts_with("received:") {
                continue;
            }
            head.received_count += 1;
            // Deliberately loose: anywhere in the header, not only after
            // `by`. A sender can forge a mention of us, but forging one can
            // only get its own message refused.
            if line.contains(&hostname) {
                head.by_us_count += 1;
            }
        }
        head
    }
}

/// The header block, one unfolded header per item.
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
            // Folded continuations belong to the header above them, so they
            // are joined rather than counted: a `Received` header spread over
            // four lines is one hop, not four.
            let next_is_continuation = matches!(self.rest.first(), Some(b' ' | b'\t'));
            let Some(line) = self.next_line() else {
                self.done = true;
                break;
            };
            if line.is_empty() && header.is_empty() {
                // The blank line that ends the header block.
                self.done = true;
                return None;
            }
            header.push_str(&String::from_utf8_lossy(line));
            if !next_is_continuation {
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

/// One domain's worth of recipients: one connection serves all of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub domain: String,
    pub recipients: Vec<Mailbox>,
}

/// Where this message goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub groups: Vec<Group>,
    /// The envelope sender to announce, unchanged. Rewriting it so that SPF
    /// passes at the destination is SRS, which is its own piece of work.
    pub sender: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Say this to the sending server and store nothing.
    Refuse(Reply),
    Deliver(Plan),
}

/// Turns one accepted envelope into the deliveries it means.
pub fn decide(envelope: &Envelope, router: &Router, head: &Head, limits: &Limits) -> Decision {
    // The trace is checked before the table, because a message in a loop is
    // not one whose recipients are interesting.
    if head.received_count >= limits.max_received {
        return Decision::Refuse(Reply {
            code: 554,
            enhanced: Some("5.4.6".into()),
            text: format!(
                "too many hops: the message already carries {} Received headers",
                head.received_count
            ),
        });
    }
    if head.by_us_count >= limits.max_by_us {
        return Decision::Refuse(Reply {
            code: 554,
            enhanced: Some("5.4.6".into()),
            // The host is not named here because `decide` is given no
            // hostname: the `Received` header this hop would have added names
            // it, and the sender's own trace shows it. Keeping the signature
            // free of configuration is worth more than the name in the text.
            text: "this message has already passed through this host".into(),
        });
    }

    let mut flat = Vec::new();
    for recipient in &envelope.to {
        // Every recipient here was accepted at RCPT time, so it parses; one
        // that does not is dropped rather than refusing the whole message for
        // the others.
        let Ok(mailbox) = Mailbox::parse(recipient) else {
            continue;
        };
        if expand(router, mailbox, 0, limits, &mut flat).is_err() {
            return Decision::Refuse(Reply {
                code: 550,
                enhanced: Some("5.4.6".into()),
                text: format!("the alias for {recipient} points in a circle"),
            });
        }
    }

    // One copy per mailbox. Two aliases on one envelope that lead to the same
    // address are two routes to one person, not two messages.
    let mut seen = BTreeSet::new();
    flat.retain(|mailbox| seen.insert(mailbox.clone()));

    if flat.is_empty() {
        return Decision::Refuse(Reply {
            code: 550,
            enhanced: Some("5.1.1".into()),
            text: "the alias expands to no deliverable mailbox".into(),
        });
    }

    // Grouped by domain, in the order the domains were first seen, so one
    // connection serves every recipient at that destination and the order is
    // reproducible for a test to assert on.
    let mut groups: Vec<Group> = Vec::new();
    for mailbox in flat {
        match groups.iter_mut().find(|g| g.domain == mailbox.domain()) {
            Some(group) => group.recipients.push(mailbox),
            None => groups.push(Group {
                domain: mailbox.domain().to_string(),
                recipients: vec![mailbox],
            }),
        }
    }

    Decision::Deliver(Plan {
        groups,
        // Unchanged: rewriting it so the destination's SPF check passes is
        // SRS, which is a separate piece of work. The null sender stays null
        // — a bounce that acquired a sender could be bounced again.
        sender: envelope.from.clone(),
    })
}

/// Hit when an alias chain is deeper than [`Limits::max_internal_depth`].
struct TooDeep;

/// Resolves one mailbox to the addresses mail actually leaves for.
///
/// An alias whose destination is one of our own domains is resolved here
/// rather than handed to our own MX record: delivering it would send the
/// message to this process, which would expand it on the next hop and spend a
/// `Received` header to do what a table lookup does.
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
        // A refusal is a refusal however it is reached: this branch of the
        // expansion is dropped, and the others still go.
        Some((_, Route::Reject(_))) | None => Ok(()),
    }
}

/// What one delivery attempt's results mean for the inbound session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// The single reply the sending server reads.
    pub reply: Reply,
    /// The recipients whose copy has not been delivered and has not been
    /// refused either, so the message has to be kept for them.
    pub hold: Vec<Mailbox>,
}

/// Collapses every destination's answer into the one reply SMTP allows.
///
/// `id` is the queue id, which goes into the acceptance so that the sending
/// server's log line and ours can be joined. The plan wrote this function as
/// `reply_for(&[Outcome])`; the id is the one thing it needs that the
/// outcomes do not carry.
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
        // Something arrived. The sending server must not be asked to send it
        // again, so the answer is 250 whatever happened to the rest.
        //
        // Deferred recipients are held here and are visible in `queue/` until
        // the retry-queue milestone picks them up. Permanently refused ones
        // are a known hole: the sender has been told 250 and cannot be told
        // otherwise, and only a DSN of our own could report the failure.
        // There is no DSN generator yet, so those copies are lost — logged at
        // error level by the caller, and not papered over here by pretending
        // a 550 is retryable.
        return Verdict {
            reply: Reply {
                code: 250,
                enhanced: Some("2.0.0".into()),
                text: format!("delivered as {id}"),
            },
            hold: deferred.iter().map(|(_, _, m)| (*m).clone()).collect(),
        };
    }

    // Nothing arrived, so nothing is stored: the sending server still holds
    // the message and is the right place for it to wait.
    let worth = |(_, reply, _): &(Option<&str>, &Reply, &Mailbox)| -> u8 {
        // Mirrors `client::Fail::worth`: the sentence worth relaying is the
        // destination's own, and a reply mxhop wrote for itself — which is
        // what the `mxhop:` marker means — says the least.
        match (reply.code >= 500, reply.text.starts_with("mxhop: ")) {
            (true, _) => 3,
            (false, false) => 2,
            (false, true) => 1,
        }
    };
    let best = refused
        .iter()
        .chain(deferred.iter())
        .max_by_key(|entry| worth(entry));

    let reply = match best {
        None => Reply {
            // No recipients at all. Not reachable from the session — a plan
            // with no groups is refused by `decide` — but a 451 is the safe
            // answer to "we do not know what happened".
            code: 451,
            enhanced: Some("4.4.1".into()),
            text: "mxhop: nothing was delivered and nothing said why".into(),
        },
        Some((host, reply, _)) => {
            let text = match host {
                // The destination's own words, attributed. Without the host
                // name the sender cannot tell our sentence from theirs.
                Some(host) if !reply.text.starts_with("mxhop: ") => {
                    format!("{host} said: {}", reply.text)
                }
                _ => reply.text.clone(),
            };
            if deferred.is_empty() {
                Reply {
                    code: reply.code,
                    enhanced: reply.enhanced.clone(),
                    text,
                }
            } else {
                // One recipient still undecided makes the whole message
                // retryable, even when the informative sentence came from a
                // permanent refusal — so the code is 4xx and the enhanced
                // code must not stay 5.x.x and contradict it.
                let enhanced = match &reply.enhanced {
                    Some(enhanced) if enhanced.starts_with('4') => enhanced.clone(),
                    _ => "4.4.1".to_string(),
                };
                Reply {
                    code: 451,
                    enhanced: Some(enhanced),
                    text,
                }
            }
        }
    };

    Verdict {
        reply,
        hold: Vec::new(),
    }
}

/// The facts of one hop, which become one `Received` header.
#[derive(Debug, Clone)]
pub struct Trace {
    /// What the client said in EHLO/HELO. A claim, and sanitised as one.
    pub helo: String,
    /// The peer's reverse DNS, when it has one.
    pub ptr: Option<String>,
    /// The peer's address, without a port.
    pub ip: String,
    /// This host's name.
    pub by: String,
    /// The queue id, which is how this hop is found in two logs at once.
    pub id: String,
    /// Whether the client said EHLO (`ESMTP`) rather than HELO (`SMTP`).
    pub esmtp: bool,
    /// Every envelope recipient. The `for` clause is written only when there
    /// is exactly one.
    pub recipients: Vec<String>,
    pub at_unix_ms: u64,
}

impl Trace {
    /// The header, CRLF-terminated, ready to be written in front of the
    /// stored message.
    pub fn header(&self) -> String {
        // Every piece of this that came from the other end of the connection
        // is either domain-shaped or replaced. A HELO name is whatever the
        // client typed, and a name with a CRLF in it copied in verbatim would
        // end this header and begin one of the client's own — a forged
        // `Received`, or an `Authentication-Results` the destination trusts.
        // That is the one security bug this header can carry.
        let helo = name_or_unknown(Some(&self.helo));
        let ptr = name_or_unknown(self.ptr.as_deref());
        let ip = match self.ip.parse::<std::net::IpAddr>() {
            Ok(ip) => ip.to_string(),
            Err(_) => "unknown".to_string(),
        };
        let proto = if self.esmtp { "ESMTP" } else { "SMTP" };

        let mut parts = vec![
            format!("Received: from {helo} ({ptr} [{ip}])"),
            // `(mxhop)` is the product, which is what an operator grepping a
            // destination's headers for our mail actually searches for.
            format!("by {} (mxhop) with {proto} id {}", self.by, self.id),
        ];
        // RFC 5321 §4.4 allows one `for`, and with several recipients each
        // copy would tell its reader who else received it — a disclosure the
        // sender never asked for.
        if let [only] = &self.recipients[..]
            && is_safe_address(only)
        {
            parts.push(format!("for <{only}>"));
        }
        // The `;` belongs immediately before the date, wherever the clauses
        // ended.
        let last = parts.len() - 1;
        parts[last].push(';');
        parts.push(email_date(self.at_unix_ms));

        // Folded with CRLF and whitespace: one logical header, however long.
        let mut header = parts.join("\r\n        ");
        header.push_str("\r\n");
        header
    }
}

/// A name fit to print in a trace, or `unknown`.
///
/// Anything that is not domain-shaped — an address literal, a bare
/// `localhost`, a name with a control character in it — becomes `unknown`
/// rather than being quoted: a reader of this header cannot tell a sanitised
/// name from a real one, so the only safe report is that there was none.
fn name_or_unknown(name: Option<&str>) -> String {
    match name {
        Some(name) if is_qualified(name) => name.to_string(),
        _ => "unknown".to_string(),
    }
}

/// Whether an envelope recipient can be written into a header as it stands.
fn is_safe_address(address: &str) -> bool {
    !address.is_empty()
        && address.len() <= 320
        && !address
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == '<' || c == '>')
}

/// An RFC 5322 date in UTC.
///
/// Written out rather than pulled in with a date crate: this is the only date
/// mxhop formats, and the arithmetic is Howard Hinnant's `civil_from_days`,
/// which is exact for every day in the range a clock can hold.
pub fn email_date(unix_ms: u64) -> String {
    const DAY: u64 = 86_400;
    let secs = unix_ms / 1_000;
    let days = (secs / DAY) as i64;
    let (hour, minute, second) = {
        let rest = secs % DAY;
        (rest / 3_600, (rest % 3_600) / 60, rest % 60)
    };

    // 1970-01-01 was a Thursday, which is where the weekday comes from.
    const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    let weekday = WEEKDAYS[(days.rem_euclid(7)) as usize];

    // Shift the epoch to 0000-03-01 so that a leap day is the last day of the
    // year instead of one in the middle of it.
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
        // An internal hop: this alias points back at one of our own domains.
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
            last_reply: None,
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

    /// Two aliases on one envelope that both lead to the same mailbox used to
    /// mean two connections and two copies in that mailbox — the recipient
    /// sees the duplicate, and there is no way for them to tell it was the
    /// alias table rather than the sender.
    #[test]
    fn one_recipient_two_aliases_gets_one_copy() {
        let plan = plan(decide(
            &envelope(&["hi@example.com", "team@example.com"]),
            &router(),
            &Head::default(),
            &Limits::default(),
        ));

        assert_eq!(
            mailboxes(&plan),
            vec!["a@gmail.test", "b@fast.test"],
            "a@gmail.test is reached by both aliases and must be sent one copy"
        );
    }

    /// Without expansion the message is handed to our own MX record, arrives
    /// back at this process, and either loops until the hop limit stops it or
    /// is refused as a relay.
    #[test]
    fn an_internal_hop_is_expanded_before_leaving() {
        let plan = plan(decide(
            &envelope(&["staff@example.com"]),
            &router(),
            &Head::default(),
            &Limits::default(),
        ));

        assert_eq!(mailboxes(&plan), vec!["a@gmail.test", "b@fast.test"]);
        assert!(
            plan.groups.iter().all(|g| g.domain != "example.com"),
            "nothing may leave addressed to a domain we are the MX for: {plan:?}"
        );
    }

    /// One connection per domain. Two recipients at the same destination sent
    /// over two connections double the destination's rate-limit accounting
    /// against us for no reason.
    #[test]
    fn recipients_are_grouped_by_destination_domain() {
        let plan = plan(decide(
            &envelope(&["team@example.com", "two@example.com"]),
            &router(),
            &Head::default(),
            &Limits::default(),
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

    /// A bounce is sent with `MAIL FROM:<>` so that it cannot itself be
    /// bounced. Giving it a sender on the way out means a bounce loop between
    /// two mail servers with us in the middle.
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
                &Limits::default()
            ))
            .sender,
            None
        );
    }

    /// The loop the alias table cannot see: our alias forwards to Gmail, and
    /// a filter there forwards back to another of our aliases. Nothing in the
    /// table is wrong, and the message goes round until something counts.
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

    /// The same loop seen from the other side, and the one that catches it
    /// sooner: our own name in the trace three times means we are the loop.
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

    /// A trace that does not mention us is counted but not blamed on us: a
    /// `by_us` test that matched any hostname would refuse ordinary mail.
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
            recipients: recipients.iter().map(|s| s.to_string()).collect(),
            at_unix_ms: 1_762_423_302_000,
        }
    }

    /// RFC 5321 §4.4 allows one `for`, and listing several recipients tells
    /// everyone who gets a copy who else did — a privacy leak the sender
    /// never asked for and cannot see.
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

    /// The one security bug this header can carry. A HELO name is whatever
    /// the client typed; typed with a CRLF in it and copied in verbatim, it
    /// ends our header and starts one of its own — a forged `Received`, or
    /// worse an `Authentication-Results` the destination believes.
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
        // Every line of the header is either the first one or a fold.
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

    /// The date is the one part of the header a human reads against their own
    /// clock, and an off-by-one in the civil-date arithmetic is invisible
    /// until somebody tries to order two messages by it.
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

    /// The whole point of a synchronous forwarder. If the sender reads our
    /// own words instead of Gmail's, the person who has mistyped an address
    /// is told "delivery failed" by a host they have never heard of, and
    /// Gmail's actual sentence — which says what to do — is lost.
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

    /// Deferred means nothing is known yet, and the sending server is still
    /// holding the message. Answering 250 and keeping it ourselves moves the
    /// retry responsibility onto a forwarder that has no retry queue yet.
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

    /// The case with no honest single answer. One of two recipients got the
    /// message, so the sender must not retransmit — which means 250 — and the
    /// other one's copy is ours to keep.
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
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            vec!["b@fast.test"]
        );
    }

    /// A permanent refusal in a mixed outcome is the known hole: the sender
    /// has been told 250, so only a DSN of our own could report it, and there
    /// is no DSN generator yet. It must not be held — retrying a 550 forever
    /// is worse — so it is dropped, loudly.
    #[test]
    fn a_refusal_in_a_mixed_outcome_is_not_held() {
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
    }

    /// When several destinations refuse, the sender gets one sentence. The
    /// one worth sending is the one that says something: a 550 from the
    /// destination beats a 451 we wrote ourselves.
    #[test]
    fn the_most_informative_refusal_is_the_one_relayed() {
        let verdict = reply_for(
            &[
                outcome(
                    "mx.a.test",
                    &[(
                        "a@gmail.test",
                        client::Verdict::Deferred(their(451, "4.4.1", "mxhop: nobody answered")),
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

        assert_eq!(
            verdict.reply.code, 451,
            "one deferral means the whole message is still retryable"
        );
        assert!(
            verdict.reply.text.contains("we do not like you"),
            "the destination's own sentence is the informative one: {}",
            verdict.reply
        );
    }

    #[test]
    fn a_plan_that_expands_to_nothing_is_refused_rather_than_silently_dropped() {
        let mut r = Router::default();
        // An alias pointing at one of our own local parts that has no route:
        // `config::check` catches this, and a reloaded table might not.
        r.insert("example.com", "hi", forward(&["ghost@example.com"]));

        match decide(
            &envelope(&["hi@example.com"]),
            &r,
            &Head::default(),
            &Limits::default(),
        ) {
            Decision::Refuse(reply) => assert_eq!(reply.code, 550),
            Decision::Deliver(plan) => panic!("nowhere to deliver, yet a plan: {plan:?}"),
        }
    }

    #[test]
    fn an_internal_hop_deeper_than_the_bound_is_refused() {
        let mut r = Router::default();
        // A cycle the table check would have refused. The bound is what keeps
        // this from being an infinite expansion in a long-running process.
        r.insert("example.com", "a", forward(&["b@example.com"]));
        r.insert("example.com", "b", forward(&["a@example.com"]));

        match decide(
            &envelope(&["a@example.com"]),
            &r,
            &Head::default(),
            &Limits::default(),
        ) {
            Decision::Refuse(reply) => assert_eq!(reply.code, 550),
            Decision::Deliver(plan) => panic!("a cycle expanded into a plan: {plan:?}"),
        }
    }

    /// An internal hop onto an address the table refuses has to drop that
    /// branch, not deliver it: `Route::Reject` is a refusal wherever it is
    /// reached from.
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
        ));
        assert_eq!(mailboxes(&plan), vec!["a@gmail.test"]);
    }
}
