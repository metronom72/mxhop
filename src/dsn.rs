use std::fmt::Write as _;

use crate::auth::{Auth, DkimVerdict, Spf};
use crate::envelope::Envelope;
use crate::policy::email_date;
use crate::routing::{Mailbox, is_qualified};
use crate::smtp::client::Reply;

pub const MAILER_DAEMON: &str = "MAILER-DAEMON";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    Permanently,
    GaveUp,
}

impl Refused {
    fn sentence(self) -> &'static str {
        match self {
            Refused::Permanently => {
                "The destination refused it permanently, so it was not tried again."
            }
            Refused::GaveUp => {
                "It was retried until the queue's lifetime ran out and is not being \
                 tried again."
            }
        }
    }

    fn status(self, reply: &Reply) -> String {
        match reply.enhanced.as_deref() {
            Some(enhanced) if is_status(enhanced) => enhanced.to_string(),
            _ => match self {
                Refused::Permanently => "5.0.0".into(),
                Refused::GaveUp => "4.4.7".into(),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotSent {
    Suppressed(Suppressed),
    NotQueued(String),
}

impl std::fmt::Display for NotSent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotSent::Suppressed(why) => f.write_str(why.why()),
            NotSent::NotQueued(e) => write!(f, "it could not be written to the queue: {e}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suppressed {
    NullSender,
    Unauthenticated,
    SenderNotAnAddress,
}

impl Suppressed {
    pub fn why(self) -> &'static str {
        match self {
            Suppressed::NullSender => {
                "the envelope sender is null, and a bounce must never be bounced"
            }
            Suppressed::Unauthenticated => {
                "nothing proved the envelope sender is who it says it is, so a report \
                 would be mail sent to whoever was named in it"
            }
            Suppressed::SenderNotAnAddress => "the envelope sender is not an address",
        }
    }
}

pub fn recipient(envelope: &Envelope) -> Result<Mailbox, Suppressed> {
    let from = envelope.from.as_deref().ok_or(Suppressed::NullSender)?;
    if !envelope.sender_authenticated {
        return Err(Suppressed::Unauthenticated);
    }
    Mailbox::parse(from).map_err(|_| Suppressed::SenderNotAnAddress)
}

pub fn proves_sender(auth: &Auth, mail_from: Option<&str>) -> bool {
    let Some(domain) = mail_from.and_then(|from| from.rsplit_once('@')) else {
        return false;
    };
    let domain = domain.1.to_ascii_lowercase();

    if auth.spf_mail == Spf::Pass {
        return true;
    }

    auth.dkim.iter().any(|signature| {
        signature.result == DkimVerdict::Pass && aligned(&signature.domain, &domain)
    })
}

fn aligned(signing: &str, envelope: &str) -> bool {
    let signing = signing.to_ascii_lowercase();
    signing == envelope || envelope.ends_with(&format!(".{signing}"))
}

#[derive(Debug)]
pub struct Report {
    pub to: Mailbox,
    pub body: Vec<u8>,
}

pub fn report(
    envelope: &Envelope,
    failures: &[(Mailbox, Reply)],
    refused: Refused,
    hostname: &str,
    now_unix_ms: u64,
) -> Result<Report, Suppressed> {
    let to = recipient(envelope)?;
    let boundary = format!("mxhop-dsn-{}", envelope.id);
    let mut out = String::with_capacity(2048);

    let _ = write!(
        out,
        "From: Mail Delivery Subsystem <{MAILER_DAEMON}@{host}>\r\n\
         To: <{to}>\r\n\
         Subject: Undelivered mail returned to sender\r\n\
         Date: {date}\r\n\
         Auto-Submitted: auto-replied\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: multipart/report; report-type=delivery-status;\r\n\
         \tboundary=\"{boundary}\"\r\n\
         \r\n\
         --{boundary}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         \r\n\
         This is the mail system at {host}.\r\n\
         \r\n\
         A message you sent could not be delivered to one or more of its\r\n\
         recipients. {sentence}\r\n\
         \r\n",
        host = name_or_unknown(hostname),
        date = email_date(now_unix_ms),
        sentence = refused.sentence(),
    );

    for (mailbox, reply) in failures {
        let _ = write!(out, "<{mailbox}>: {}\r\n", one_line(reply));
    }

    let _ = write!(
        out,
        "\r\n\
         --{boundary}\r\n\
         Content-Type: message/delivery-status\r\n\
         \r\n\
         Reporting-MTA: dns; {host}\r\n\
         Arrival-Date: {arrived}\r\n",
        host = name_or_unknown(hostname),
        arrived = email_date(envelope.received_at_unix_ms),
    );

    for (mailbox, reply) in failures {
        let _ = write!(
            out,
            "\r\n\
             Final-Recipient: rfc822; {mailbox}\r\n\
             Action: failed\r\n\
             Status: {status}\r\n\
             Diagnostic-Code: smtp; {diagnostic}\r\n",
            status = refused.status(reply),
            diagnostic = one_line(reply),
        );
    }

    let _ = write!(
        out,
        "\r\n\
         --{boundary}\r\n\
         Content-Type: text/rfc822-headers\r\n\
         \r\n"
    );
    out.push_str(&envelope.received);
    out.push_str(&envelope.authentication_results);
    let _ = write!(out, "\r\n--{boundary}--\r\n");

    Ok(Report {
        to,
        body: out.into_bytes(),
    })
}

fn one_line(reply: &Reply) -> String {
    let text: String = reply
        .text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    match &reply.enhanced {
        Some(enhanced) if is_status(enhanced) => {
            format!("{} {} {}", reply.code, enhanced, text.trim())
        }
        _ => format!("{} {}", reply.code, text.trim()),
    }
}

fn is_status(s: &str) -> bool {
    let mut parts = s.split('.');
    let class = parts.next().filter(|p| p.len() == 1);
    let subject = parts.next().filter(|p| !p.is_empty() && p.len() <= 3);
    let detail = parts.next().filter(|p| !p.is_empty() && p.len() <= 3);
    parts.next().is_none()
        && matches!(class, Some("2" | "4" | "5"))
        && subject.is_some_and(|p| p.bytes().all(|b| b.is_ascii_digit()))
        && detail.is_some_and(|p| p.bytes().all(|b| b.is_ascii_digit()))
}

fn name_or_unknown(host: &str) -> &str {
    if is_qualified(host) { host } else { "unknown" }
}

pub async fn send(
    spool: &crate::spool::Spool,
    hostname: &str,
    original: &Envelope,
    failures: &[(Mailbox, Reply)],
    refused: Refused,
    now_unix_ms: u64,
) -> Result<String, NotSent> {
    let report =
        report(original, failures, refused, hostname, now_unix_ms).map_err(NotSent::Suppressed)?;
    let id = crate::spool::new_id();
    let envelope = Envelope {
        id: id.clone(),
        from: None,
        to: vec![report.to.to_string()],
        helo: hostname.to_string(),
        peer: "local".into(),
        received_at_unix_ms: now_unix_ms,
        size: report.body.len() as u64,
        received: String::new(),
        authentication_results: String::new(),
        last_reply: None,
        attempts: 0,
        next_attempt_unix_ms: 0,
        via: Default::default(),
        sender_authenticated: false,
        arc: String::new(),
    };

    spool
        .store(&envelope, &report.body)
        .await
        .map(|()| id)
        .map_err(|e| NotSent::NotQueued(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{Dkim, DkimVerdict};

    fn original(from: Option<&str>) -> Envelope {
        Envelope {
            id: "0000001762400000-000001-1a2b".into(),
            from: from.map(ToString::to_string),
            to: vec!["hi@example.com".into()],
            helo: "mail.elsewhere.test".into(),
            peer: "198.51.100.7:40000".into(),
            received_at_unix_ms: 1_762_400_000_000,
            size: 42,
            received: "Received: from mail.elsewhere.test by mx.test; today\r\n".into(),
            authentication_results: "Authentication-Results: mx.test; spf=pass\r\n".into(),
            last_reply: None,
            attempts: 3,
            next_attempt_unix_ms: 0,
            via: Default::default(),
            sender_authenticated: true,
            arc: String::new(),
        }
    }

    fn failure() -> Vec<(Mailbox, Reply)> {
        vec![(
            Mailbox::parse("me@gmail.test").unwrap(),
            Reply {
                code: 550,
                enhanced: Some("5.1.1".into()),
                text: "no such user".into(),
                lines: Vec::new(),
            },
        )]
    }

    fn text(envelope: &Envelope) -> String {
        String::from_utf8(
            report(
                envelope,
                &failure(),
                Refused::Permanently,
                "mx.tooling.ninja",
                1_762_400_600_000,
            )
            .expect("a report")
            .body,
        )
        .unwrap()
    }

    #[test]
    fn a_forged_envelope_gets_no_report() {
        let forged = Envelope {
            sender_authenticated: false,
            arc: String::new(),
            ..original(Some("victim@paypal.test"))
        };

        assert_eq!(
            report(
                &forged,
                &failure(),
                Refused::Permanently,
                "mx.tooling.ninja",
                0
            )
            .unwrap_err(),
            Suppressed::Unauthenticated
        );
    }

    #[test]
    fn a_bounce_is_never_bounced() {
        assert_eq!(
            report(
                &original(None),
                &failure(),
                Refused::GaveUp,
                "mx.tooling.ninja",
                0
            )
            .unwrap_err(),
            Suppressed::NullSender
        );
    }

    #[test]
    fn a_report_goes_to_the_envelope_sender_and_names_the_recipient_that_failed() {
        let body = text(&original(Some("sender@elsewhere.test")));

        assert!(body.contains("To: <sender@elsewhere.test>\r\n"), "{body}");
        assert!(
            body.contains("Final-Recipient: rfc822; me@gmail.test"),
            "{body}"
        );
        assert!(body.contains("Action: failed"), "{body}");
        assert!(body.contains("Status: 5.1.1"), "{body}");
        assert!(
            body.contains("Diagnostic-Code: smtp; 550 5.1.1 no such user"),
            "{body}"
        );
    }

    #[test]
    fn the_report_is_a_multipart_report_whose_parts_all_close() {
        let body = text(&original(Some("sender@elsewhere.test")));
        let boundary = "mxhop-dsn-0000001762400000-000001-1a2b";

        assert!(
            body.contains("Content-Type: multipart/report; report-type=delivery-status;"),
            "{body}"
        );
        assert_eq!(
            body.matches(&format!("--{boundary}\r\n")).count(),
            3,
            "three parts: the human one, the status one and the headers: {body}"
        );
        assert!(body.ends_with(&format!("--{boundary}--\r\n")), "{body}");
        assert!(
            body.contains("Content-Type: message/delivery-status"),
            "{body}"
        );
        assert!(body.contains("Content-Type: text/rfc822-headers"), "{body}");
    }

    #[test]
    fn the_report_carries_the_trace_of_the_message_it_is_about() {
        let body = text(&original(Some("sender@elsewhere.test")));

        assert!(
            body.contains("Received: from mail.elsewhere.test by mx.test; today"),
            "{body}"
        );
        assert!(
            body.contains("Authentication-Results: mx.test; spf=pass"),
            "{body}"
        );
    }

    #[test]
    fn giving_up_and_being_refused_are_told_apart() {
        let envelope = original(Some("sender@elsewhere.test"));
        let gave_up = String::from_utf8(
            report(&envelope, &failure(), Refused::GaveUp, "mx.test", 0)
                .unwrap()
                .body,
        )
        .unwrap();

        assert!(
            gave_up.contains("retried until the queue's lifetime ran out"),
            "{gave_up}"
        );
        assert!(
            text(&envelope).contains("refused it permanently"),
            "{}",
            text(&envelope)
        );
    }

    #[test]
    fn an_spf_pass_on_the_envelope_sender_is_enough() {
        let auth = Auth {
            spf_mail: Spf::Pass,
            ..Auth::default()
        };

        assert!(proves_sender(&auth, Some("sender@elsewhere.test")));
    }

    #[test]
    fn a_dkim_pass_for_somebody_elses_domain_proves_nothing_about_this_envelope() {
        let auth = Auth {
            spf_mail: Spf::Fail,
            dkim: vec![Dkim {
                domain: "newsletter.test".into(),
                selector: "s1".into(),
                b8: "AbCdEfGh".into(),
                result: DkimVerdict::Pass,
            }],
            ..Auth::default()
        };

        assert!(
            !proves_sender(&auth, Some("victim@paypal.test")),
            "a signature over the From header says nothing about who the report \
             would be sent to"
        );
        assert!(proves_sender(&auth, Some("bounce@newsletter.test")));
        assert!(proves_sender(&auth, Some("bounce@mail.newsletter.test")));
    }

    #[test]
    fn a_failing_check_proves_nothing() {
        assert!(!proves_sender(&Auth::default(), Some("a@b.test")));
        assert!(!proves_sender(
            &Auth {
                spf_mail: Spf::Pass,
                ..Auth::default()
            },
            None
        ));
    }

    #[test]
    fn a_reply_with_a_newline_in_it_cannot_add_a_header_to_the_report() {
        let envelope = original(Some("sender@elsewhere.test"));
        let crafted = vec![(
            Mailbox::parse("me@gmail.test").unwrap(),
            Reply {
                code: 550,
                enhanced: Some("5.1.1\r\nX-Forged: yes".into()),
                text: "no\r\nX-Also-Forged: yes".into(),
                lines: Vec::new(),
            },
        )];

        let body = String::from_utf8(
            report(&envelope, &crafted, Refused::Permanently, "mx.test", 0)
                .unwrap()
                .body,
        )
        .unwrap();

        assert!(!body.contains("\r\nX-Forged"), "{body}");
        assert!(!body.contains("\r\nX-Also-Forged"), "{body}");
        assert!(
            body.contains("Diagnostic-Code: smtp; 550 no  X-Also-Forged: yes\r\n"),
            "the destination's own words are quoted, on one line: {body}"
        );
        assert!(
            body.contains("Status: 5.0.0"),
            "a crafted enhanced code is not copied into the status: {body}"
        );
    }

    #[test]
    fn a_hostname_that_is_not_a_name_is_not_printed() {
        let envelope = original(Some("sender@elsewhere.test"));
        let body = String::from_utf8(
            report(
                &envelope,
                &failure(),
                Refused::Permanently,
                "mx\r\nX-Forged: yes",
                0,
            )
            .unwrap()
            .body,
        )
        .unwrap();

        assert!(!body.contains("X-Forged"), "{body}");
        assert!(body.contains("Reporting-MTA: dns; unknown"), "{body}");
    }
}
