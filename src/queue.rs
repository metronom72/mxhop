//! The retry queue: what happens to a message a destination deferred.
//!
//! A message reaches `queue/` only when it has already been accepted — the
//! sending server has been told `250` and will never send it again, so from
//! that moment the copy on this disk is the only one. Everything here follows
//! from that: nothing is deleted until a destination has either taken the
//! message or refused it for good, and when mxhop does give up it moves the
//! files to `frozen/` rather than removing them.
//!
//! The runner is a single task reading the queue from disk every
//! [`SWEEP_INTERVAL`]. From disk, and not from a list in memory, because
//! `queue/` is also the administration interface: an operator who moves an
//! envelope back out of `frozen/`, or edits a recipient in one, gets what
//! they asked for on the next sweep without restarting the service.
//!
//! One attempt at a time, in arrival order. A forwarder that opens a
//! connection per queued message is an amplifier pointed at whichever
//! destination is currently broken, and the queue is almost always backed up
//! for exactly one such destination.

use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, error, info, warn};

use crate::envelope::{Envelope, now_unix_ms};
use crate::policy;
use crate::routing::Mailbox;
use crate::smtp::client::{Delivery, Relay, Reply, Verdict};
use crate::spool::Spool;
use crate::srs::Srs;

/// The wait after the first failed attempt, and the step every later wait
/// doubles from.
///
/// Five minutes because the thing being waited out is usually a destination
/// under load or a greylist, and both clear in minutes; retrying sooner is
/// how a forwarder earns a rate limit of its own.
pub const FIRST_BACKOFF: Duration = Duration::from_secs(5 * 60);

/// The longest wait between two attempts. Doubling without a ceiling means a
/// message that has been stuck for a day waits another day, so the moment the
/// destination comes back is the moment nothing is delivered.
pub const MAX_BACKOFF: Duration = Duration::from_secs(2 * 60 * 60);

/// How long a message may stay in the queue before mxhop stops trying.
///
/// Four days rather than Postfix's five, and the reason is SRS: a forwarded
/// message leaves with a rewritten sender whose signature is only valid for
/// `srs.max_age_days` — seven by default — so a bounce provoked by the last
/// attempt has to arrive while that address still decodes. Four days of
/// attempts leaves three for the report to come back.
pub const LIFETIME: Duration = Duration::from_secs(4 * 24 * 60 * 60);

/// How often the queue is read from disk. The schedule lives in the
/// envelopes, so this is only the resolution of the clock that reads them.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// How long to wait before trying a message that has already been tried
/// `attempts` times.
///
/// Pure, and a function of nothing but the count, so that the envelope on
/// disk is the whole schedule: the runner can be restarted, or the machine
/// rebooted, without losing where a message was in it.
pub fn backoff(attempts: u32) -> Duration {
    // `attempts` is what has already been spent, so the first wait follows
    // one attempt. Zero means the same thing as one here — an envelope
    // written before this field existed — and gets the same five minutes.
    let doublings = attempts.saturating_sub(1).min(32);
    let seconds = FIRST_BACKOFF
        .as_secs()
        .saturating_mul(1u64 << doublings.min(16));
    Duration::from_secs(seconds.min(MAX_BACKOFF.as_secs()))
}

/// What one sweep did, for the log and for a test to assert on.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Swept {
    /// Messages whose next attempt is still in the future.
    pub waiting: usize,
    /// Messages attempted in this sweep.
    pub attempted: usize,
    /// Messages that left the queue because every remaining recipient was
    /// settled — delivered, or refused for good.
    pub settled: usize,
    /// Messages rescheduled: somebody is still deferring them.
    pub deferred: usize,
    /// Messages given up on and moved to `frozen/`.
    pub frozen: usize,
}

/// The queue runner: the spool, somewhere to deliver to, and the sender
/// rewriter if the deployment has one.
pub struct Runner<L> {
    spool: Arc<Spool>,
    relay: Arc<L>,
    srs: Option<Arc<Srs>>,
}

impl<L> Runner<L>
where
    L: Relay,
{
    pub fn new(spool: Arc<Spool>, relay: Arc<L>, srs: Option<Arc<Srs>>) -> Self {
        Self { spool, relay, srs }
    }

    /// Sweeps for as long as the process runs.
    pub async fn run(self) {
        loop {
            self.sweep().await;
            tokio::time::sleep(SWEEP_INTERVAL).await;
        }
    }

    /// One pass over the queue.
    pub async fn sweep(&self) -> Swept {
        let queued = match self.spool.queued().await {
            Ok(queued) => queued,
            // The queue directory has gone or cannot be read. Nothing here
            // can fix that, and giving up on the whole runner would mean a
            // mount that comes back to a service that has stopped looking.
            Err(e) => {
                warn!(
                    path = %self.spool.queue_dir().display(),
                    "the queue cannot be read, so nothing held is being retried \
                     right now: {e}"
                );
                return Swept::default();
            }
        };

        let mut swept = Swept::default();
        for envelope in queued {
            // Read inside the loop: one attempt can take minutes, and a
            // message that became due while an earlier one was being
            // delivered should go out in this sweep rather than the next.
            let now = now_unix_ms();

            if envelope.next_attempt_unix_ms > now {
                swept.waiting += 1;
                continue;
            }

            if expired(&envelope, now) {
                // Error level, not warning: this is mail that was accepted
                // and will not be delivered, and until mxhop can send a
                // delivery report of its own this line is the only notice
                // anybody gets.
                error!(
                    id = %envelope.id,
                    to = envelope.to.join(", "),
                    attempts = envelope.attempts,
                    days = LIFETIME.as_secs() / 86_400,
                    "giving up: this message has been in the queue longer than the \
                     retry lifetime and is being moved to frozen/, where it stays \
                     readable; nobody is told, because mxhop cannot send a delivery \
                     report yet: {}",
                    envelope.last_reply.as_deref().unwrap_or("no reason recorded")
                );
                match self.spool.freeze(&envelope.id).await {
                    Ok(()) => swept.frozen += 1,
                    Err(e) => warn!(
                        id = %envelope.id,
                        "this message could not be moved to frozen/, so it will be \
                         tried again next sweep: {e}"
                    ),
                }
                continue;
            }

            swept.attempted += 1;
            if self.attempt(&envelope).await {
                swept.settled += 1;
            } else {
                swept.deferred += 1;
            }
        }

        if swept != Swept::default() {
            debug!(
                waiting = swept.waiting,
                attempted = swept.attempted,
                settled = swept.settled,
                deferred = swept.deferred,
                frozen = swept.frozen,
                "queue swept"
            );
        }
        swept
    }

    /// One attempt at one message. `true` means it has left the queue.
    async fn attempt(&self, envelope: &Envelope) -> bool {
        let body = match self.spool.body(&envelope.id).await {
            Ok(body) => body,
            // An envelope whose message is gone can never be delivered, so
            // retrying it for ever would be a line in the log every minute
            // and nothing else. It is reported once and removed — which is
            // also what cleans up after a `forget` that failed half way.
            Err(e) => {
                error!(
                    id = %envelope.id,
                    to = envelope.to.join(", "),
                    "this envelope's message cannot be read, so it can never be \
                     delivered; the envelope is being removed: {e}"
                );
                if let Err(e) = self.spool.forget(&envelope.id).await {
                    warn!(id = %envelope.id, "and it could not be removed either: {e}");
                }
                return true;
            }
        };

        // The recipients on a held envelope are destinations, not the
        // addresses the sending server asked for: the alias table was
        // consulted before the message was ever stored, and consulting it
        // again here would re-expand an address that has since been pointed
        // somewhere else — delivering the message to somebody who was never
        // its recipient.
        let mut recipients = Vec::with_capacity(envelope.to.len());
        for address in &envelope.to {
            match Mailbox::parse(address) {
                Ok(mailbox) => recipients.push(mailbox),
                // Only reachable if somebody edited the envelope by hand,
                // which is a supported thing to do: the rest of the message
                // still goes.
                Err(e) => error!(
                    id = %envelope.id,
                    recipient = %address,
                    "this recipient is not an address mxhop can deliver to, so this \
                     copy is lost: {e}"
                ),
            }
        }
        if recipients.is_empty() {
            error!(
                id = %envelope.id,
                "nothing in this envelope can be delivered to; it is being moved to \
                 frozen/ rather than retried"
            );
            if let Err(e) = self.spool.freeze(&envelope.id).await {
                warn!(id = %envelope.id, "and it could not be moved: {e}");
            }
            return true;
        }

        // The sender the destination checks SPF against, rewritten with
        // today's date rather than the one the message arrived on: an SRS
        // address carries its own expiry, and a four-day-old one minted at
        // arrival would stop decoding while the message was still being
        // retried. Mirrors `session::hand_on`, quietly: everything it warns
        // about there was decided while the sending server still held the
        // message, and has been decided already by the time a message is
        // here.
        let sender = match (&self.srs, envelope.from.as_deref()) {
            (None, _) => envelope.from.clone(),
            // A bounce has nothing to rewrite and must acquire nothing: an
            // address in a bounce's envelope is an address that bounce can
            // itself be bounced to.
            (Some(_), None) => None,
            (Some(srs), Some(from)) => Some(
                srs.rewrite(Some(from), crate::srs::today())
                    .unwrap_or_else(|| from.to_string()),
            ),
        };

        // The trace as it was written when the message arrived, and the
        // findings as they were then. Both are kept on the envelope for this
        // moment: re-deriving them would claim a time the message did not
        // arrive at, and would mean asking DNS again — days later, about a
        // message whose sender's records may have changed since.
        let mut head = envelope.received.clone();
        head.push_str(&envelope.authentication_results);
        let body: Arc<[u8]> = body.into();

        let mut still_deferred: Vec<(Mailbox, Reply)> = Vec::new();
        let mut delivered = 0usize;
        let mut refused = 0usize;

        for group in policy::group_by_domain(recipients) {
            // One fresh budget per domain, unlike the inbound session, which
            // divides one budget between its groups: there nothing could be
            // allowed to outlast the sending server's patience, and here
            // there is no sending server waiting.
            let outcome = self
                .relay
                .deliver(Delivery::new(
                    sender.clone(),
                    group.recipients,
                    head.clone().into_bytes(),
                    Arc::clone(&body),
                ))
                .await;

            for result in outcome.results {
                match result.verdict {
                    Verdict::Accepted => {
                        delivered += 1;
                        info!(
                            id = %envelope.id,
                            recipient = %result.mailbox,
                            host = outcome.host.as_deref().unwrap_or("unknown"),
                            attempt = envelope.attempts + 1,
                            "delivered from the queue"
                        );
                    }
                    // Nobody is told. The sending server was answered `250`
                    // days ago, and there is no delivery report generator
                    // yet, so this line is the only record this copy existed
                    // — one per recipient rather than a count, because the
                    // question an operator is answering is "did my mail to
                    // b@ arrive?" and they will grep for `b@`.
                    Verdict::Refused(reply) => {
                        refused += 1;
                        error!(
                            id = %envelope.id,
                            recipient = %result.mailbox,
                            host = outcome.host.as_deref().unwrap_or("unknown"),
                            "this copy was permanently refused and is lost; mxhop \
                             cannot send a bounce of its own yet: {reply}"
                        );
                    }
                    Verdict::Deferred(reply) => still_deferred.push((result.mailbox, reply)),
                }
            }
        }

        if still_deferred.is_empty() {
            info!(
                id = %envelope.id,
                delivered,
                refused,
                attempts = envelope.attempts + 1,
                "out of the queue"
            );
            if let Err(e) = self.spool.forget(&envelope.id).await {
                // The message is still in `queue/` and will be delivered
                // again on the next sweep — a duplicate, which is the one
                // thing worse than a deferral. Worth a loud line, because
                // the cause is the disk and the symptom will be somebody
                // receiving the same mail every minute.
                error!(
                    id = %envelope.id,
                    "this message has been delivered but could not be removed from the \
                     queue, so it will be delivered again: {e}"
                );
                return false;
            }
            return true;
        }

        let attempts = envelope.attempts + 1;
        let wait = backoff(attempts);
        let rescheduled = Envelope {
            // Only the recipients still waiting. One that has been delivered
            // and stays on the envelope is a second copy on the next sweep.
            to: still_deferred
                .iter()
                .map(|(mailbox, _)| mailbox.to_string())
                .collect(),
            last_reply: Some(
                still_deferred
                    .iter()
                    .map(|(mailbox, reply)| format!("{mailbox}: {reply}"))
                    .collect::<Vec<_>>()
                    .join("; "),
            ),
            attempts,
            next_attempt_unix_ms: now_unix_ms() + wait.as_millis() as u64,
            ..envelope.clone()
        };

        match self.spool.update(&rescheduled).await {
            Ok(()) => info!(
                id = %rescheduled.id,
                held = rescheduled.to.join(", "),
                attempts,
                minutes = wait.as_secs() / 60,
                "still deferred, will try again: {}",
                rescheduled.last_reply.as_deref().unwrap_or("no reason recorded")
            ),
            // The old envelope is still there, so the message is tried again
            // — immediately, because its old `next_attempt` is in the past.
            // That is a tight loop against a destination that is deferring,
            // so it is reported at error level with the reason the schedule
            // could not be written.
            Err(e) => error!(
                id = %rescheduled.id,
                held = rescheduled.to.join(", "),
                "this message is still deferred and its new schedule could not be \
                 written, so the next sweep will try it again at once: {e}"
            ),
        }
        false
    }
}

/// Whether a message has been in the queue longer than mxhop keeps trying.
///
/// Measured from arrival rather than from the first deferral, because what
/// the sender's postmaster is owed an answer about is how long ago they sent
/// it — and because a clock that starts on the first failure can be restarted
/// by one.
fn expired(envelope: &Envelope, now_unix_ms: u64) -> bool {
    now_unix_ms.saturating_sub(envelope.received_at_unix_ms) > LIFETIME.as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::Mutex;

    use crate::smtp::client::{Outcome, RecipientResult};
    use crate::spool::new_id;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join("mxhop-tests")
            .join(format!("queue-{name}-{}", new_id()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    /// A destination that answers whatever the test told it to, per domain,
    /// and keeps every delivery it was handed so the test can read the bytes
    /// that went out.
    #[derive(Default)]
    struct Fake {
        answers: BTreeMap<String, Verdict>,
        /// Per recipient, which beats per domain when the test is about one
        /// of two recipients at the same host coming unstuck.
        per_recipient: BTreeMap<String, Verdict>,
        seen: Mutex<Vec<Delivery>>,
    }

    impl Fake {
        fn accepting() -> Self {
            Self::default()
        }

        fn answering(domain: &str, verdict: Verdict) -> Self {
            let mut fake = Self::default();
            fake.answers.insert(domain.to_string(), verdict);
            fake
        }

        fn for_recipient(mut self, address: &str, verdict: Verdict) -> Self {
            self.per_recipient.insert(address.to_string(), verdict);
            self
        }

        fn deliveries(&self) -> Vec<Delivery> {
            self.seen.lock().unwrap().clone()
        }

        fn only(&self) -> Delivery {
            let seen = self.deliveries();
            assert_eq!(seen.len(), 1, "expected one delivery, got {}", seen.len());
            seen.into_iter().next().unwrap()
        }
    }

    impl Relay for Fake {
        async fn deliver(&self, delivery: Delivery) -> Outcome {
            let domain = delivery.to[0].domain().to_string();
            let results = delivery
                .to
                .iter()
                .map(|mailbox| RecipientResult {
                    mailbox: mailbox.clone(),
                    verdict: self
                        .per_recipient
                        .get(&mailbox.to_string())
                        .or_else(|| self.answers.get(&domain))
                        .cloned()
                        .unwrap_or(Verdict::Accepted),
                })
                .collect();
            self.seen.lock().unwrap().push(delivery);
            Outcome {
                host: Some(format!("mx.{domain}")),
                results,
            }
        }

        async fn ptr(&self, _ip: std::net::IpAddr) -> Option<String> {
            None
        }

        async fn verify(&self, _probe: crate::auth::Probe<'_>) -> crate::auth::Auth {
            crate::auth::Auth::not_checked()
        }
    }

    fn theirs(code: u16, enhanced: &str, text: &str) -> Reply {
        Reply {
            code,
            enhanced: Some(enhanced.to_string()),
            text: text.to_string(),
            lines: Vec::new(),
        }
    }

    /// A message as the session leaves it in the queue: tried once, due now.
    fn held(to: &[&str]) -> Envelope {
        Envelope {
            id: new_id(),
            from: Some("sender@elsewhere.test".into()),
            to: to.iter().map(|s| s.to_string()).collect(),
            helo: "mail.elsewhere.test".into(),
            peer: "198.51.100.7:40000".into(),
            received_at_unix_ms: now_unix_ms(),
            size: 7,
            received: "Received: from mail.elsewhere.test by mx.test; today\r\n".into(),
            authentication_results: "Authentication-Results: mx.test; spf=pass\r\n".into(),
            last_reply: Some("hi@dest.test: 451 4.3.0 try later".into()),
            attempts: 1,
            next_attempt_unix_ms: 0,
        }
    }

    const BODY: &[u8] = b"Subject: hi\r\n\r\nbody\r\n";

    /// A runner over a fresh spool holding one message.
    async fn with(envelope: &Envelope, relay: Fake) -> (Runner<Fake>, Arc<Spool>, Arc<Fake>) {
        let spool = Arc::new(Spool::open(scratch("run")).await.unwrap());
        spool.store(envelope, BODY).await.unwrap();
        let relay = Arc::new(relay);
        let runner = Runner::new(Arc::clone(&spool), Arc::clone(&relay), None);
        (runner, spool, relay)
    }

    #[test]
    fn the_wait_doubles_from_five_minutes_and_stops_at_two_hours() {
        assert_eq!(backoff(1), Duration::from_secs(300));
        assert_eq!(backoff(2), Duration::from_secs(600));
        assert_eq!(backoff(3), Duration::from_secs(1_200));
        assert_eq!(backoff(4), Duration::from_secs(2_400));
        assert_eq!(backoff(5), Duration::from_secs(4_800));
        assert_eq!(backoff(6), MAX_BACKOFF, "and never longer than that");
        assert_eq!(backoff(500), MAX_BACKOFF, "including when it overflows");
    }

    /// An envelope from a build that had no schedule in it says `attempts: 0`,
    /// and must not be treated as never tried: the message it belongs to was
    /// delivered to once already, in the session that accepted it.
    #[test]
    fn a_message_with_no_recorded_attempt_still_waits_the_first_interval() {
        assert_eq!(backoff(0), backoff(1));
    }

    #[tokio::test]
    async fn a_message_the_destination_now_takes_leaves_the_queue() {
        let envelope = held(&["hi@dest.test"]);
        let (runner, spool, relay) = with(&envelope, Fake::accepting()).await;

        let swept = runner.sweep().await;

        assert_eq!(swept.attempted, 1);
        assert_eq!(swept.settled, 1);
        assert!(
            spool.queued().await.unwrap().is_empty(),
            "a delivered message left in the queue is delivered again a minute later"
        );
        assert_eq!(relay.only().to[0].to_string(), "hi@dest.test");
    }

    /// The whole point of the stored `received` and `authentication_results`
    /// fields: a retry goes out as the bytes that arrived, under the trace
    /// written when they arrived. Rebuilding either would claim a time the
    /// message did not arrive at, and would break the sender's DKIM
    /// signature if it covered the body.
    #[tokio::test]
    async fn the_retry_carries_the_stored_trace_and_the_stored_message() {
        let envelope = held(&["hi@dest.test"]);
        let (runner, _spool, relay) = with(&envelope, Fake::accepting()).await;

        runner.sweep().await;

        let delivery = relay.only();
        assert_eq!(
            String::from_utf8(delivery.head.clone()).unwrap(),
            format!("{}{}", envelope.received, envelope.authentication_results)
        );
        assert_eq!(&*delivery.body, BODY);
    }

    #[tokio::test]
    async fn a_message_still_deferred_is_rescheduled_with_the_reason_and_not_retried_at_once() {
        let envelope = held(&["hi@dest.test"]);
        let (runner, spool, relay) = with(
            &envelope,
            Fake::answering(
                "dest.test",
                Verdict::Deferred(theirs(451, "4.3.0", "mailbox busy, try later")),
            ),
        )
        .await;

        let swept = runner.sweep().await;

        assert_eq!(swept.deferred, 1);
        let queued = spool.queued().await.unwrap();
        assert_eq!(queued.len(), 1, "it is still ours to deliver");
        assert_eq!(queued[0].attempts, 2, "and this attempt has been counted");
        assert!(
            queued[0]
                .last_reply
                .as_deref()
                .unwrap()
                .contains("mailbox busy"),
            "the destination's own words are what an operator needs: {:?}",
            queued[0].last_reply
        );

        // Due in ten minutes, not now: the second sweep must leave it alone.
        let swept = runner.sweep().await;
        assert_eq!(swept.waiting, 1);
        assert_eq!(swept.attempted, 0);
        assert_eq!(
            relay.deliveries().len(),
            1,
            "a destination that said `try later` must not be asked again in the same minute"
        );
    }

    /// A permanent refusal is nobody's to retry. The copy is lost — there is
    /// no delivery report generator yet — but it must not keep the message in
    /// the queue for four days.
    #[tokio::test]
    async fn a_permanent_refusal_on_a_retry_takes_the_message_out_of_the_queue() {
        let envelope = held(&["hi@dest.test"]);
        let (runner, spool, _relay) = with(
            &envelope,
            Fake::answering(
                "dest.test",
                Verdict::Refused(theirs(550, "5.1.1", "no such user")),
            ),
        )
        .await;

        let swept = runner.sweep().await;

        assert_eq!(swept.settled, 1);
        assert!(spool.queued().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn only_the_recipients_that_are_still_stuck_stay_on_the_envelope() {
        let envelope = held(&["one@dest.test", "two@dest.test"]);
        let (runner, spool, _relay) = with(
            &envelope,
            Fake::accepting().for_recipient(
                "two@dest.test",
                Verdict::Deferred(theirs(452, "4.2.2", "over quota")),
            ),
        )
        .await;

        runner.sweep().await;

        let queued = spool.queued().await.unwrap();
        assert_eq!(
            queued[0].to,
            vec!["two@dest.test".to_string()],
            "one@ has its copy; leaving it on the envelope would send it a second one"
        );
    }

    /// Two recipients at two different hosts are two connections, because one
    /// SMTP connection serves one domain — and the grouping is shared with
    /// the inbound session rather than written twice.
    #[tokio::test]
    async fn recipients_at_different_domains_are_delivered_one_connection_each() {
        let envelope = held(&["one@first.test", "two@second.test"]);
        let (runner, _spool, relay) = with(&envelope, Fake::accepting()).await;

        runner.sweep().await;

        let domains: Vec<String> = relay
            .deliveries()
            .iter()
            .map(|d| d.to[0].domain().to_string())
            .collect();
        assert_eq!(domains, vec!["first.test", "second.test"]);
    }

    #[tokio::test]
    async fn a_message_that_is_not_due_yet_is_left_alone() {
        let envelope = Envelope {
            next_attempt_unix_ms: now_unix_ms() + 60_000,
            ..held(&["hi@dest.test"])
        };
        let (runner, spool, relay) = with(&envelope, Fake::accepting()).await;

        let swept = runner.sweep().await;

        assert_eq!(
            swept,
            Swept {
                waiting: 1,
                ..Swept::default()
            }
        );
        assert!(relay.deliveries().is_empty());
        assert_eq!(spool.queued().await.unwrap().len(), 1);
    }

    /// Four days of a destination refusing to take a message is the end of
    /// it. The files must survive that — somebody's mail is in them, and
    /// mxhop cannot tell its sender it was not delivered — so they move to
    /// `frozen/` instead of being removed.
    #[tokio::test]
    async fn a_message_older_than_the_lifetime_is_frozen_rather_than_retried_for_ever() {
        let envelope = Envelope {
            received_at_unix_ms: now_unix_ms() - (LIFETIME.as_millis() as u64 + 1),
            attempts: 40,
            ..held(&["hi@dest.test"])
        };
        let (runner, spool, relay) = with(&envelope, Fake::accepting()).await;

        let swept = runner.sweep().await;

        assert_eq!(swept.frozen, 1);
        assert_eq!(
            swept.attempted, 0,
            "a message past its lifetime is not attempted once more on the way out"
        );
        assert!(relay.deliveries().is_empty());
        assert!(spool.queued().await.unwrap().is_empty());
        assert!(
            spool
                .frozen_dir()
                .join(format!("{}.eml", envelope.id))
                .exists(),
            "the message itself has to still be readable"
        );
    }

    /// An envelope whose message has gone — a `forget` that failed half way,
    /// or an operator who removed the wrong file — can never be delivered.
    /// Retrying it would be a line in the log every minute for four days.
    #[tokio::test]
    async fn an_envelope_whose_message_is_gone_leaves_the_queue() {
        let envelope = held(&["hi@dest.test"]);
        let (runner, spool, relay) = with(&envelope, Fake::accepting()).await;
        std::fs::remove_file(spool.queue_dir().join(format!("{}.eml", envelope.id))).unwrap();

        runner.sweep().await;

        assert!(spool.queued().await.unwrap().is_empty());
        assert!(
            relay.deliveries().is_empty(),
            "there was nothing to deliver"
        );
    }

    /// The envelope sender is rewritten on every attempt, with today's date —
    /// not stored rewritten at arrival. An SRS address carries its own
    /// expiry, and one minted four days ago would be close to the end of the
    /// window a bounce has to come back through.
    #[tokio::test]
    async fn the_retry_leaves_with_an_srs_rewritten_sender() {
        let envelope = held(&["hi@dest.test"]);
        let spool = Arc::new(Spool::open(scratch("srs")).await.unwrap());
        spool.store(&envelope, BODY).await.unwrap();
        let relay = Arc::new(Fake::accepting());
        let srs = Arc::new(crate::srs::Srs::new(
            "srs.mx.test",
            vec![format!("mxhop-queue-test-{}", new_id()).into_bytes()],
            crate::srs::DEFAULT_MAX_AGE_DAYS,
        ));
        let runner = Runner::new(Arc::clone(&spool), Arc::clone(&relay), Some(srs));

        runner.sweep().await;

        let from = relay.only().from.expect("a sender");
        assert!(
            from.ends_with("@srs.mx.test"),
            "the destination checks SPF against the sender it is handed: {from}"
        );
    }

    /// A bounce arrives with the null sender and must leave with it: an
    /// address in a bounce's envelope is an address that bounce can itself be
    /// bounced to.
    #[tokio::test]
    async fn a_bounce_is_retried_with_the_null_sender() {
        let envelope = Envelope {
            from: None,
            ..held(&["hi@dest.test"])
        };
        let spool = Arc::new(Spool::open(scratch("bounce")).await.unwrap());
        spool.store(&envelope, BODY).await.unwrap();
        let relay = Arc::new(Fake::accepting());
        let srs = Arc::new(crate::srs::Srs::new(
            "srs.mx.test",
            vec![b"mxhop-queue-test-bounce".to_vec()],
            crate::srs::DEFAULT_MAX_AGE_DAYS,
        ));
        let runner = Runner::new(Arc::clone(&spool), Arc::clone(&relay), Some(srs));

        runner.sweep().await;

        assert_eq!(relay.only().from, None);
    }

    /// The queue is the administration interface, so a hand-edited envelope
    /// has to be survivable: one unusable recipient costs that copy and
    /// nothing else.
    #[tokio::test]
    async fn an_unparseable_recipient_does_not_stop_the_rest_of_the_message() {
        let envelope = held(&["not an address", "hi@dest.test"]);
        let (runner, spool, relay) = with(&envelope, Fake::accepting()).await;

        runner.sweep().await;

        assert_eq!(relay.only().to[0].to_string(), "hi@dest.test");
        assert!(spool.queued().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_envelope_with_no_deliverable_recipient_is_frozen() {
        let envelope = held(&["not an address"]);
        let (runner, spool, relay) = with(&envelope, Fake::accepting()).await;

        runner.sweep().await;

        assert!(relay.deliveries().is_empty());
        assert!(spool.queued().await.unwrap().is_empty());
        assert!(
            spool
                .frozen_dir()
                .join(format!("{}.json", envelope.id))
                .exists(),
            "and it is kept, because the mail in it is still somebody's"
        );
    }

    #[tokio::test]
    async fn an_empty_queue_is_not_work() {
        let spool = Arc::new(Spool::open(scratch("empty")).await.unwrap());
        let runner = Runner::new(spool, Arc::new(Fake::accepting()), None);

        assert_eq!(runner.sweep().await, Swept::default());
    }
}
