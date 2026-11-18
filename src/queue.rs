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

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tracing::{debug, error, info, warn};

use crate::envelope::{Envelope, now_unix_ms};
use crate::policy;
use crate::routing::Mailbox;
use crate::smtp::client::{Delivery, Relay, Reply, Verdict};
use crate::spool::Spool;
use crate::srs::Srs;

/// The wait before each attempt after the first, in minutes: one minute,
/// then five, fifteen, an hour, and every four hours after that.
///
/// The last entry repeats for as long as the message is in the queue, which
/// is what makes this a complete schedule rather than a prefix of one. The
/// first interval is deliberately short — a destination that answered "not
/// now" is usually a greylist, and a greylist clears in a minute.
pub const DEFAULT_RETRY_MINUTES: [u64; 5] = [1, 5, 15, 60, 240];

/// How long a message may stay in the queue before mxhop stops trying.
///
/// Two days. It has to fit inside the SRS window: a forwarded message leaves
/// with a rewritten sender whose signature is only valid for
/// `srs.max_age_days` — seven by default — so a bounce provoked by the last
/// attempt has to arrive while that address still decodes, and `check`
/// refuses a lifetime that does not fit.
pub const DEFAULT_LIFETIME_HOURS: u64 = 48;

/// How often the queue is read from disk. The schedule lives in the
/// envelopes, so this is only the resolution of the clock that reads them.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// The longest `queue.lifetime_hours` mxhop will accept. A month of attempts
/// is a month in which nobody has been told anything, and every sender's
/// postmaster gave up waiting long before it.
pub const MAX_LIFETIME_HOURS: u64 = 30 * 24;

/// The longest interval `queue.retry_minutes` may state: a day between
/// attempts, inside a lifetime measured in hours, is a schedule that retries
/// almost nothing.
pub const MAX_RETRY_MINUTES: u64 = 24 * 60;

/// The most intervals `queue.retry_minutes` may state. The last one repeats,
/// so a list this long is already a schedule nobody is reading.
pub const MAX_RETRY_STEPS: usize = 32;

/// The longest `queue.sweep_seconds` mxhop will accept. The schedule lives in
/// the envelopes, so this is only how often they are read; an hour between
/// reads would make every interval above an hour long in practice.
pub const MAX_SWEEP_SECONDS: u64 = 60 * 60;

/// When the runner tries things, as the configuration states it.
///
/// Carried as one value rather than three arguments because the inbound
/// session needs it too: the first wait is written into an envelope at the
/// moment it is held, and it has to be the same wait the runner would
/// compute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Schedule {
    /// The wait before each attempt after the first, the last entry
    /// repeating for ever. See [`DEFAULT_RETRY_MINUTES`].
    ///
    /// A list rather than a first interval and a doubling rule, because the
    /// shape that is actually wanted — short, short, longer, then settle
    /// down — is not a geometric series, and writing it as one made the
    /// early intervals either too long or the late ones too short.
    ///
    /// Never empty: [`Schedule::backoff`] falls back to the first default
    /// interval if it somehow is, and `config` refuses an empty list.
    pub retries: Vec<Duration>,
    /// How long a message may stay in the queue. See
    /// [`DEFAULT_LIFETIME_HOURS`].
    pub lifetime: Duration,
    /// How often the queue is read from disk. See [`SWEEP_INTERVAL`].
    pub sweep_interval: Duration,
}

impl Default for Schedule {
    fn default() -> Self {
        Self {
            retries: DEFAULT_RETRY_MINUTES
                .iter()
                .map(|m| Duration::from_secs(m * 60))
                .collect(),
            lifetime: Duration::from_secs(DEFAULT_LIFETIME_HOURS * 3_600),
            sweep_interval: SWEEP_INTERVAL,
        }
    }
}

impl Schedule {
    /// How long to wait before trying a message that has already been tried
    /// `attempts` times.
    ///
    /// A function of nothing but the count and this list, so that the
    /// envelope on disk is the whole schedule: the runner can be restarted,
    /// or the machine rebooted, without losing where a message was in it.
    pub fn backoff(&self, attempts: u32) -> Duration {
        // `attempts` is what has already been spent, so one attempt earns
        // the first interval. Zero means the same thing as one here — an
        // envelope written before this field existed — and gets it too.
        let step = attempts.max(1) as usize - 1;
        self.retries
            .get(step)
            // Past the end of the list, the last interval repeats: that is
            // what "and every four hours after that" means, and it is also
            // what stops a long-stuck message from waiting for ever.
            .or_else(|| self.retries.last())
            .copied()
            // Unreachable: `config` refuses an empty list and `Default`
            // fills one in. A panic here would be a queue that stops on a
            // configuration nothing can produce.
            .unwrap_or(Duration::from_secs(DEFAULT_RETRY_MINUTES[0] * 60))
    }

    /// The longest interval in the schedule — the one that repeats.
    ///
    /// Used as "long enough that nothing is still happening": a host nothing
    /// has retried for this long is one whose failure count has stopped
    /// being evidence.
    pub fn longest(&self) -> Duration {
        self.retries
            .iter()
            .max()
            .copied()
            .unwrap_or(Duration::from_secs(DEFAULT_RETRY_MINUTES[0] * 60))
    }

    /// Whether a message has been in the queue longer than mxhop keeps
    /// trying.
    ///
    /// Measured from arrival rather than from the first deferral, because
    /// what the sender's postmaster is owed an answer about is how long ago
    /// they sent it — and because a clock that starts on the first failure
    /// can be restarted by one.
    pub fn expired(&self, envelope: &Envelope, now_unix_ms: u64) -> bool {
        now_unix_ms.saturating_sub(envelope.received_at_unix_ms) > self.lifetime.as_millis() as u64
    }
}

/// What each destination has been doing lately.
///
/// A hundred messages queued for one host that is refusing connections are a
/// hundred connection attempts per sweep without this, every one of them
/// timing out, and the sweep takes so long that mail for the destinations
/// that *are* up waits behind it. One failure therefore stands in for the
/// domain: the next message for it is skipped until the backoff expires.
///
/// In memory, and lost on restart, deliberately. It is a statement about what
/// is true right now rather than about any message, and writing it to disk
/// would mean a message carrying a fact about a host it shares with others.
/// The cost of losing it is one connection per domain after a restart.
#[derive(Debug, Default)]
struct Hosts(Mutex<BTreeMap<String, Backoff>>);

#[derive(Debug)]
struct Backoff {
    /// Consecutive failures, which is what the wait doubles from.
    failures: u32,
    not_before_unix_ms: u64,
}

impl Hosts {
    /// `Some(millis)` if this domain must not be connected to yet.
    fn held_until(&self, domain: &str, now_unix_ms: u64) -> Option<u64> {
        self.0
            .lock()
            .expect("the host table is never held across an await")
            .get(domain)
            .map(|b| b.not_before_unix_ms)
            .filter(|not_before| *not_before > now_unix_ms)
    }

    /// Nobody answered, or everybody deferred. Returns the wait this earns,
    /// for the log line.
    fn failed(&self, domain: &str, now_unix_ms: u64, schedule: &Schedule) -> Duration {
        let mut table = self
            .0
            .lock()
            .expect("the host table is never held across an await");
        let entry = table.entry(domain.to_string()).or_insert(Backoff {
            failures: 0,
            not_before_unix_ms: 0,
        });
        entry.failures = entry.failures.saturating_add(1);
        let wait = schedule.backoff(entry.failures);
        entry.not_before_unix_ms = now_unix_ms + wait.as_millis() as u64;
        wait
    }

    /// The destination answered for itself — it took the message, or refused
    /// it, which are both answers. Whatever was wrong with it is over.
    fn answered(&self, domain: &str) -> bool {
        self.0
            .lock()
            .expect("the host table is never held across an await")
            .remove(domain)
            .is_some()
    }

    /// Forgets domains nothing has tried for a whole longest-interval's worth
    /// of time.
    ///
    /// Without this the table keeps an entry per domain that has ever failed,
    /// and the queue of a busy forwarder names a great many domains. A
    /// failure count nothing has added to for that long is also not evidence
    /// about the host as it is now.
    fn prune(&self, now_unix_ms: u64, schedule: &Schedule) {
        let stale = schedule.longest().as_millis() as u64;
        self.0
            .lock()
            .expect("the host table is never held across an await")
            .retain(|_, b| b.not_before_unix_ms.saturating_add(stale) > now_unix_ms);
    }
}

/// What one attempt came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Attempted {
    /// Out of the queue: delivered, refused for good, or undeliverable.
    Settled,
    /// Still ours, rescheduled.
    Deferred,
    /// Not tried at all: a destination it needs is backed off.
    HeldBack,
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
    /// Messages due, but for a destination that is currently backed off:
    /// skipped without a connection and without costing them an attempt.
    pub held_back: usize,
}

/// The queue runner: the spool, somewhere to deliver to, the sender rewriter
/// if the deployment has one, and when to try things.
pub struct Runner<L> {
    spool: Arc<Spool>,
    relay: Arc<L>,
    srs: Option<Arc<Srs>>,
    schedule: Schedule,
    hosts: Hosts,
}

impl<L> Runner<L>
where
    L: Relay,
{
    pub fn new(
        spool: Arc<Spool>,
        relay: Arc<L>,
        srs: Option<Arc<Srs>>,
        schedule: Schedule,
    ) -> Self {
        Self {
            spool,
            relay,
            srs,
            schedule,
            hosts: Hosts::default(),
        }
    }

    /// Sweeps for as long as the process runs.
    pub async fn run(self) {
        loop {
            self.sweep().await;
            tokio::time::sleep(self.schedule.sweep_interval).await;
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

            if self.schedule.expired(&envelope, now) {
                // Error level, not warning: this is mail that was accepted
                // and will not be delivered, and until mxhop can send a
                // delivery report of its own this line is the only notice
                // anybody gets.
                error!(
                    id = %envelope.id,
                    to = envelope.to.join(", "),
                    attempts = envelope.attempts,
                    days = self.schedule.lifetime.as_secs() / 86_400,
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

            match self.attempt(&envelope).await {
                Attempted::Settled => {
                    swept.attempted += 1;
                    swept.settled += 1;
                }
                Attempted::Deferred => {
                    swept.attempted += 1;
                    swept.deferred += 1;
                }
                Attempted::HeldBack => swept.held_back += 1,
            }
        }

        // After the pass rather than before it, so that a domain this sweep
        // backed off is never pruned in the same breath.
        self.hosts.prune(now_unix_ms(), &self.schedule);

        if swept != Swept::default() {
            debug!(
                waiting = swept.waiting,
                attempted = swept.attempted,
                settled = swept.settled,
                deferred = swept.deferred,
                frozen = swept.frozen,
                held_back = swept.held_back,
                "queue swept"
            );
        }
        swept
    }

    /// One attempt at one message.
    async fn attempt(&self, envelope: &Envelope) -> Attempted {
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
                return Attempted::Settled;
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
            return Attempted::Settled;
        }

        let groups = policy::group_by_domain(recipients);

        // A destination that has just failed is not asked again until its
        // backoff expires, and a message needing one is skipped whole — not
        // partly delivered, even when its other destinations are up.
        //
        // That costs the healthy domain a wait of up to one ceiling, and buys
        // a rule with no second schedule in it: a part-delivered attempt
        // would have to leave the skipped recipients on the envelope without
        // counting an attempt against them, which is two clocks on one
        // message. It is also nearly free in practice — a message is only
        // here because a destination deferred, and the recipients that were
        // delivered came off the envelope then.
        let now = now_unix_ms();
        if let Some((domain, not_before)) = groups
            .iter()
            .filter_map(|group| {
                self.hosts
                    .held_until(&group.domain, now)
                    .map(|until| (group.domain.clone(), until))
            })
            .max_by_key(|(_, until)| *until)
        {
            debug!(
                id = %envelope.id,
                domain = %domain,
                seconds = (not_before.saturating_sub(now)) / 1000,
                "not trying this message yet: this destination has just failed for \
                 another one, and one connection an interval is enough to find out \
                 whether it is back"
            );
            return Attempted::HeldBack;
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

        for group in groups {
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

            // Every recipient deferred means the destination said nothing
            // about any of them: it did not answer, or it answered "not
            // now" to the lot. Either way the next message for this domain
            // would learn the same thing at the cost of another connection.
            // One recipient settled is a destination that is working, so
            // whatever was wrong with it is over.
            if outcome
                .results
                .iter()
                .all(|r| matches!(r.verdict, Verdict::Deferred(_)))
            {
                let wait = self
                    .hosts
                    .failed(&group.domain, now_unix_ms(), &self.schedule);
                info!(
                    domain = %group.domain,
                    host = outcome.host.as_deref().unwrap_or("none answered"),
                    minutes = wait.as_secs() / 60,
                    "this destination deferred everything it was handed, so other \
                     queued messages for it are skipped until it is tried again"
                );
            } else if self.hosts.answered(&group.domain) {
                info!(
                    domain = %group.domain,
                    "this destination is answering again; queued messages for it are \
                     no longer skipped"
                );
            }

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
                return Attempted::Deferred;
            }
            return Attempted::Settled;
        }

        let attempts = envelope.attempts + 1;
        let wait = self.schedule.backoff(attempts);
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
        Attempted::Deferred
    }
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
        /// Behind a lock because the tests about a destination coming back
        /// change the answer between two sweeps.
        answers: Mutex<BTreeMap<String, Verdict>>,
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
            let fake = Self::default();
            fake.say(domain, verdict);
            fake
        }

        fn say(&self, domain: &str, verdict: Verdict) {
            self.answers
                .lock()
                .unwrap()
                .insert(domain.to_string(), verdict);
        }

        fn now_accepting(&self, domain: &str) {
            self.answers.lock().unwrap().remove(domain);
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
            let answers = self.answers.lock().unwrap().clone();
            let results = delivery
                .to
                .iter()
                .map(|mailbox| RecipientResult {
                    mailbox: mailbox.clone(),
                    verdict: self
                        .per_recipient
                        .get(&mailbox.to_string())
                        .or_else(|| answers.get(&domain))
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

    /// A runner over a fresh spool holding one message, on the schedule the
    /// defaults give.
    async fn with(envelope: &Envelope, relay: Fake) -> (Runner<Fake>, Arc<Spool>, Arc<Fake>) {
        with_many(std::slice::from_ref(envelope), relay).await
    }

    /// The same, for the tests about one destination and several messages.
    async fn with_many(
        envelopes: &[Envelope],
        relay: Fake,
    ) -> (Runner<Fake>, Arc<Spool>, Arc<Fake>) {
        with_schedule(envelopes, relay, Schedule::default()).await
    }

    /// The same again, on a schedule of the test's own: the tests about a
    /// destination coming back have to get past a wait, and a millisecond is
    /// a wait.
    async fn with_schedule(
        envelopes: &[Envelope],
        relay: Fake,
        schedule: Schedule,
    ) -> (Runner<Fake>, Arc<Spool>, Arc<Fake>) {
        let spool = Arc::new(Spool::open(scratch("run")).await.unwrap());
        for envelope in envelopes {
            spool.store(envelope, BODY).await.unwrap();
        }
        let relay = Arc::new(relay);
        let runner = Runner::new(Arc::clone(&spool), Arc::clone(&relay), None, schedule);
        (runner, spool, relay)
    }

    /// A schedule whose waits are a fraction of a second, so that a test can
    /// sleep through one instead of through five minutes.
    ///
    /// Long enough that one sweep cannot outlast it, which is the bug the
    /// first two versions of this helper had: a sweep writes an envelope per
    /// deferred message and waits for the platter each time, which on a real
    /// filesystem is tens of milliseconds, so a wait of one or fifty had
    /// already expired by the time the sweep reached the second message —
    /// and the test passed for the wrong reason.
    fn impatient() -> Schedule {
        Schedule {
            retries: vec![Duration::from_millis(400)],
            ..Schedule::default()
        }
    }

    /// One minute, five, fifteen, an hour, then every four hours — the
    /// schedule this queue was specified with, read off the default.
    #[test]
    fn the_waits_are_one_five_fifteen_sixty_and_then_every_four_hours() {
        let schedule = Schedule::default();
        let minutes = |n: u64| Duration::from_secs(n * 60);

        assert_eq!(schedule.backoff(1), minutes(1));
        assert_eq!(schedule.backoff(2), minutes(5));
        assert_eq!(schedule.backoff(3), minutes(15));
        assert_eq!(schedule.backoff(4), minutes(60));
        assert_eq!(schedule.backoff(5), minutes(240));
        assert_eq!(
            schedule.backoff(6),
            minutes(240),
            "the last interval repeats: that is what 'and every four hours' means"
        );
        assert_eq!(
            schedule.backoff(5_000),
            minutes(240),
            "including for a message that has been stuck as long as the lifetime allows"
        );
    }

    /// Two days of attempts on that schedule, which is what the lifetime has
    /// to be long enough to contain and short enough to fit inside the SRS
    /// window.
    #[test]
    fn the_default_lifetime_is_forty_eight_hours() {
        assert_eq!(
            Schedule::default().lifetime,
            Duration::from_secs(48 * 3_600)
        );
    }

    /// A schedule shorter than the number of attempts a message gets must
    /// not run off the end of its own list.
    #[test]
    fn a_schedule_of_one_interval_repeats_it() {
        let schedule = Schedule {
            retries: vec![Duration::from_secs(90)],
            ..Schedule::default()
        };

        assert_eq!(schedule.backoff(1), Duration::from_secs(90));
        assert_eq!(schedule.backoff(99), Duration::from_secs(90));
    }

    /// Intervals are kept as `Duration`, so a schedule stated in less than
    /// whole seconds is the schedule it says. An earlier version computed the
    /// wait in whole seconds and floored a 400 ms interval to zero, which is
    /// a configuration with no waits in it at all — and the first test that
    /// wanted one passed for the wrong reason.
    #[test]
    fn an_interval_shorter_than_a_second_is_not_floored_to_nothing() {
        assert_eq!(impatient().backoff(1), Duration::from_millis(400));
        assert_eq!(impatient().backoff(9), Duration::from_millis(400));
    }

    /// An envelope from a build that had no schedule in it says `attempts: 0`,
    /// and must not be treated as never tried: the message it belongs to was
    /// delivered to once already, in the session that accepted it.
    #[test]
    fn a_message_with_no_recorded_attempt_still_waits_the_first_interval() {
        let schedule = Schedule::default();

        assert_eq!(schedule.backoff(0), schedule.backoff(1));
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
            received_at_unix_ms: now_unix_ms()
                - (Schedule::default().lifetime.as_millis() as u64 + 1),
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
        let runner = Runner::new(
            Arc::clone(&spool),
            Arc::clone(&relay),
            Some(srs),
            Schedule::default(),
        );

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
        let runner = Runner::new(
            Arc::clone(&spool),
            Arc::clone(&relay),
            Some(srs),
            Schedule::default(),
        );

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

    // --------------------------------------------- one failure, one domain

    /// The reason per-host backoff exists. A dead destination with a hundred
    /// messages queued for it was a hundred connections per sweep, every one
    /// of them waiting out the connect timeout, and the sweep took so long
    /// that mail for destinations that *were* up waited behind it.
    #[tokio::test]
    async fn a_destination_that_has_just_failed_is_tried_for_one_message_not_all_of_them() {
        let queued: Vec<Envelope> = (0..3).map(|_| held(&["hi@dest.test"])).collect();
        let (runner, _spool, relay) = with_many(
            &queued,
            Fake::answering(
                "dest.test",
                Verdict::Deferred(theirs(421, "4.7.0", "too many connections")),
            ),
        )
        .await;

        let swept = runner.sweep().await;

        assert_eq!(
            relay.deliveries().len(),
            1,
            "one connection is enough to learn what this destination thinks"
        );
        assert_eq!(swept.attempted, 1);
        assert_eq!(swept.held_back, 2);
    }

    /// Being skipped is not being tried: a message held back for somebody
    /// else's failure must not age out of the queue faster than one that was
    /// actually attempted, and its own schedule must not move.
    #[tokio::test]
    async fn a_message_held_back_for_another_is_not_charged_an_attempt() {
        let first = held(&["hi@dest.test"]);
        let second = held(&["hi@dest.test"]);
        let (runner, spool, _relay) = with_many(
            &[first.clone(), second.clone()],
            Fake::answering(
                "dest.test",
                Verdict::Deferred(theirs(451, "4.3.0", "try later")),
            ),
        )
        .await;

        runner.sweep().await;

        let queued = spool.queued().await.unwrap();
        let held_back = queued
            .iter()
            .find(|e| e.id == second.id)
            .expect("still in the queue");
        assert_eq!(held_back.attempts, 1, "nothing was spent on its behalf");
        assert_eq!(
            held_back.next_attempt_unix_ms, 0,
            "and its own schedule is untouched: the backoff that skipped it is the \
             destination's, and it is kept in memory rather than written into \
             somebody's envelope"
        );
    }

    /// A destination that answers for itself — by taking the message or by
    /// refusing it — is a working destination, and the next message for it
    /// must go out in the same sweep rather than waiting out a backoff
    /// earned before it came back.
    #[tokio::test]
    async fn a_destination_that_answers_again_stops_holding_the_rest_back() {
        let queued: Vec<Envelope> = (0..3).map(|_| held(&["hi@dest.test"])).collect();
        let (runner, spool, relay) = with_schedule(
            &queued,
            Fake::answering(
                "dest.test",
                Verdict::Deferred(theirs(451, "4.3.0", "try later")),
            ),
            impatient(),
        )
        .await;

        let swept = runner.sweep().await;
        assert_eq!(
            (swept.attempted, swept.held_back),
            (1, 2),
            "one message learns the destination is deferring, and the other two are \
             not asked to learn it again"
        );

        // The destination comes back, and its backoff — a millisecond on
        // this schedule — expires.
        relay.now_accepting("dest.test");
        tokio::time::sleep(Duration::from_millis(600)).await;
        let swept = runner.sweep().await;

        assert_eq!(
            swept.attempted, 3,
            "the backlog goes out in the sweep that finds the host up, rather than one \
             message per interval"
        );
        assert_eq!(swept.settled, 3);
        assert!(
            spool.queued().await.unwrap().is_empty(),
            "and the queue is empty"
        );
        assert_eq!(relay.deliveries().len(), 4, "one failed probe, then three");
    }

    /// While a destination is backed off, nothing probes it — including the
    /// message that earned the backoff. The probe is the next attempt after
    /// the wait, and that is the whole saving: one connection per interval
    /// instead of one per message per sweep.
    #[tokio::test]
    async fn nothing_touches_a_backed_off_destination_until_its_wait_is_over() {
        let queued: Vec<Envelope> = (0..3).map(|_| held(&["hi@dest.test"])).collect();
        let (runner, _spool, relay) = with_many(
            &queued,
            Fake::answering(
                "dest.test",
                Verdict::Deferred(theirs(451, "4.3.0", "try later")),
            ),
        )
        .await;

        runner.sweep().await;
        let swept = runner.sweep().await;

        assert_eq!(swept.attempted, 0);
        assert_eq!(
            swept.held_back, 2,
            "and the third is waiting on its own clock"
        );
        assert_eq!(swept.waiting, 1);
        assert_eq!(relay.deliveries().len(), 1);
    }

    /// The backoff is per destination and not a pause on the queue: mail for
    /// a host that is up must not wait behind a host that is down, which is
    /// the failure this feature exists to prevent rather than cause.
    #[tokio::test]
    async fn a_destination_that_is_up_is_delivered_to_while_another_is_backed_off() {
        let broken = held(&["hi@broken.test"]);
        let working = held(&["hi@working.test"]);
        let (runner, spool, relay) = with_many(
            &[broken.clone(), working.clone()],
            Fake::answering(
                "broken.test",
                Verdict::Deferred(theirs(451, "4.3.0", "try later")),
            ),
        )
        .await;

        runner.sweep().await;

        let domains: Vec<String> = relay
            .deliveries()
            .iter()
            .map(|d| d.to[0].domain().to_string())
            .collect();
        assert_eq!(domains, vec!["broken.test", "working.test"]);
        assert_eq!(
            spool.queued().await.unwrap().len(),
            1,
            "the working one is delivered and gone"
        );
    }

    /// A host that fails repeatedly waits longer each time, on the same
    /// schedule a message does — and the count is the host's, so the second
    /// failure's wait is the second interval even though each message that
    /// provoked it was on its first attempt.
    #[test]
    fn a_hosts_wait_lengthens_with_its_own_failures() {
        let schedule = Schedule::default();
        let hosts = Hosts::default();

        assert_eq!(hosts.failed("dest.test", 0, &schedule), schedule.backoff(1));
        assert_eq!(hosts.failed("dest.test", 0, &schedule), schedule.backoff(2));
        assert_eq!(hosts.failed("dest.test", 0, &schedule), schedule.backoff(3));
        assert!(
            schedule.backoff(3) > schedule.backoff(1),
            "a host that keeps failing has to be asked less often, not the same"
        );
        assert_eq!(
            hosts.failed("other.test", 0, &schedule),
            schedule.backoff(1),
            "and it is this host's own count, not a global one"
        );

        assert!(hosts.answered("dest.test"), "it was being held");
        assert_eq!(
            hosts.failed("dest.test", 0, &schedule),
            schedule.backoff(1),
            "a host that answered starts again from the first interval"
        );
    }

    #[test]
    fn a_host_nothing_has_tried_for_a_whole_ceiling_is_forgotten() {
        // Otherwise the table keeps an entry per domain that has ever
        // failed, and the queue of a busy forwarder names a great many.
        let schedule = Schedule::default();
        let hosts = Hosts::default();
        hosts.failed("dest.test", 0, &schedule);

        let later = schedule.backoff(1).as_millis() as u64 + schedule.longest().as_millis() as u64;
        hosts.prune(later + 1, &schedule);

        assert!(
            !hosts.answered("dest.test"),
            "a failure count nothing has added to for a ceiling's worth of time is not \
             evidence about the host as it is now"
        );
    }

    #[tokio::test]
    async fn an_empty_queue_is_not_work() {
        let spool = Arc::new(Spool::open(scratch("empty")).await.unwrap());
        let runner = Runner::new(
            spool,
            Arc::new(Fake::accepting()),
            None,
            Schedule::default(),
        );

        assert_eq!(runner.sweep().await, Swept::default());
    }
}
