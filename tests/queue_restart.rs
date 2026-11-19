use std::collections::VecDeque;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mxhop::auth::{Auth, Probe};
use mxhop::envelope::{Envelope, now_unix_ms};
use mxhop::queue::{Runner, Schedule};
use mxhop::smtp::client::{Delivery, Outcome, RecipientResult, Relay, Reply, Verdict};
use mxhop::spool::{Spool, new_id};

const BODY: &[u8] = b"From: sender@elsewhere.test\r\nSubject: hi\r\n\r\nbody\r\n";

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir()
        .join("mxhop-tests")
        .join(format!("restart-{name}-{}", new_id()));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn held(id_hint: &str) -> Envelope {
    Envelope {
        id: format!("{}-{id_hint}", new_id()),
        from: Some("sender@elsewhere.test".into()),
        to: vec!["hi@dest.test".into()],
        helo: "mail.elsewhere.test".into(),
        peer: "198.51.100.7:40000".into(),
        received_at_unix_ms: now_unix_ms(),
        size: BODY.len() as u64,
        received: "Received: from mail.elsewhere.test by mx.test; today\r\n".into(),
        authentication_results: "Authentication-Results: mx.test; spf=pass\r\n".into(),
        last_reply: Some("hi@dest.test: 451 4.3.0 try later".into()),
        attempts: 1,
        next_attempt_unix_ms: 0,
    }
}

fn impatient() -> Schedule {
    Schedule {
        retries: vec![Duration::from_millis(400)],
        ..Schedule::default()
    }
}

#[derive(Default)]
struct Fake {
    verdicts: Mutex<VecDeque<Verdict>>,
    hangs: bool,
    seen: Mutex<Vec<Delivery>>,
}

impl Fake {
    fn accepting() -> Self {
        Self::default()
    }

    fn saying(verdicts: Vec<Verdict>) -> Self {
        Self {
            verdicts: Mutex::new(verdicts.into()),
            ..Self::default()
        }
    }

    fn that_never_answers() -> Self {
        Self {
            hangs: true,
            ..Self::default()
        }
    }

    fn deliveries(&self) -> Vec<Delivery> {
        self.seen.lock().unwrap().clone()
    }
}

impl Relay for Fake {
    async fn deliver(&self, delivery: Delivery) -> Outcome {
        self.seen.lock().unwrap().push(delivery.clone());
        if self.hangs {
            tokio::time::sleep(Duration::from_secs(3_600)).await;
        }
        let verdict = self
            .verdicts
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Verdict::Accepted);
        Outcome {
            host: Some(format!("mx.{}", delivery.to[0].domain())),
            results: delivery
                .to
                .iter()
                .map(|mailbox| RecipientResult {
                    mailbox: mailbox.clone(),
                    verdict: verdict.clone(),
                })
                .collect(),
        }
    }

    async fn ptr(&self, _ip: IpAddr) -> Option<String> {
        None
    }

    async fn verify(&self, _probe: Probe<'_>, _budget: mxhop::auth::Budget) -> Auth {
        Auth::not_checked()
    }
}

fn greylisted() -> Verdict {
    Verdict::Deferred(Reply {
        code: 450,
        enhanced: Some("4.2.0".into()),
        text: "greylisted, try again in a minute".into(),
        lines: Vec::new(),
    })
}

async fn restart(root: &PathBuf, relay: Fake) -> (Runner<Fake>, Arc<Spool>, Arc<Fake>) {
    let spool = Arc::new(Spool::open(root).await.expect("reopen the spool"));
    let relay = Arc::new(relay);
    let runner = Runner::new(Arc::clone(&spool), Arc::clone(&relay), None, impatient());
    (runner, spool, relay)
}

fn delivered_bytes(delivery: &Delivery, envelope: &Envelope) -> Vec<u8> {
    assert_eq!(
        String::from_utf8(delivery.head.clone()).unwrap(),
        format!("{}{}", envelope.received, envelope.authentication_results),
        "a retry has to carry the trace written when the message arrived"
    );
    delivery.body.to_vec()
}

#[tokio::test]
async fn a_greylisted_message_is_delivered_on_the_retry() {
    let root = scratch("greylist");
    let envelope = held("grey");
    let (runner, spool, relay) = restart(&root, Fake::saying(vec![greylisted()])).await;
    spool.store(&envelope, BODY).await.unwrap();

    let first = runner.sweep().await;
    assert_eq!(first.attempted, 1);
    assert_eq!(first.deferred, 1, "a 450 is not a refusal");

    let waiting = spool.queued().await.unwrap();
    assert_eq!(waiting.len(), 1, "the message is still ours");
    assert_eq!(waiting[0].attempts, 2, "and the attempt was counted");
    assert!(
        waiting[0]
            .last_reply
            .as_deref()
            .unwrap()
            .contains("greylisted"),
        "the destination's own sentence is what an operator reads: {:?}",
        waiting[0].last_reply
    );

    tokio::time::sleep(Duration::from_millis(600)).await;
    let second = runner.sweep().await;

    assert_eq!(second.settled, 1);
    assert!(
        spool.queued().await.unwrap().is_empty(),
        "a delivered message left in the queue is delivered again a minute later"
    );
    let deliveries = relay.deliveries();
    assert_eq!(
        deliveries.len(),
        2,
        "one refused attempt, then one that was taken"
    );
    assert_eq!(
        delivered_bytes(&deliveries[1], &envelope),
        BODY,
        "one changed byte invalidates the sender's DKIM signature"
    );
}

#[tokio::test]
async fn a_message_deferred_before_the_process_died_is_delivered_after_the_restart() {
    let root = scratch("kill-between");
    let envelope = held("between");

    {
        let (runner, spool, _relay) = restart(&root, Fake::saying(vec![greylisted()])).await;
        spool.store(&envelope, BODY).await.unwrap();
        runner.sweep().await;
    }

    let (runner, spool, relay) = restart(&root, Fake::accepting()).await;

    let found = spool.queued().await.unwrap();
    assert_eq!(
        found.len(),
        1,
        "the queue is read off the disk, not remembered"
    );
    assert_eq!(
        found[0].attempts, 2,
        "and the attempt the dead process made still counts: a restart that reset this \
         would retry from the first interval for as long as something keeps restarting"
    );
    assert!(
        found[0].next_attempt_unix_ms > 0,
        "the schedule came back with it"
    );

    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(runner.sweep().await.settled, 1);

    assert!(spool.queued().await.unwrap().is_empty());
    assert_eq!(
        delivered_bytes(&relay.deliveries()[0], &envelope),
        BODY,
        "delivered after the restart, byte for byte"
    );
}

#[tokio::test]
async fn a_message_killed_mid_delivery_is_still_in_the_queue_and_goes_out_afterwards() {
    let root = scratch("kill-mid");
    let envelope = held("mid");

    {
        let (runner, spool, relay) = restart(&root, Fake::that_never_answers()).await;
        spool.store(&envelope, BODY).await.unwrap();

        let killed = tokio::time::timeout(Duration::from_millis(200), runner.sweep()).await;
        assert!(
            killed.is_err(),
            "the destination was supposed to never answer"
        );
        assert_eq!(
            relay.deliveries().len(),
            1,
            "the attempt did start — otherwise this test proves nothing"
        );
    }

    let (runner, spool, relay) = restart(&root, Fake::accepting()).await;

    let found = spool.queued().await.unwrap();
    assert_eq!(
        found.len(),
        1,
        "an interrupted attempt must not lose the message"
    );
    assert_eq!(
        found[0], envelope,
        "and must not change it either: nothing is written until a destination has \
         answered, so the envelope is the one the session wrote"
    );
    assert_eq!(spool.body(&envelope.id).await.unwrap(), BODY);

    assert_eq!(runner.sweep().await.settled, 1, "it was due the whole time");
    assert!(spool.queued().await.unwrap().is_empty());
    assert_eq!(delivered_bytes(&relay.deliveries()[0], &envelope), BODY);
}

#[tokio::test]
async fn a_delivered_message_that_could_not_be_removed_is_delivered_again() {
    let root = scratch("forget-fails");
    let envelope = held("stuck");
    let (runner, spool, relay) = restart(&root, Fake::accepting()).await;
    spool.store(&envelope, BODY).await.unwrap();

    let mut mode = std::fs::metadata(spool.queue_dir()).unwrap().permissions();
    mode.set_readonly(true);
    std::fs::set_permissions(spool.queue_dir(), mode).unwrap();

    let swept = runner.sweep().await;

    let mut mode = std::fs::metadata(spool.queue_dir()).unwrap().permissions();
    mode.set_mode(0o755);
    std::fs::set_permissions(spool.queue_dir(), mode).unwrap();

    assert_eq!(relay.deliveries().len(), 1, "the destination took it");
    assert_eq!(
        swept.settled, 0,
        "but it is still in the queue, so the sweep must not report it as finished"
    );
    assert_eq!(
        spool.queued().await.unwrap().len(),
        1,
        "and it is still there to prove it"
    );

    assert_eq!(runner.sweep().await.settled, 1);
    assert_eq!(
        relay.deliveries().len(),
        2,
        "delivered a second time: a duplicate is recoverable by a human reading two \
         copies, and a dropped message is not"
    );
    assert!(spool.queued().await.unwrap().is_empty());
}
