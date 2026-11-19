use std::time::Duration;

use tokio::sync::{mpsc, watch};

#[derive(Debug, Clone)]
pub struct Shutdown(watch::Receiver<bool>);

impl Shutdown {
    pub fn never() -> Self {
        let (tx, rx) = watch::channel(false);
        std::mem::forget(tx);
        Self(rx)
    }

    pub fn requested(&self) -> bool {
        *self.0.borrow()
    }

    pub async fn wait(&mut self) {
        if self.requested() {
            return;
        }
        while self.0.changed().await.is_ok() {
            if self.requested() {
                return;
            }
        }
        std::future::pending::<()>().await
    }
}

#[derive(Debug)]
pub struct Trigger(watch::Sender<bool>);

impl Trigger {
    pub fn fire(&self) {
        self.0.send_replace(true);
    }

    pub fn subscribe(&self) -> Shutdown {
        Shutdown(self.0.subscribe())
    }
}

pub fn channel() -> (Trigger, Shutdown) {
    let (tx, rx) = watch::channel(false);
    (Trigger(tx), Shutdown(rx))
}

#[derive(Debug, Clone)]
pub struct Tracker(#[allow(dead_code)] mpsc::Sender<()>);

#[derive(Debug)]
pub struct Idle(mpsc::Receiver<()>);

impl Idle {
    pub async fn wait(mut self, within: Duration) -> bool {
        tokio::time::timeout(within, async { while self.0.recv().await.is_some() {} })
            .await
            .is_ok()
    }
}

pub fn tracker() -> (Tracker, Idle) {
    let (tx, rx) = mpsc::channel(1);
    (Tracker(tx), Idle(rx))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_shutdown_that_was_never_asked_for_never_resolves() {
        let mut never = Shutdown::never();

        assert!(!never.requested());
        assert!(
            tokio::time::timeout(Duration::from_millis(50), never.wait())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn firing_reaches_every_subscriber_and_stays_fired() {
        let (trigger, mut first) = channel();
        let mut second = trigger.subscribe();
        trigger.fire();

        first.wait().await;
        second.wait().await;

        assert!(first.requested());
        assert!(second.requested());
    }

    #[tokio::test]
    async fn a_subscriber_made_after_the_fact_is_still_told() {
        let (trigger, _) = channel();
        trigger.fire();
        let mut late = trigger.subscribe();

        tokio::time::timeout(Duration::from_millis(50), late.wait())
            .await
            .expect("a late subscriber must not wait for a second fire");
    }

    #[tokio::test]
    async fn idle_waits_for_the_last_holder_and_no_longer() {
        let (tracker, idle) = tracker();
        let second = tracker.clone();

        let task = tokio::spawn(async move { idle.wait(Duration::from_secs(5)).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!task.is_finished());

        drop(tracker);
        drop(second);

        assert!(task.await.unwrap());
    }

    #[tokio::test]
    async fn idle_gives_up_on_a_holder_that_will_not_finish() {
        let (tracker, idle) = tracker();

        assert!(
            !idle.wait(Duration::from_millis(50)).await,
            "the deadline is the whole point: a session that never ends must not \
             keep the process alive"
        );
        drop(tracker);
    }
}
