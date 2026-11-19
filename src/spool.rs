use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::fs;
use tokio::io::AsyncWriteExt;
use tracing::warn;

use crate::envelope::Envelope;

pub fn new_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let ms = crate::envelope::now_unix_ms();
    let n = COUNTER.fetch_add(1, Ordering::Relaxed) & 0xff_ffff;
    format!("{ms:013}-{n:06x}-{:04x}", std::process::id() & 0xffff)
}

#[derive(Debug, Clone)]
pub struct Spool {
    tmp: PathBuf,
    queue: PathBuf,
    frozen: PathBuf,
}

impl Spool {
    pub async fn open(root: impl AsRef<Path>) -> io::Result<Self> {
        let root = root.as_ref();
        let spool = Self {
            tmp: root.join("tmp"),
            queue: root.join("queue"),
            frozen: root.join("frozen"),
        };
        fs::create_dir_all(&spool.tmp).await?;
        fs::create_dir_all(&spool.queue).await?;
        fs::create_dir_all(&spool.frozen).await?;
        Ok(spool)
    }

    pub async fn store(&self, envelope: &Envelope, body: &[u8]) -> io::Result<()> {
        let message = format!("{}.eml", envelope.id);
        let sidecar = format!("{}.json", envelope.id);

        let json = serde_json::to_vec_pretty(envelope).map_err(io::Error::other)?;
        let staged = [
            self.tmp.join(&message),
            self.tmp.join(&sidecar),
            self.queue.join(&message),
        ];

        if let Err(e) = self.stage_and_rename(&message, &sidecar, body, &json).await {
            for path in &staged {
                match fs::remove_file(path).await {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => warn!(
                        path = %path.display(),
                        "a half-stored message could not be removed; it is a copy of \
                         somebody's mail that nothing will deliver and nothing else \
                         will report: {e}"
                    ),
                }
            }
            return Err(e);
        }

        if let Err(e) = sync_dir(&self.queue).await {
            warn!(
                id = %envelope.id,
                "the message is queued, but the queue directory could not be flushed, \
                 so it may not survive a power cut in the next moment: {e}"
            );
        }
        Ok(())
    }

    async fn stage_and_rename(
        &self,
        message: &str,
        sidecar: &str,
        body: &[u8],
        json: &[u8],
    ) -> io::Result<()> {
        durable_write(&self.tmp.join(message), body).await?;
        durable_write(&self.tmp.join(sidecar), json).await?;

        fs::rename(self.tmp.join(message), self.queue.join(message)).await?;
        fs::rename(self.tmp.join(sidecar), self.queue.join(sidecar)).await
    }

    pub async fn queued(&self) -> io::Result<Vec<Envelope>> {
        let mut entries = fs::read_dir(&self.queue).await?;
        let mut found = Vec::new();

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            match fs::read(&path).await {
                Ok(bytes) => match serde_json::from_slice::<Envelope>(&bytes) {
                    Ok(envelope) => found.push(envelope),
                    Err(_) => continue,
                },
                Err(_) => continue,
            }
        }

        found.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(found)
    }

    pub async fn body(&self, id: &str) -> io::Result<Vec<u8>> {
        fs::read(self.queue.join(format!("{id}.eml"))).await
    }

    pub async fn update(&self, envelope: &Envelope) -> io::Result<()> {
        let sidecar = format!("{}.json", envelope.id);
        let json = serde_json::to_vec_pretty(envelope).map_err(io::Error::other)?;
        let staged = self.tmp.join(&sidecar);

        if let Err(e) = durable_write(&staged, &json).await {
            self.sweep(&staged).await;
            return Err(e);
        }
        if let Err(e) = fs::rename(&staged, self.queue.join(&sidecar)).await {
            self.sweep(&staged).await;
            return Err(e);
        }

        if let Err(e) = sync_dir(&self.queue).await {
            warn!(
                id = %envelope.id,
                "the envelope is updated, but the queue directory could not be \
                 flushed, so a power cut in the next moment could bring the previous \
                 attempt count back: {e}"
            );
        }
        Ok(())
    }

    pub async fn forget(&self, id: &str) -> io::Result<()> {
        let mut failure = None;
        for name in [format!("{id}.eml"), format!("{id}.json")] {
            match fs::remove_file(self.queue.join(&name)).await {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => failure = Some(e),
            }
        }
        match failure {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    pub async fn freeze(&self, id: &str) -> io::Result<()> {
        let message = format!("{id}.eml");
        let sidecar = format!("{id}.json");

        match fs::rename(self.queue.join(&message), self.frozen.join(&message)).await {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        fs::rename(self.queue.join(&sidecar), self.frozen.join(&sidecar)).await
    }

    async fn sweep(&self, path: &Path) {
        match fs::remove_file(path).await {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => warn!(
                path = %path.display(),
                "a staged file could not be removed; nothing will ever read it and \
                 nothing else will report it: {e}"
            ),
        }
    }

    pub fn queue_dir(&self) -> &Path {
        &self.queue
    }

    pub fn tmp_dir(&self) -> &Path {
        &self.tmp
    }

    pub fn frozen_dir(&self) -> &Path {
        &self.frozen
    }
}

async fn durable_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = fs::File::create(path).await?;
    file.write_all(bytes).await?;
    file.sync_all().await
}

async fn sync_dir(path: &Path) -> io::Result<()> {
    let dir = fs::File::open(path).await?;
    match dir.sync_all().await {
        Err(e) if e.kind() == io::ErrorKind::InvalidInput => Ok(()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join("mxhop-tests")
            .join(format!("{name}-{}", new_id()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    fn envelope(id: &str, body_len: u64) -> Envelope {
        Envelope {
            id: id.to_string(),
            from: Some("sender@elsewhere.test".into()),
            to: vec!["hi@example.com".into()],
            helo: "mail.elsewhere.test".into(),
            peer: "198.51.100.7:40000".into(),
            received_at_unix_ms: crate::envelope::now_unix_ms(),
            size: body_len,
            received: String::new(),
            authentication_results: String::new(),
            last_reply: None,
            attempts: 0,
            next_attempt_unix_ms: 0,
            via: Default::default(),
        }
    }

    fn names(dir: &Path) -> BTreeSet<String> {
        std::fs::read_dir(dir)
            .expect("read dir")
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    }

    #[tokio::test]
    async fn a_store_that_fails_part_way_leaves_nothing_behind_in_tmp() {
        let root = scratch("store-fails");
        let spool = Spool::open(&root).await.unwrap();

        let mut mode = std::fs::metadata(spool.queue_dir()).unwrap().permissions();
        mode.set_readonly(true);
        std::fs::set_permissions(spool.queue_dir(), mode).unwrap();

        let failed = spool.store(&envelope("stuck", 5), b"hello").await;

        let mut mode = std::fs::metadata(spool.queue_dir()).unwrap().permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            mode.set_mode(0o755);
        }
        #[cfg(not(unix))]
        mode.set_readonly(false);
        std::fs::set_permissions(spool.queue_dir(), mode).unwrap();

        assert!(
            failed.is_err(),
            "a queue directory that cannot be written to is not a successful store"
        );
        assert_eq!(
            names(spool.tmp_dir()),
            BTreeSet::new(),
            "the store failed, so the caller will answer 4xx and the sending server \
             keeps the message — our half-written copy has to go"
        );
        assert_eq!(
            names(spool.queue_dir()),
            BTreeSet::new(),
            "and nothing half-arrived in the queue either"
        );
    }

    #[tokio::test]
    async fn a_store_whose_envelope_cannot_be_renamed_leaves_no_message_in_the_queue() {
        let root = scratch("sidecar-fails");
        let spool = Spool::open(&root).await.unwrap();
        std::fs::create_dir(spool.queue_dir().join("blocked.json")).unwrap();

        let failed = spool.store(&envelope("blocked", 5), b"hello").await;

        assert!(
            failed.is_err(),
            "the envelope never arrived, so the message is not in the queue and \
             the caller has to answer 4xx"
        );
        assert!(
            names(spool.tmp_dir()).is_empty(),
            "nothing staged may be left behind"
        );
        assert_eq!(
            names(spool.queue_dir()),
            BTreeSet::from(["blocked.json".to_string()]),
            "and `blocked.eml` has to be gone too: it is the whole message, and \
             without its envelope nothing will ever look at it again"
        );
        assert!(
            spool.queued().await.unwrap().is_empty(),
            "the queue is as it was"
        );
    }

    #[tokio::test]
    async fn opening_creates_the_directories() {
        let root = scratch("open").join("nested");
        let spool = Spool::open(&root).await.unwrap();

        assert!(spool.queue_dir().is_dir());
        assert!(spool.tmp_dir().is_dir());
    }

    #[tokio::test]
    async fn opening_an_existing_spool_keeps_what_is_in_it() {
        let root = scratch("reopen");
        let spool = Spool::open(&root).await.unwrap();
        let body = b"Subject: hi\r\n\r\nbody\r\n";
        spool
            .store(&envelope("id-one", body.len() as u64), body)
            .await
            .unwrap();

        let reopened = Spool::open(&root).await.unwrap();
        assert_eq!(reopened.queued().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_stored_message_is_in_the_queue_and_nothing_is_left_in_tmp() {
        let root = scratch("store");
        let spool = Spool::open(&root).await.unwrap();
        let body = b"Subject: hi\r\n\r\nbody\r\n";

        spool
            .store(&envelope("id-one", body.len() as u64), body)
            .await
            .unwrap();

        assert_eq!(
            names(spool.queue_dir()),
            BTreeSet::from(["id-one.eml".to_string(), "id-one.json".to_string()])
        );
        assert!(
            names(spool.tmp_dir()).is_empty(),
            "a leftover in tmp is a message nobody will ever deliver"
        );
    }

    #[tokio::test]
    async fn the_stored_message_is_byte_for_byte_what_arrived() {
        let root = scratch("bytes");
        let spool = Spool::open(&root).await.unwrap();
        let body = b"From: a@b.test\r\nSubject: =?utf-8?B?0YLQtdGB0YI=?=\r\n\r\n  spaces  \r\n\xff\xfe\r\n";

        spool
            .store(&envelope("id-bytes", body.len() as u64), body)
            .await
            .unwrap();

        assert_eq!(
            spool.body("id-bytes").await.unwrap(),
            body,
            "one changed byte invalidates the sender's DKIM signature"
        );
    }

    #[tokio::test]
    async fn the_envelope_comes_back_as_it_went_in() {
        let root = scratch("envelope");
        let spool = Spool::open(&root).await.unwrap();
        let sent = envelope("id-env", 7);

        spool.store(&sent, b"hello\r\n").await.unwrap();

        assert_eq!(spool.queued().await.unwrap(), vec![sent]);
    }

    #[tokio::test]
    async fn the_queue_is_listed_in_arrival_order() {
        let root = scratch("order");
        let spool = Spool::open(&root).await.unwrap();
        for id in ["0000000000001-000000-0001", "0000000000002-000000-0001"] {
            spool.store(&envelope(id, 2), b"x\r\n").await.unwrap();
        }

        let ids: Vec<String> = spool
            .queued()
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.id)
            .collect();
        assert_eq!(
            ids,
            vec!["0000000000001-000000-0001", "0000000000002-000000-0001"]
        );
    }

    #[tokio::test]
    async fn a_message_without_its_envelope_is_not_in_the_queue() {
        let root = scratch("orphan");
        let spool = Spool::open(&root).await.unwrap();
        std::fs::write(spool.queue_dir().join("orphan.eml"), b"body\r\n").unwrap();

        assert!(spool.queued().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_unreadable_envelope_does_not_hide_the_rest_of_the_queue() {
        let root = scratch("broken-sidecar");
        let spool = Spool::open(&root).await.unwrap();
        spool.store(&envelope("good", 2), b"x\r\n").await.unwrap();
        std::fs::write(spool.queue_dir().join("bad.json"), b"{not json").unwrap();

        let queued = spool.queued().await.unwrap();
        assert_eq!(queued.len(), 1, "the good one still has to be delivered");
        assert_eq!(queued[0].id, "good");
    }

    #[tokio::test]
    async fn an_updated_envelope_is_what_comes_back_and_the_message_is_untouched() {
        let root = scratch("update");
        let spool = Spool::open(&root).await.unwrap();
        let body = b"Subject: hi\r\n\r\nbody\r\n";
        spool
            .store(&envelope("id-upd", body.len() as u64), body)
            .await
            .unwrap();

        let rescheduled = Envelope {
            attempts: 3,
            next_attempt_unix_ms: 1_762_400_000_000,
            last_reply: Some("hi@example.com: 451 4.3.0 try later".into()),
            ..envelope("id-upd", body.len() as u64)
        };
        spool.update(&rescheduled).await.unwrap();

        assert_eq!(spool.queued().await.unwrap(), vec![rescheduled]);
        assert_eq!(
            spool.body("id-upd").await.unwrap(),
            body,
            "a retry has to be the identical bytes, or the sender's DKIM signature \
             stops verifying on the second attempt"
        );
        assert!(
            names(spool.tmp_dir()).is_empty(),
            "the staged envelope has to be gone"
        );
    }

    #[tokio::test]
    async fn a_forgotten_message_leaves_nothing_behind() {
        let root = scratch("forget");
        let spool = Spool::open(&root).await.unwrap();
        spool.store(&envelope("gone", 2), b"x\r\n").await.unwrap();

        spool.forget("gone").await.unwrap();

        assert_eq!(
            names(spool.queue_dir()),
            BTreeSet::new(),
            "a delivered message that stays on disk is delivered again on the next sweep"
        );
    }

    #[tokio::test]
    async fn forgetting_a_message_that_is_already_gone_is_not_a_failure() {
        let root = scratch("forget-twice");
        let spool = Spool::open(&root).await.unwrap();
        spool.store(&envelope("twice", 2), b"x\r\n").await.unwrap();

        spool.forget("twice").await.unwrap();
        spool.forget("twice").await.unwrap();
    }

    #[tokio::test]
    async fn a_frozen_message_is_out_of_the_queue_and_still_on_disk() {
        let root = scratch("freeze");
        let spool = Spool::open(&root).await.unwrap();
        let body = b"Subject: hi\r\n\r\nbody\r\n";
        spool
            .store(&envelope("cold", body.len() as u64), body)
            .await
            .unwrap();

        spool.freeze("cold").await.unwrap();

        assert!(
            spool.queued().await.unwrap().is_empty(),
            "a frozen message is one nothing retries"
        );
        assert_eq!(
            names(spool.frozen_dir()),
            BTreeSet::from(["cold.eml".to_string(), "cold.json".to_string()]),
            "and it is still somebody's mail: it has to be where `ls` finds it, \
             envelope included, so an operator can put it back"
        );
        assert_eq!(
            std::fs::read(spool.frozen_dir().join("cold.eml")).unwrap(),
            body
        );
    }

    #[test]
    fn ids_are_unique_and_sort_by_arrival() {
        let ids: Vec<String> = (0..10_000).map(|_| new_id()).collect();

        let unique: BTreeSet<&String> = ids.iter().collect();
        assert_eq!(
            unique.len(),
            ids.len(),
            "two messages must never share a file"
        );

        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted, "`ls` should show the queue in arrival order");
    }
}
