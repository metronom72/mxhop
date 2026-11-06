//! The queue on disk: one message, two files.
//!
//! `queue/<id>.eml` is the message exactly as it arrived; `queue/<id>.json` is
//! its envelope. Two files rather than a database because `ls` and `cat` are
//! then the whole administration interface, and a message stuck in a queue is
//! something an operator should be able to read without a tool.
//!
//! The order of operations is the part that matters. Both files are written
//! into `tmp/`, flushed to the platter, and only then renamed into `queue/` —
//! the envelope last. A message becomes visible to delivery when, and only
//! when, its envelope is there, so `kill -9` at any point leaves either
//! nothing or a complete message, never half of one. mxhop answers `250` only
//! after that rename has returned: before it, the sending server still owns
//! the message, which is exactly where responsibility belongs.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::fs;
use tokio::io::AsyncWriteExt;

use crate::envelope::Envelope;

/// A fresh queue id. Sorts by time, so `ls` shows the queue in arrival order.
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
}

impl Spool {
    /// Opens (and creates) the spool directories.
    pub async fn open(root: impl AsRef<Path>) -> io::Result<Self> {
        let root = root.as_ref();
        let spool = Self {
            tmp: root.join("tmp"),
            queue: root.join("queue"),
        };
        fs::create_dir_all(&spool.tmp).await?;
        fs::create_dir_all(&spool.queue).await?;
        Ok(spool)
    }

    /// Stores one message. Returns when it is durably in the queue.
    pub async fn store(&self, envelope: &Envelope, body: &[u8]) -> io::Result<()> {
        let message = format!("{}.eml", envelope.id);
        let sidecar = format!("{}.json", envelope.id);

        let json = serde_json::to_vec_pretty(envelope).map_err(io::Error::other)?;
        durable_write(&self.tmp.join(&message), body).await?;
        durable_write(&self.tmp.join(&sidecar), &json).await?;

        // The message first, its envelope second: delivery looks for
        // envelopes, so the message becomes visible only once both are there.
        fs::rename(self.tmp.join(&message), self.queue.join(&message)).await?;
        fs::rename(self.tmp.join(&sidecar), self.queue.join(&sidecar)).await?;
        sync_dir(&self.queue).await
    }

    /// Every complete message in the queue, in arrival order.
    pub async fn queued(&self) -> io::Result<Vec<Envelope>> {
        let mut entries = fs::read_dir(&self.queue).await?;
        let mut found = Vec::new();

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            // One unreadable envelope is one stuck message, not a stuck
            // queue: the rest still have to be delivered.
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

    /// The stored message belonging to an envelope.
    pub async fn body(&self, id: &str) -> io::Result<Vec<u8>> {
        fs::read(self.queue.join(format!("{id}.eml"))).await
    }

    pub fn queue_dir(&self) -> &Path {
        &self.queue
    }

    pub fn tmp_dir(&self) -> &Path {
        &self.tmp
    }
}

/// Writes a file and waits for the platter, not the page cache.
async fn durable_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = fs::File::create(path).await?;
    file.write_all(bytes).await?;
    file.sync_all().await
}

/// Flushes a directory entry, which is what makes a rename survive a power
/// cut. Not every filesystem allows it; where it is refused, the rename is
/// already durable.
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
        }
    }

    fn names(dir: &Path) -> BTreeSet<String> {
        std::fs::read_dir(dir)
            .expect("read dir")
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
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
        // This is what `kill -9` between the two renames leaves behind. It has
        // to be invisible to delivery: half a message delivered is worse than
        // none.
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
