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
use tracing::warn;

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
        // The queue-side message is in this list as well as the two staged
        // files, and it is the one that matters most. The renames go message
        // first, envelope second, so a failure in between leaves
        // `queue/<id>.eml` in place — and `queued()` lists envelopes, so that
        // file is never returned, never delivered and never seen again: a
        // full copy of somebody's message, leaked by the one window the
        // sweep exists for.
        let staged = [
            self.tmp.join(&message),
            self.tmp.join(&sidecar),
            self.queue.join(&message),
        ];

        // Every exit between here and the last rename has to sweep `tmp/`.
        // Returning the error on its own leaves a copy of the message in a
        // directory nothing ever reads again: delivery looks in `queue/`, so
        // a leaked `tmp/<id>.eml` is undeliverable and invisible at once, and
        // it is the full message, so a spool that fails intermittently fills
        // the disk with mail nobody can see. A failed store means the caller
        // answers 4xx and the sending server keeps the message, which is the
        // copy that matters.
        if let Err(e) = self.stage_and_rename(&message, &sidecar, body, &json).await {
            for path in &staged {
                match fs::remove_file(path).await {
                    Ok(()) => {}
                    // Already renamed on, or never created: there was nothing
                    // to clean up, and the store's own error is the one worth
                    // reporting.
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    // Anything else is the sweep failing in the one situation
                    // it exists for, which leaves a copy of a message on disk
                    // that nothing will ever read. Silence here is an
                    // operator watching the disk fill with no way to find
                    // what is filling it, so the path goes in the log.
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

        // Both renames returned, so the message *is* in the queue and will be
        // delivered whatever happens next. A judgement call: a `sync_dir`
        // failure is reported as success, with the risk named, rather than as
        // an error. Returning `Err` would have the session answer the sending
        // server 4xx and log that the message could not be held, while it is
        // sitting in `queue/` waiting to be delivered — the sender then sends
        // it again and the recipient gets two copies, and the log says the
        // opposite of what is on disk. What is actually in doubt is narrower:
        // the directory entry may not survive a power cut in the next moment,
        // which is one message at risk in a crash rather than one message
        // duplicated in every such failure.
        if let Err(e) = sync_dir(&self.queue).await {
            warn!(
                id = %envelope.id,
                "the message is queued, but the queue directory could not be flushed, \
                 so it may not survive a power cut in the next moment: {e}"
            );
        }
        Ok(())
    }

    /// The staging and the two renames, so that [`Spool::store`] has one
    /// place to clean up from. Everything that can leave a file behind is in
    /// here; the directory flush is not, because by then there is nothing
    /// left to sweep and its failure means something else — see
    /// [`Spool::store`].
    async fn stage_and_rename(
        &self,
        message: &str,
        sidecar: &str,
        body: &[u8],
        json: &[u8],
    ) -> io::Result<()> {
        durable_write(&self.tmp.join(message), body).await?;
        durable_write(&self.tmp.join(sidecar), json).await?;

        // The message first, its envelope second: delivery looks for
        // envelopes, so the message becomes visible only once both are there.
        fs::rename(self.tmp.join(message), self.queue.join(message)).await?;
        fs::rename(self.tmp.join(sidecar), self.queue.join(sidecar)).await
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
            received: String::new(),
            last_reply: None,
        }
    }

    fn names(dir: &Path) -> BTreeSet<String> {
        std::fs::read_dir(dir)
            .expect("read dir")
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    }

    /// `tmp/` is a staging area, and anything left in it is a message
    /// nobody will ever look at again: delivery reads `queue/`, so a leaked
    /// `tmp/<id>.eml` is a copy of somebody's mail that is both undeliverable
    /// and invisible.
    ///
    /// The failure is forced by taking the write bit off `queue/`, which is
    /// how this happens in production — a full disk or a mode somebody fixed
    /// by hand — so the two files are written and flushed and then the rename
    /// into `queue/` is refused. The session-level version of this test
    /// asserted `tmp/` was empty after a *successful* store, which was true
    /// before any of this existed and exercised no failure at all.
    #[tokio::test]
    async fn a_store_that_fails_part_way_leaves_nothing_behind_in_tmp() {
        let root = scratch("store-fails");
        let spool = Spool::open(&root).await.unwrap();

        let mut mode = std::fs::metadata(spool.queue_dir()).unwrap().permissions();
        mode.set_readonly(true);
        std::fs::set_permissions(spool.queue_dir(), mode).unwrap();

        let failed = spool.store(&envelope("stuck", 5), b"hello").await;

        // Put the directory back first, so a failing assertion below does not
        // leave an unreadable scratch directory behind.
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

    /// The sweep exists for the window between the two renames, and this is
    /// the half of it that was missed: the message has already moved into
    /// `queue/` and only its envelope failed. `queued()` lists envelopes, so
    /// `queue/<id>.eml` on its own is never returned and never delivered —
    /// a full copy of somebody's message, invisible to everything but `ls`,
    /// which is precisely the leak the sweep was added to prevent.
    ///
    /// The failure is aimed at that one rename by putting a *directory*
    /// where the envelope has to go: `rename(2)` refuses to replace a
    /// directory with a file, so the message's own rename succeeds and the
    /// envelope's does not.
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
