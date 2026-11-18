//! What the SMTP session agreed to, separate from the message itself.
//!
//! The envelope is what delivery acts on: who the sender told us it is from,
//! who it is for, and what mxhop knows about the connection. None of it comes
//! from the message's own headers, which are the sender's claims rather than
//! the session's facts.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// The queue id, which is also the file name.
    pub id: String,
    /// `MAIL FROM`. `None` is the null sender, `<>`: a bounce, which must
    /// never be bounced again.
    pub from: Option<String>,
    /// `RCPT TO`, as given — resolving aliases is delivery's job.
    pub to: Vec<String>,
    /// What the client said in EHLO/HELO. A claim, kept for the trace.
    pub helo: String,
    /// Where the connection came from.
    pub peer: String,
    pub received_at_unix_ms: u64,
    /// The size of the stored message in bytes.
    pub size: u64,
    /// The `Received` header mxhop built for this hop, which is prepended on
    /// the wire and never stored in the message file. A held copy has to be
    /// retried with the identical bytes — a second attempt that re-derives
    /// the header would claim a time the message did not arrive at, and a
    /// different trace would break the only thread an operator can follow
    /// through two logs.
    #[serde(default)]
    pub received: String,
    /// The `Authentication-Results` header mxhop built for this hop, which
    /// goes on the wire directly under `received` and is likewise never
    /// stored in the message file. Empty when the check is switched off.
    ///
    /// Kept for the same reason `received` is: a held copy has to be retried
    /// with the identical bytes, and re-deriving this one would mean repeating
    /// every lookup — possibly getting different answers, and certainly
    /// losing the record of what was true when the message arrived.
    #[serde(default)]
    pub authentication_results: String,
    /// What the destination last said about this message, for the operator
    /// reading `queue/` — and the reason the next attempt is being made.
    #[serde(default)]
    pub last_reply: Option<String>,
    /// How many delivery attempts this copy has already cost. A message
    /// reaches the queue having been tried once already, in the session that
    /// accepted it, so a held envelope is written with `1`: the wait before
    /// the next attempt is a function of this number, and starting it at
    /// zero would try the same destination twice in five minutes.
    #[serde(default)]
    pub attempts: u32,
    /// The earliest moment the queue runner may try again, in unix
    /// milliseconds. `0` — the default, and therefore what an envelope
    /// written before this field existed says — means "now", which is the
    /// right reading: a message that was held under an older build has been
    /// waiting since that build stopped running.
    #[serde(default)]
    pub next_attempt_unix_ms: u64,
}

impl Envelope {
    pub fn is_bounce(&self) -> bool {
        self.from.is_none()
    }
}

pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Envelope {
        Envelope {
            id: "0000001762400000-000001-1a2b".into(),
            from: Some("sender@elsewhere.test".into()),
            to: vec!["hi@example.com".into()],
            helo: "mail.elsewhere.test".into(),
            peer: "198.51.100.7:40000".into(),
            received_at_unix_ms: 1_762_400_000_000,
            size: 42,
            received: "Received: from mail.elsewhere.test\r\n".into(),
            authentication_results: "Authentication-Results: mx.example.com; dkim=none\r\n".into(),
            last_reply: None,
            attempts: 0,
            next_attempt_unix_ms: 0,
        }
    }

    #[test]
    fn an_envelope_survives_the_round_trip_through_json() {
        let json = serde_json::to_string(&sample()).unwrap();
        assert_eq!(serde_json::from_str::<Envelope>(&json).unwrap(), sample());
    }

    #[test]
    fn the_null_sender_round_trips_as_null() {
        let bounce = Envelope {
            from: None,
            ..sample()
        };
        let json = serde_json::to_string(&bounce).unwrap();

        assert!(json.contains("\"from\":null"), "{json}");
        assert!(serde_json::from_str::<Envelope>(&json).unwrap().is_bounce());
    }

    /// An envelope written by a build that had no retry queue still has to
    /// be readable, and it has to come back as a message that is *due*: the
    /// fields it lacks mean "try it now". Refusing to read it, or reading it
    /// as scheduled for the epoch plus a backoff, would leave a message in
    /// `queue/` that nothing ever delivers — which is the state this whole
    /// milestone exists to end.
    #[test]
    fn an_envelope_from_before_the_retry_queue_is_due_immediately() {
        let json = r#"{
            "id": "0000001762400000-000001-1a2b",
            "from": "sender@elsewhere.test",
            "to": ["hi@example.com"],
            "helo": "mail.elsewhere.test",
            "peer": "198.51.100.7:40000",
            "received_at_unix_ms": 1762400000000,
            "size": 42
        }"#;

        let envelope: Envelope = serde_json::from_str(json).expect("an older envelope still reads");

        assert_eq!(envelope.attempts, 0);
        assert_eq!(
            envelope.next_attempt_unix_ms, 0,
            "zero is in the past, so the first sweep after an upgrade picks it up"
        );
    }

    #[test]
    fn a_message_with_a_sender_is_not_a_bounce() {
        assert!(!sample().is_bounce());
    }
}
