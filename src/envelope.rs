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
    /// reading `queue/`. Not acted on: there is no retry queue yet.
    #[serde(default)]
    pub last_reply: Option<String>,
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

    #[test]
    fn a_message_with_a_sender_is_not_a_bounce() {
        assert!(!sample().is_bounce());
    }
}
