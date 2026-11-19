use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub id: String,
    pub from: Option<String>,
    pub to: Vec<String>,
    pub helo: String,
    pub peer: String,
    pub received_at_unix_ms: u64,
    pub size: u64,
    #[serde(default)]
    pub received: String,
    #[serde(default)]
    pub authentication_results: String,
    #[serde(default)]
    pub last_reply: Option<String>,
    #[serde(default)]
    pub attempts: u32,
    #[serde(default)]
    pub next_attempt_unix_ms: u64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub via: BTreeMap<String, String>,
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
            via: BTreeMap::new(),
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
