use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsEvent {
    pub id: Uuid,
    pub received_at: DateTime<Utc>,
    pub source_host: String,
    pub subscription_id: Option<String>,
    pub raw_xml: String,
    pub parsed: Option<ParsedEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedEvent {
    pub provider: String,
    pub event_id: u32,
    pub level: EventLevel,
    pub task: u16,
    pub opcode: u8,
    pub keywords: u64,
    pub time_created: DateTime<Utc>,
    pub event_record_id: u64,
    pub process_id: Option<u32>,
    pub thread_id: Option<u32>,
    pub channel: String,
    pub computer: String,
    pub security_user_id: Option<String>,
    pub message: Option<String>,
    pub data: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum EventLevel {
    Critical = 1,
    Error = 2,
    Warning = 3,
    Information = 4,
    Verbose = 5,
}

impl Default for EventLevel {
    fn default() -> Self {
        EventLevel::Information
    }
}

impl WindowsEvent {
    pub fn new(source_host: String, raw_xml: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            received_at: Utc::now(),
            source_host,
            subscription_id: None,
            raw_xml,
            parsed: None,
        }
    }

    pub fn with_parsed(mut self, parsed: ParsedEvent) -> Self {
        self.parsed = Some(parsed);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionRequest {
    pub subscription_id: String,
    pub source_host: String,
    pub query: String,
    pub heartbeat_interval: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heartbeat {
    pub subscription_id: String,
    pub source_host: String,
    pub timestamp: DateTime<Utc>,
}
