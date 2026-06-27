//! Syslog payload sub-parsers.
//!
//! Each parser module exposes `try_parse(&SyslogMessage) -> Option<Payload>`
//! following the DNS try-chain pattern.  `dispatch` runs the chain and returns
//! the first match as a `SyslogPayload` variant, or `SyslogPayload::None`.

use crate::syslog::SyslogMessage;
use chrono::{DateTime, Utc};
use serde_json::Value;

pub mod auditd;
pub mod cef;
pub mod dhcp;
pub mod leef;
pub mod radius;
pub mod web_access;

// ---------------------------------------------------------------------------
// Output types (defined once, referenced by all tasks)
// ---------------------------------------------------------------------------

/// Parsed payload extracted from a syslog message body.
/// Each variant carries the fields specific to that format; `None` means no
/// sub-parser matched.
#[derive(Debug, Clone)]
pub enum SyslogPayload {
    Cef(cef::CefRecord),
    Leef(leef::LeefRecord),
    Auditd(auditd::AuditdRecord),
    Dhcp(dhcp::DhcpRecord),
    Radius(radius::RadiusRecord),
    WebAccess(web_access::WebAccessRecord),
    Dns(crate::syslog::dns::DnsLogEntry),
    None,
}

impl SyslogPayload {
    /// The canonical S3 partition string for this variant.
    /// Returns `None` for `SyslogPayload::None` (caller must gate on this).
    pub fn payload_type(&self) -> Option<&'static str> {
        match self {
            SyslogPayload::Cef(_)       => Some("cef"),
            SyslogPayload::Leef(_)      => Some("leef"),
            SyslogPayload::Auditd(_)    => Some("auditd"),
            SyslogPayload::Dhcp(_)      => Some("dhcp"),
            SyslogPayload::Radius(_)    => Some("radius"),
            SyslogPayload::WebAccess(_) => Some("web_access"),
            SyslogPayload::Dns(_)       => Some("dns"),
            SyslogPayload::None         => Option::None,
        }
    }

    /// Serialize the inner parsed struct to a JSON `Value`.
    pub fn to_json(&self) -> Value {
        match self {
            SyslogPayload::Cef(r)       => serde_json::to_value(r).unwrap_or(Value::Null),
            SyslogPayload::Leef(r)      => serde_json::to_value(r).unwrap_or(Value::Null),
            SyslogPayload::Auditd(r)    => serde_json::to_value(r).unwrap_or(Value::Null),
            SyslogPayload::Dhcp(r)      => serde_json::to_value(r).unwrap_or(Value::Null),
            SyslogPayload::Radius(r)    => serde_json::to_value(r).unwrap_or(Value::Null),
            SyslogPayload::WebAccess(r) => serde_json::to_value(r).unwrap_or(Value::Null),
            SyslogPayload::Dns(r)       => serde_json::to_value(r).unwrap_or(Value::Null),
            SyslogPayload::None         => Value::Null,
        }
    }
}

/// The structured record written to `StructuredSyslogSink`.
/// Carries the syslog envelope fields plus the payload type tag and the
/// parsed-fields JSON blob.  No bespoke typed Parquet schema per format in v1.
#[derive(Debug, Clone)]
pub struct StructuredSyslogRecord {
    // Syslog envelope
    pub priority: u8,
    pub severity: u8,
    pub facility: u8,
    pub timestamp: Option<DateTime<Utc>>,
    pub hostname: Option<String>,
    pub app_name: Option<String>,
    pub received_at: DateTime<Utc>,
    // Payload
    pub payload_type: &'static str,
    pub parsed: Value,
}

impl StructuredSyslogRecord {
    /// Build from a `SyslogMessage` and a matched `SyslogPayload`.
    /// Returns `None` when `payload` is `SyslogPayload::None`.
    pub fn from_syslog_and_payload(
        msg: &SyslogMessage,
        payload: &SyslogPayload,
    ) -> Option<Self> {
        let payload_type = payload.payload_type()?;
        Some(Self {
            priority: msg.priority,
            severity: msg.severity,
            facility: msg.facility,
            timestamp: msg.timestamp,
            hostname: msg.hostname.clone(),
            app_name: msg.app_name.clone(),
            received_at: Utc::now(),
            payload_type,
            parsed: payload.to_json(),
        })
    }
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

/// Try all sub-parsers in priority order and return the first match.
///
/// Priority order:
/// 1. Prefix-keyed (fast rejection on first bytes): CEF, LEEF
/// 2. Key=value record formats: auditd
/// 3. Regex line formats: DHCP, RADIUS, web_access
/// 4. DNS (existing try-chain via `DnsLogEntry::from_syslog`)
/// 5. None
pub fn dispatch(msg: &SyslogMessage) -> SyslogPayload {
    if let Some(r) = cef::try_parse(msg)       { return SyslogPayload::Cef(r); }
    if let Some(r) = leef::try_parse(msg)      { return SyslogPayload::Leef(r); }
    if let Some(r) = auditd::try_parse(msg)    { return SyslogPayload::Auditd(r); }
    if let Some(r) = dhcp::try_parse(msg)      { return SyslogPayload::Dhcp(r); }
    if let Some(r) = radius::try_parse(msg)    { return SyslogPayload::Radius(r); }
    if let Some(r) = web_access::try_parse(msg){ return SyslogPayload::WebAccess(r); }
    if let Some(r) = crate::syslog::dns::DnsLogEntry::from_syslog(msg) {
        return SyslogPayload::Dns(r);
    }
    SyslogPayload::None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syslog::{SyslogMessage, SyslogProtocol};

    fn bare_msg(text: &str) -> SyslogMessage {
        SyslogMessage {
            priority: 134,
            severity: 6,
            facility: 16,
            timestamp: None,
            hostname: Some("host".into()),
            app_name: Some("app".into()),
            proc_id: None,
            msg_id: None,
            message: text.to_string(),
            structured_data: None,
            protocol: SyslogProtocol::Rfc3164,
        }
    }

    #[test]
    fn dispatch_unknown_message_returns_none_variant() {
        let msg = bare_msg("this is not any known format");
        assert!(matches!(dispatch(&msg), SyslogPayload::None));
    }

    #[test]
    fn structured_syslog_record_payload_type_roundtrip() {
        let msg = bare_msg("irrelevant");
        let rec = StructuredSyslogRecord {
            priority: msg.priority,
            severity: msg.severity,
            facility: msg.facility,
            timestamp: None,
            hostname: msg.hostname.clone(),
            app_name: msg.app_name.clone(),
            received_at: chrono::Utc::now(),
            payload_type: "cef",
            parsed: serde_json::json!({"vendor": "Acme"}),
        };
        assert_eq!(rec.payload_type, "cef");
        assert_eq!(rec.parsed["vendor"], "Acme");
    }
}
