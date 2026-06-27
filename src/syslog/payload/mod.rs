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
    macro_rules! try_parser {
        ($variant:ident, $module:ident) => {
            if let Some(r) = $module::try_parse(msg) {
                let payload = SyslogPayload::$variant(r);
                if let Some(t) = payload.payload_type() {
                    metrics::counter!("syslog_payload_parsed", "type" => t).increment(1);
                }
                return payload;
            }
        };
    }

    try_parser!(Cef,       cef);
    try_parser!(Leef,      leef);
    try_parser!(Auditd,    auditd);
    try_parser!(Dhcp,      dhcp);
    try_parser!(Radius,    radius);
    try_parser!(WebAccess, web_access);

    if let Some(r) = crate::syslog::dns::DnsLogEntry::from_syslog(msg) {
        metrics::counter!("syslog_payload_parsed", "type" => "dns").increment(1);
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
    fn dispatch_cef_message_returns_cef_variant() {
        let m = bare_msg(
            "CEF:0|Vendor|Product|1.0|100|Login|5|src=10.0.0.1 dst=10.0.0.2",
        );
        let p = dispatch(&m);
        assert!(
            matches!(p, SyslogPayload::Cef(_)),
            "expected Cef variant, got {:?}",
            p.payload_type()
        );
    }

    #[test]
    fn dispatch_leef_message_returns_leef_variant() {
        let m = bare_msg("LEEF:1.0|V|P|1.0|E|\tkey=val");
        assert!(matches!(dispatch(&m), SyslogPayload::Leef(_)));
    }

    #[test]
    fn dispatch_auditd_message_returns_auditd_variant() {
        let m = bare_msg("type=SYSCALL msg=audit(1609459200.000:1): syscall=59 success=yes");
        assert!(matches!(dispatch(&m), SyslogPayload::Auditd(_)));
    }

    #[test]
    fn dispatch_dhcp_message_returns_dhcp_variant() {
        let m = bare_msg("DHCPACK on 10.0.0.5 to aa:bb:cc:dd:ee:ff (host) via eth0");
        assert!(matches!(dispatch(&m), SyslogPayload::Dhcp(_)));
    }

    #[test]
    fn dispatch_radius_message_returns_radius_variant() {
        let m = bare_msg("Login OK: [alice] (from client vpn port 10)");
        assert!(matches!(dispatch(&m), SyslogPayload::Radius(_)));
    }

    #[test]
    fn dispatch_web_access_message_returns_web_access_variant() {
        let m = bare_msg(
            r#"192.168.1.1 - - [15/Jan/2024:10:00:00 +0000] "GET / HTTP/1.1" 200 1234 "-" "-""#,
        );
        assert!(matches!(dispatch(&m), SyslogPayload::WebAccess(_)));
    }

    #[test]
    fn dispatch_dns_bind_returns_dns_variant() {
        let m = bare_msg(
            "client 192.168.1.10#12345: query: example.com IN A + (93.184.216.34)",
        );
        assert!(matches!(dispatch(&m), SyslogPayload::Dns(_)));
    }

    #[test]
    fn payload_type_returns_expected_strings() {
        assert_eq!(SyslogPayload::None.payload_type(), None);
        // Just verify the string constants — real variants tested above.
        assert_eq!(
            SyslogPayload::Dhcp(crate::syslog::payload::dhcp::DhcpRecord {
                message_type: "DHCPACK".into(),
                ip_address: None, mac_address: None, hostname: None, interface: None,
            }).payload_type(),
            Some("dhcp")
        );
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
