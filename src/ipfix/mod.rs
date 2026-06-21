//! IPFIX / NetFlow flow record types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::net::IpAddr;

pub mod decoder;
pub mod listener;

/// A single decoded network flow record, normalised across IPFIX v10,
/// NetFlow v9, and NetFlow v5.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FlowRecord {
    // identity / provenance
    pub observation_domain_id: u32,
    pub template_id: u16,
    pub protocol_version: u8,
    pub exporter: IpAddr,
    pub export_time: DateTime<Utc>,
    // curated common flow fields
    pub src_addr: Option<IpAddr>,
    pub dst_addr: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub ip_protocol: Option<u8>,
    pub octet_delta_count: Option<u64>,
    pub packet_delta_count: Option<u64>,
    pub flow_start: Option<DateTime<Utc>>,
    pub flow_end: Option<DateTime<Utc>>,
    pub tcp_flags: Option<u8>,
    pub input_interface: Option<u32>,
    pub output_interface: Option<u32>,
    /// Non-curated fields: keyed by IE name or "ie<id>" / "ie<pen>:<id>".
    /// Unknown byte values are hex-encoded strings.
    pub extra: JsonValue,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::net::Ipv4Addr;

    fn make_minimal_record() -> FlowRecord {
        FlowRecord {
            observation_domain_id: 0,
            template_id: 0,
            protocol_version: 5,
            exporter: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            export_time: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            src_addr: None,
            dst_addr: None,
            src_port: None,
            dst_port: None,
            ip_protocol: None,
            octet_delta_count: None,
            packet_delta_count: None,
            flow_start: None,
            flow_end: None,
            tcp_flags: None,
            input_interface: None,
            output_interface: None,
            extra: serde_json::json!({}),
        }
    }

    #[test]
    fn flow_record_roundtrips_json() {
        let rec = make_minimal_record();
        let json = serde_json::to_string(&rec).expect("serialise");
        let back: FlowRecord = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(rec, back);
    }

    #[test]
    fn flow_record_extra_stores_arbitrary_json() {
        let mut rec = make_minimal_record();
        rec.extra = serde_json::json!({ "ie200": "deadbeef", "ie0:300": "cafebabe" });
        assert_eq!(rec.extra["ie200"], "deadbeef");
    }

    #[test]
    fn flow_record_clone_is_independent() {
        let rec = make_minimal_record();
        let mut clone = rec.clone();
        clone.protocol_version = 10;
        // Original unchanged
        assert_eq!(rec.protocol_version, 5);
    }
}
