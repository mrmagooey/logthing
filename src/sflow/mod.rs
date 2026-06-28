//! sFlow v5 record types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::net::IpAddr;

pub mod decoder;
pub mod listener;

/// Discriminates between sFlow flow samples and counter samples.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SampleType {
    Flow,
    Counter,
}

/// A single decoded sFlow v5 record, normalised across flow and counter samples.
///
/// Flow records carry 5-tuple + sampling metadata.
/// Counter records carry generic interface counter fields (RFC 3176 §5.4.1).
/// Non-curated record types land in `extra` as `{ "format": N, "length": N, "data_base64": "..." }`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SflowRecord {
    // identity / provenance
    pub sample_type: SampleType,
    pub exporter: IpAddr,
    pub received_at: DateTime<Utc>,
    // ── flow sample fields (Some for Flow, None for Counter) ──
    pub src_addr: Option<IpAddr>,
    pub dst_addr: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub ip_protocol: Option<u8>,
    pub sampling_rate: Option<u32>,
    pub input_ifindex: Option<u32>,
    pub output_ifindex: Option<u32>,
    // ── counter sample fields (Some for Counter, None for Flow) ──
    pub if_index: Option<u32>,
    pub if_type: Option<u32>,
    pub if_speed: Option<u64>,
    pub if_direction: Option<u32>,
    pub if_in_octets: Option<u64>,
    pub if_out_octets: Option<u64>,
    pub if_in_ucast_pkts: Option<u64>,
    pub if_out_ucast_pkts: Option<u64>,
    pub if_in_errors: Option<u32>,
    pub if_out_errors: Option<u32>,
    /// Non-curated or vendor-specific records land here as JSON objects:
    /// `[{ "format": N, "length": N, "data_base64": "..." }, ...]`
    pub extra: JsonValue,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_flow_record() -> SflowRecord {
        SflowRecord {
            sample_type: SampleType::Flow,
            exporter: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            received_at: chrono::Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            src_addr: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            dst_addr: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            src_port: Some(12345),
            dst_port: Some(443),
            ip_protocol: Some(6),
            sampling_rate: Some(512),
            input_ifindex: Some(1),
            output_ifindex: Some(2),
            // counter fields absent for flow records
            if_index: None,
            if_type: None,
            if_speed: None,
            if_direction: None,
            if_in_octets: None,
            if_out_octets: None,
            if_in_ucast_pkts: None,
            if_out_ucast_pkts: None,
            if_in_errors: None,
            if_out_errors: None,
            extra: serde_json::json!({}),
        }
    }

    #[test]
    fn sflow_record_roundtrips_json() {
        let rec = make_flow_record();
        let json = serde_json::to_string(&rec).expect("serialize");
        let back: SflowRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rec, back);
    }

    #[test]
    fn sample_type_serializes_as_lowercase_string() {
        let flow = SampleType::Flow;
        let counter = SampleType::Counter;
        let fj = serde_json::to_value(&flow).unwrap();
        let cj = serde_json::to_value(&counter).unwrap();
        assert_eq!(fj, serde_json::json!("flow"));
        assert_eq!(cj, serde_json::json!("counter"));
    }

    #[test]
    fn sflow_record_clone_is_independent() {
        let rec = make_flow_record();
        let mut clone = rec.clone();
        clone.src_port = Some(9999);
        assert_eq!(rec.src_port, Some(12345));
    }

    #[test]
    fn extra_stores_arbitrary_json() {
        let mut rec = make_flow_record();
        rec.extra = serde_json::json!({"raw_format": 1, "data_base64": "AAAA"});
        assert_eq!(rec.extra["raw_format"], 1);
    }
}
