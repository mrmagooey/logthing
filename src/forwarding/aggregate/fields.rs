//! Field access for aggregation: one small adapter per source record type.
//!
//! Group-by columns and numeric aggregates both go through `AggFields::field`,
//! so a rule can name any field of any source without the aggregator knowing
//! which source it came from.

use std::borrow::Cow;

/// A single scalar field value read off a record.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldValue<'a> {
    Str(Cow<'a, str>),
    Num(f64),
    Bool(bool),
}

/// The per-source adapter contract.
pub trait AggFields {
    /// Stream name a rule's optional `stream` filter matches against.
    fn stream(&self) -> &str;
    /// Look up one field by the name a rule configured.
    fn field(&self, name: &str) -> Option<FieldValue<'_>>;
}

/// Cap on a single group value. Bounds worst-case aggregator memory to
/// `max_groups * group_by.len() * MAX_GROUP_VALUE_BYTES` per rule.
//
// ponytail: fixed 256-byte cap, so two keys sharing a 256-byte prefix merge
// into one group. Raise the constant if that ever matters.
pub const MAX_GROUP_VALUE_BYTES: usize = 256;

/// Truncate to at most `max` bytes, walking back to the nearest char boundary
/// so the result is always valid UTF-8.
pub fn truncate_to_bytes(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Render a field value as a group-key component.
pub fn group_value_string(v: FieldValue<'_>) -> String {
    let s = match v {
        FieldValue::Str(s) => return truncate_to_bytes(&s, MAX_GROUP_VALUE_BYTES).to_string(),
        // Whole numbers render as integers: a port grouped as "443", not "443.0".
        FieldValue::Num(n)
            if n.is_finite() && n.fract() == 0.0 && n.abs() < 9.007_199_254_740_992e15 =>
        {
            (n as i64).to_string()
        }
        // `{n:?}` (not `to_string`): Display drops the decimal point for whole
        // floats beyond the i64-shortcut range (e.g. "9007199254740994"),
        // while Debug always keeps it ("...994.0"), which is what a value
        // that hit this fallback needs to still look like a float.
        FieldValue::Num(n) => format!("{n:?}"),
        FieldValue::Bool(b) => b.to_string(),
    };
    // Numeric and boolean renderings are always short, but truncate uniformly
    // so the memory bound holds for every branch.
    truncate_to_bytes(&s, MAX_GROUP_VALUE_BYTES).to_string()
}

/// Numeric contribution of a field value to a sum/min/max accumulator.
///
/// SQL semantics: a value that isn't a usable number contributes nothing (the
/// record is still counted). Numeric strings parse — Zeek and Suricata JSON
/// carry numbers as strings in places, and treating those as absent would
/// produce surprising all-null columns.
pub fn numeric_value(v: &FieldValue<'_>) -> Option<f64> {
    let n = match v {
        FieldValue::Num(n) => *n,
        FieldValue::Str(s) => s.parse::<f64>().ok()?,
        FieldValue::Bool(_) => return None,
    };
    n.is_finite().then_some(n)
}

/// JSON field lookup: literal key first, then a dotted path.
///
/// Zeek NDJSON carries `"id.orig_h"` as one flat key; Suricata EVE nests
/// `dns.rrname`. Trying the literal key first means a flat key always wins,
/// which is what the source that produced it intended.
pub fn json_field<'a>(root: &'a serde_json::Value, name: &str) -> Option<FieldValue<'a>> {
    if let Some(v) = root.get(name) {
        return scalar(v);
    }
    if !name.contains('.') {
        return None;
    }
    let mut cur = root;
    for seg in name.split('.') {
        cur = cur.get(seg)?;
    }
    scalar(cur)
}

/// Map a JSON scalar to a `FieldValue`. Objects, arrays, and null are misses —
/// they are not group-able scalars.
fn scalar(v: &serde_json::Value) -> Option<FieldValue<'_>> {
    match v {
        serde_json::Value::String(s) => Some(FieldValue::Str(Cow::Borrowed(s.as_str()))),
        serde_json::Value::Number(n) => n.as_f64().map(FieldValue::Num),
        serde_json::Value::Bool(b) => Some(FieldValue::Bool(*b)),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Per-source impls: JSON-backed records
// ---------------------------------------------------------------------------

impl AggFields for crate::zeek::ZeekRecord {
    fn stream(&self) -> &str {
        &self.log_path
    }
    fn field(&self, name: &str) -> Option<FieldValue<'_>> {
        json_field(&self.fields, name)
    }
}

impl AggFields for crate::suricata::SuricataRecord {
    fn stream(&self) -> &str {
        &self.event_type
    }
    fn field(&self, name: &str) -> Option<FieldValue<'_>> {
        json_field(&self.fields, name)
    }
}

// ---------------------------------------------------------------------------
// Per-source impls: typed records
// ---------------------------------------------------------------------------

/// Helper: `Option<T: Display>` → `FieldValue::Str`.
fn opt_str<T: std::fmt::Display>(v: &Option<T>) -> Option<FieldValue<'static>> {
    v.as_ref()
        .map(|x| FieldValue::Str(Cow::Owned(x.to_string())))
}

/// Helper: `Option<T: Into<f64>>` → `FieldValue::Num`.
fn opt_num<T: Copy + Into<f64>>(v: &Option<T>) -> Option<FieldValue<'static>> {
    v.map(|x| FieldValue::Num(x.into()))
}

impl AggFields for crate::ipfix::FlowRecord {
    fn stream(&self) -> &str {
        // IPFIX has no stream concept; one bucket keeps rule matching uniform.
        "flows"
    }
    fn field(&self, name: &str) -> Option<FieldValue<'_>> {
        match name {
            "observation_domain_id" => Some(FieldValue::Num(self.observation_domain_id as f64)),
            "template_id" => Some(FieldValue::Num(self.template_id as f64)),
            "protocol_version" => Some(FieldValue::Num(self.protocol_version as f64)),
            "exporter" => Some(FieldValue::Str(Cow::Owned(self.exporter.to_string()))),
            "export_time" => Some(FieldValue::Str(Cow::Owned(self.export_time.to_rfc3339()))),
            "src_addr" => opt_str(&self.src_addr),
            "dst_addr" => opt_str(&self.dst_addr),
            "src_port" => opt_num(&self.src_port),
            "dst_port" => opt_num(&self.dst_port),
            "ip_protocol" => opt_num(&self.ip_protocol),
            "octet_delta_count" => self.octet_delta_count.map(|v| FieldValue::Num(v as f64)),
            "packet_delta_count" => self.packet_delta_count.map(|v| FieldValue::Num(v as f64)),
            "flow_start" => opt_str(&self.flow_start.map(|t| t.to_rfc3339())),
            "flow_end" => opt_str(&self.flow_end.map(|t| t.to_rfc3339())),
            "tcp_flags" => opt_num(&self.tcp_flags),
            "input_interface" => opt_num(&self.input_interface),
            "output_interface" => opt_num(&self.output_interface),
            // Non-curated IEs land in `extra` keyed by IE name.
            other => json_field(&self.extra, other),
        }
    }
}

impl AggFields for crate::sflow::SflowRecord {
    fn stream(&self) -> &str {
        match self.sample_type {
            crate::sflow::SampleType::Flow => "flow",
            crate::sflow::SampleType::Counter => "counter",
        }
    }
    fn field(&self, name: &str) -> Option<FieldValue<'_>> {
        match name {
            "exporter" => Some(FieldValue::Str(Cow::Owned(self.exporter.to_string()))),
            "received_at" => Some(FieldValue::Str(Cow::Owned(self.received_at.to_rfc3339()))),
            "src_addr" => opt_str(&self.src_addr),
            "dst_addr" => opt_str(&self.dst_addr),
            "src_port" => opt_num(&self.src_port),
            "dst_port" => opt_num(&self.dst_port),
            "ip_protocol" => opt_num(&self.ip_protocol),
            "sampling_rate" => opt_num(&self.sampling_rate),
            "input_ifindex" => opt_num(&self.input_ifindex),
            "output_ifindex" => opt_num(&self.output_ifindex),
            "if_index" => opt_num(&self.if_index),
            "if_type" => opt_num(&self.if_type),
            "if_speed" => self.if_speed.map(|v| FieldValue::Num(v as f64)),
            "if_direction" => opt_num(&self.if_direction),
            "if_in_octets" => self.if_in_octets.map(|v| FieldValue::Num(v as f64)),
            "if_out_octets" => self.if_out_octets.map(|v| FieldValue::Num(v as f64)),
            "if_in_ucast_pkts" => self.if_in_ucast_pkts.map(|v| FieldValue::Num(v as f64)),
            "if_out_ucast_pkts" => self.if_out_ucast_pkts.map(|v| FieldValue::Num(v as f64)),
            "if_in_errors" => opt_num(&self.if_in_errors),
            "if_out_errors" => opt_num(&self.if_out_errors),
            other => json_field(&self.extra, other),
        }
    }
}

impl AggFields for crate::syslog::SyslogMessage {
    fn stream(&self) -> &str {
        self.app_name.as_deref().unwrap_or("")
    }
    fn field(&self, name: &str) -> Option<FieldValue<'_>> {
        match name {
            "priority" => Some(FieldValue::Num(self.priority as f64)),
            "severity" => Some(FieldValue::Num(self.severity as f64)),
            "facility" => Some(FieldValue::Num(self.facility as f64)),
            "timestamp" => opt_str(&self.timestamp.map(|t| t.to_rfc3339())),
            "hostname" => self
                .hostname
                .as_deref()
                .map(|s| FieldValue::Str(Cow::Borrowed(s))),
            "app_name" => self
                .app_name
                .as_deref()
                .map(|s| FieldValue::Str(Cow::Borrowed(s))),
            "proc_id" => self
                .proc_id
                .as_deref()
                .map(|s| FieldValue::Str(Cow::Borrowed(s))),
            "msg_id" => self
                .msg_id
                .as_deref()
                .map(|s| FieldValue::Str(Cow::Borrowed(s))),
            "message" => Some(FieldValue::Str(Cow::Borrowed(self.message.as_str()))),
            // RFC 5424 structured data: "sdid.param" addresses one parameter.
            other => {
                let sd = self.structured_data.as_ref()?;
                let (sdid, param) = other.split_once('.')?;
                sd.get(sdid)
                    .and_then(|params| params.get(param))
                    .map(|s| FieldValue::Str(Cow::Borrowed(s.as_str())))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;

    // -- group_value_string --

    #[test]
    fn integral_numbers_stringify_without_a_decimal_point() {
        assert_eq!(group_value_string(FieldValue::Num(443.0)), "443");
        assert_eq!(group_value_string(FieldValue::Num(-1.0)), "-1");
        assert_eq!(group_value_string(FieldValue::Num(0.0)), "0");
    }

    #[test]
    fn fractional_and_huge_numbers_keep_float_formatting() {
        assert_eq!(group_value_string(FieldValue::Num(1.5)), "1.5");
        // Beyond 2^53 the i64 shortcut is not safe; fall back to float form.
        let big = 9.007199254740994e15_f64;
        assert!(
            group_value_string(FieldValue::Num(big)).contains('e')
                || group_value_string(FieldValue::Num(big)).contains('.')
        );
    }

    #[test]
    fn booleans_stringify_as_true_false() {
        assert_eq!(group_value_string(FieldValue::Bool(true)), "true");
        assert_eq!(group_value_string(FieldValue::Bool(false)), "false");
    }

    #[test]
    fn strings_longer_than_the_cap_are_truncated() {
        let long = "a".repeat(MAX_GROUP_VALUE_BYTES + 50);
        let out = group_value_string(FieldValue::Str(Cow::Owned(long)));
        assert_eq!(out.len(), MAX_GROUP_VALUE_BYTES);
    }

    // -- truncate_to_bytes --

    #[test]
    fn truncation_never_splits_a_multibyte_char() {
        // 'é' is 2 bytes; a cap landing mid-char must walk back.
        let s = "é".repeat(200); // 400 bytes
        let out = truncate_to_bytes(&s, 255);
        assert!(out.len() <= 255);
        assert_eq!(out.len() % 2, 0, "must not split a 2-byte char");
        assert!(s.starts_with(out));
    }

    #[test]
    fn truncation_leaves_short_strings_alone() {
        assert_eq!(truncate_to_bytes("short", 256), "short");
    }

    // -- numeric_value --

    #[test]
    fn numeric_value_accepts_numbers_and_numeric_strings() {
        assert_eq!(numeric_value(&FieldValue::Num(7.0)), Some(7.0));
        assert_eq!(
            numeric_value(&FieldValue::Str(Cow::Borrowed("42"))),
            Some(42.0)
        );
        assert_eq!(
            numeric_value(&FieldValue::Str(Cow::Borrowed("1.5"))),
            Some(1.5)
        );
    }

    #[test]
    fn numeric_value_rejects_non_numeric_bool_and_non_finite() {
        assert_eq!(numeric_value(&FieldValue::Str(Cow::Borrowed("abc"))), None);
        assert_eq!(numeric_value(&FieldValue::Bool(true)), None);
        assert_eq!(numeric_value(&FieldValue::Num(f64::NAN)), None);
        assert_eq!(numeric_value(&FieldValue::Num(f64::INFINITY)), None);
    }

    // -- json_field --

    #[test]
    fn json_lookup_prefers_a_literal_dotted_key() {
        // Zeek NDJSON carries "id.orig_h" as ONE flat key.
        let v = serde_json::json!({"id.orig_h": "10.0.0.1", "id": {"orig_h": "WRONG"}});
        match json_field(&v, "id.orig_h") {
            Some(FieldValue::Str(s)) => assert_eq!(s, "10.0.0.1"),
            other => panic!("expected the flat key, got {other:?}"),
        }
    }

    #[test]
    fn json_lookup_falls_back_to_a_dotted_path() {
        // Suricata EVE nests: {"dns": {"rrname": "example.com"}}
        let v = serde_json::json!({"dns": {"rrname": "example.com"}});
        match json_field(&v, "dns.rrname") {
            Some(FieldValue::Str(s)) => assert_eq!(s, "example.com"),
            other => panic!("expected nested lookup, got {other:?}"),
        }
    }

    #[test]
    fn json_lookup_maps_scalar_types_and_misses() {
        let v = serde_json::json!({"n": 5, "f": 1.5, "b": true, "nil": null});
        assert!(matches!(json_field(&v, "n"), Some(FieldValue::Num(n)) if n == 5.0));
        assert!(matches!(json_field(&v, "f"), Some(FieldValue::Num(n)) if n == 1.5));
        assert!(matches!(json_field(&v, "b"), Some(FieldValue::Bool(true))));
        assert!(json_field(&v, "nil").is_none(), "null is a miss");
        assert!(json_field(&v, "absent").is_none());
        // Objects and arrays are not group-able scalars.
        let nested = serde_json::json!({"o": {"a": 1}, "arr": [1, 2]});
        assert!(json_field(&nested, "o").is_none());
        assert!(json_field(&nested, "arr").is_none());
    }

    // -- AggFields impls --

    #[test]
    fn zeek_record_exposes_stream_and_fields() {
        let rec = crate::zeek::ZeekRecord {
            log_path: "dns".to_string(),
            fields: serde_json::json!({"_path": "dns", "query": "example.com", "AA": false}),
            received_at: chrono::Utc::now(),
        };
        assert_eq!(rec.stream(), "dns");
        assert!(matches!(rec.field("query"), Some(FieldValue::Str(s)) if s == "example.com"));
        assert!(matches!(rec.field("AA"), Some(FieldValue::Bool(false))));
        assert!(rec.field("nope").is_none());
    }

    #[test]
    fn suricata_record_exposes_event_type_as_stream() {
        let rec = crate::suricata::SuricataRecord {
            event_type: "dns".to_string(),
            fields: serde_json::json!({"event_type": "dns", "dns": {"rrname": "a.example"}}),
            received_at: chrono::Utc::now(),
        };
        assert_eq!(rec.stream(), "dns");
        assert!(matches!(rec.field("dns.rrname"), Some(FieldValue::Str(s)) if s == "a.example"));
    }

    #[test]
    fn flow_record_exposes_curated_fields_and_extra_fallback() {
        use std::net::{IpAddr, Ipv4Addr};
        let rec = crate::ipfix::FlowRecord {
            observation_domain_id: 1,
            template_id: 256,
            protocol_version: 10,
            exporter: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            export_time: chrono::Utc::now(),
            src_addr: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5))),
            dst_addr: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            src_port: Some(51000),
            dst_port: Some(443),
            ip_protocol: Some(6),
            octet_delta_count: Some(4096),
            packet_delta_count: Some(8),
            flow_start: None,
            flow_end: None,
            tcp_flags: None,
            input_interface: None,
            output_interface: None,
            extra: serde_json::json!({"vendorField": 12}),
        };
        assert_eq!(rec.stream(), "flows");
        assert!(matches!(rec.field("src_addr"), Some(FieldValue::Str(s)) if s == "192.168.1.5"));
        assert!(matches!(rec.field("dst_port"), Some(FieldValue::Num(n)) if n == 443.0));
        assert!(matches!(rec.field("octet_delta_count"), Some(FieldValue::Num(n)) if n == 4096.0));
        // Absent Option field is a miss, not a zero.
        assert!(rec.field("tcp_flags").is_none());
        // Unknown name falls through to `extra`.
        assert!(matches!(rec.field("vendorField"), Some(FieldValue::Num(n)) if n == 12.0));
        assert!(rec.field("no_such_field").is_none());
    }

    #[test]
    fn sflow_record_stream_distinguishes_flow_from_counter() {
        use std::net::{IpAddr, Ipv4Addr};
        let mut rec = crate::sflow::SflowRecord {
            sample_type: crate::sflow::SampleType::Flow,
            exporter: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            received_at: chrono::Utc::now(),
            src_addr: Some(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1))),
            dst_addr: None,
            src_port: None,
            dst_port: Some(80),
            ip_protocol: Some(6),
            sampling_rate: Some(512),
            input_ifindex: None,
            output_ifindex: None,
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
        };
        assert_eq!(rec.stream(), "flow");
        assert!(matches!(rec.field("src_addr"), Some(FieldValue::Str(s)) if s == "10.1.1.1"));
        assert!(matches!(rec.field("sampling_rate"), Some(FieldValue::Num(n)) if n == 512.0));

        rec.sample_type = crate::sflow::SampleType::Counter;
        assert_eq!(rec.stream(), "counter");
    }

    #[test]
    fn syslog_message_exposes_app_name_as_stream_and_curated_fields() {
        let msg = crate::syslog::SyslogMessage {
            priority: 34,
            severity: 2,
            facility: 4,
            timestamp: None,
            hostname: Some("host-a".to_string()),
            app_name: Some("sshd".to_string()),
            proc_id: None,
            msg_id: None,
            message: "Failed password".to_string(),
            structured_data: None,
            protocol: crate::syslog::SyslogProtocol::Rfc5424,
        };
        assert_eq!(msg.stream(), "sshd");
        assert!(matches!(msg.field("hostname"), Some(FieldValue::Str(s)) if s == "host-a"));
        assert!(matches!(msg.field("severity"), Some(FieldValue::Num(n)) if n == 2.0));
        assert!(matches!(msg.field("message"), Some(FieldValue::Str(s)) if s == "Failed password"));
        assert!(msg.field("proc_id").is_none());
    }

    #[test]
    fn syslog_message_without_app_name_has_an_empty_stream() {
        let msg = crate::syslog::SyslogMessage {
            priority: 13,
            severity: 5,
            facility: 1,
            timestamp: None,
            hostname: None,
            app_name: None,
            proc_id: None,
            msg_id: None,
            message: "x".to_string(),
            structured_data: None,
            protocol: crate::syslog::SyslogProtocol::Rfc3164,
        };
        assert_eq!(msg.stream(), "");
    }
}
