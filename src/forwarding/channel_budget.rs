//! Per-source bounded-channel sizing from a fixed memory budget.
//!
//! `channel_capacity` is expressed in **records**, but the operational
//! constraint is **bytes**: a Zeek record and an IPFIX datagram's worth of
//! flows differ by an order of magnitude, so one shared record count would
//! mean 100 MiB for one source and gigabytes for another. Each source's
//! default is therefore `CHANNEL_BUDGET_BYTES / <measured bytes per record>`.
//!
//! The per-record figures below are **measured**, not guessed — see the tests
//! at the bottom of this file, which rebuild a representative record for each
//! type and fail if the constant has drifted by more than 2x. A memory ceiling
//! computed from an unverified divisor is fiction, and adding a field to a
//! record type would otherwise silently inflate the real ceiling.
//!
//! See `docs/superpowers/specs/2026-08-07-ingest-backpressure-design.md` §4.

/// Memory budget for one source's bounded channel, in bytes.
///
/// This is a **ceiling, not a reservation**: tokio's bounded mpsc allocates
/// its buffer lazily in blocks, so an idle or healthy channel costs nearly
/// nothing. Only Zeek and Suricata apply backpressure, so only those two are
/// designed to dwell near capacity under sustained load.
pub const CHANNEL_BUDGET_BYTES: usize = 100 * 1024 * 1024;

/// Records that fit in the budget, given a per-record byte figure.
///
/// Always returns at least 1: `tokio::sync::mpsc::channel(0)` panics, and a
/// record larger than the entire budget must still be deliverable.
pub const fn capacity_for(bytes_per_record: usize) -> usize {
    if bytes_per_record == 0 {
        return 1;
    }
    let n = CHANNEL_BUDGET_BYTES / bytes_per_record;
    if n == 0 { 1 } else { n }
}

/// Heap bytes owned by a `serde_json::Value`, following nesting.
///
/// Approximate by design (per-entry map overhead is not modelled exactly) —
/// the 2x drift tolerance in the tests is the accuracy contract. This crate
/// does not enable serde_json's `preserve_order` feature, so `Value::Object`
/// is backed by a `BTreeMap`; we do not attempt to model its per-node
/// allocation overhead, only the key/value bytes it owns.
pub fn json_heap_bytes(v: &serde_json::Value) -> usize {
    use serde_json::Value;
    match v {
        Value::Null | Value::Bool(_) | Value::Number(_) => 0,
        Value::String(s) => s.capacity(),
        Value::Array(a) => {
            a.capacity() * std::mem::size_of::<Value>()
                + a.iter().map(json_heap_bytes).sum::<usize>()
        }
        Value::Object(m) => m
            .iter()
            .map(|(k, val)| k.capacity() + std::mem::size_of::<Value>() + json_heap_bytes(val))
            .sum(),
    }
}

/// Measured heap footprint of one `ZeekRecord` carrying a representative
/// `conn` log line: 990 bytes measured, rounded up to 1024. See
/// `measured_zeek_record_bytes_matches_constant`.
pub const ZEEK_RECORD_BYTES: usize = 1024;

/// Measured heap footprint of one `SuricataRecord` carrying a representative
/// `alert` event: 1590 bytes measured, rounded up to 2048. Same shape as
/// `ZeekRecord` (String + Value + DateTime), but larger — EVE `alert` events
/// carry nested `alert`/`http`/`flow` sub-objects that a Zeek `conn` line does
/// not.
pub const SURICATA_RECORD_BYTES: usize = 2048;

/// Measured heap footprint of one `GenericRecord` (HEC/NDJSON, OTLP): 353
/// bytes measured for a representative HEC event, rounded up to 512.
pub const GENERIC_RECORD_BYTES: usize = 512;

/// Measured heap footprint of one `SyslogMessage`: 697 bytes measured for a
/// representative RFC 5424 message with structured data, rounded up to 1024.
pub const SYSLOG_MESSAGE_BYTES: usize = 1024;

/// Measured heap footprint of one `SflowRecord` — a flat, fixed-size struct
/// with no owned heap besides `extra` (empty for curated samples), so this is
/// `size_of` plus slack: 256 bytes measured, already clean.
pub const SFLOW_RECORD_BYTES: usize = 256;

/// Measured footprint of one IPFIX channel message, which is a `Vec<FlowRecord>`
/// holding **all flows from one UDP datagram**: 4184 bytes measured for the
/// 10-flow representative datagram used by this repo's IPFIX fixtures — each
/// flow carrying a handful of non-curated IEs in `extra` (ToS, TTLs,
/// flow-end reason, biflow direction), as a real export template does —
/// rounded up to 8192.
///
/// **Average-case, not a ceiling.** Flows-per-datagram is variable; this uses a
/// representative count from the repo's IPFIX test fixtures. Datagrams denser
/// than that average will push this source past `CHANNEL_BUDGET_BYTES`. Known
/// and accepted limitation — see the spec §4.3.
pub const IPFIX_DATAGRAM_BYTES: usize = 8192;

/// Measured footprint of one `Arc<WindowsEvent>` — the **pointee**, not the
/// 8-byte pointer in the channel slot. Each queued `Arc` is a distinct event;
/// the `Arc` is a transfer mechanism, not sharing. WEF fan-out to `.s3` and
/// `.local` clones the same `Arc` into both channels, so counting it once per
/// channel overcounts, which is the safe direction. Dominated by `raw_xml`
/// plus a populated `ParsedEvent.message` (real events are parsed on receipt,
/// not left `None` — see `measured_wef_event_bytes_counts_the_pointee_not_the_pointer`):
/// 12146 bytes measured for a ~5.6KB raw event with a representative parsed
/// Security-log message, rounded up to 16384.
pub const WEF_EVENT_BYTES: usize = 16384;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_for_divides_the_budget() {
        assert_eq!(capacity_for(1024), 100 * 1024);
        assert_eq!(capacity_for(CHANNEL_BUDGET_BYTES), 1);
    }

    #[test]
    fn capacity_for_never_returns_zero() {
        // A record larger than the whole budget must still allow one in flight,
        // otherwise `mpsc::channel(0)` panics.
        assert_eq!(capacity_for(CHANNEL_BUDGET_BYTES * 2), 1);
        assert_eq!(capacity_for(0), 1);
    }

    #[test]
    fn json_heap_bytes_counts_nested_strings() {
        let v = serde_json::json!({"a": "0123456789", "b": {"c": "abc"}});
        // Two string values (10 + 3) plus key capacities (1 + 1 + 1); the exact
        // total depends on allocator slack, so assert a sane lower bound only.
        assert!(json_heap_bytes(&v) >= 16, "got {}", json_heap_bytes(&v));
    }

    #[test]
    fn json_heap_bytes_is_zero_for_scalars() {
        assert_eq!(json_heap_bytes(&serde_json::json!(42)), 0);
        assert_eq!(json_heap_bytes(&serde_json::json!(null)), 0);
        assert_eq!(json_heap_bytes(&serde_json::json!(true)), 0);
    }

    /// Assert `measured` is within 2x of the documented `constant`, in either
    /// direction. Tolerance rather than equality because allocator slack and
    /// fixture choice both move the number, but a 2x drift means the 100 MiB
    /// budget is no longer 100 MiB and the constant must be revisited.
    fn assert_within_2x(measured: usize, constant: usize, name: &str) {
        assert!(
            measured * 2 >= constant && constant * 2 >= measured,
            "{name}: measured {measured} bytes but constant says {constant}; \
             update the constant (round up) and re-derive the capacity"
        );
    }

    #[test]
    fn measured_zeek_record_bytes_matches_constant() {
        use crate::zeek::ZeekRecord;
        let fields = serde_json::json!({
            "_path": "conn", "ts": 1717171717.123456, "uid": "CHhAvVGS1DHFjwGM9",
            "id.orig_h": "192.168.7.102", "id.orig_p": 33764,
            "id.resp_h": "93.184.216.34", "id.resp_p": 443,
            "proto": "tcp", "service": "ssl", "duration": 0.253,
            "orig_bytes": 1420, "resp_bytes": 5320, "conn_state": "SF",
            "local_orig": true, "local_resp": false, "missed_bytes": 0,
            "history": "ShADadFf", "orig_pkts": 12, "orig_ip_bytes": 1948,
            "resp_pkts": 14, "resp_ip_bytes": 5892
        });
        let record = ZeekRecord {
            log_path: "conn".to_string(),
            fields,
            received_at: chrono::Utc::now(),
        };
        let measured = std::mem::size_of::<ZeekRecord>()
            + record.log_path.capacity()
            + json_heap_bytes(&record.fields);
        assert_within_2x(measured, ZEEK_RECORD_BYTES, "ZeekRecord");
    }

    #[test]
    fn measured_suricata_record_bytes_matches_constant() {
        use crate::suricata::SuricataRecord;
        // Representative EVE `alert` event — larger than a Zeek `conn` line
        // because of the nested `alert`/`http`/`flow` sub-objects.
        let fields = serde_json::json!({
            "timestamp": "2026-08-07T12:34:56.789012+0000",
            "flow_id": 1921394888273746i64,
            "in_iface": "eth0",
            "event_type": "alert",
            "src_ip": "192.168.7.102",
            "src_port": 45231,
            "dest_ip": "93.184.216.34",
            "dest_port": 443,
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2024897,
                "rev": 2,
                "signature": "ET MALWARE Suspicious User-Agent (curl)",
                "category": "A Network Trojan was detected",
                "severity": 1
            },
            "http": {
                "hostname": "example.com",
                "url": "/download/payload.bin",
                "http_user_agent": "curl/7.68.0",
                "http_method": "GET",
                "protocol": "HTTP/1.1",
                "status": 200,
                "length": 1024
            },
            "app_proto": "http",
            "flow": {
                "pkts_toserver": 6,
                "pkts_toclient": 8,
                "bytes_toserver": 512,
                "bytes_toclient": 4096,
                "start": "2026-08-07T12:34:55.123456+0000"
            }
        });
        let record = SuricataRecord {
            event_type: "alert".to_string(),
            fields,
            received_at: chrono::Utc::now(),
        };
        let measured = std::mem::size_of::<SuricataRecord>()
            + record.event_type.capacity()
            + json_heap_bytes(&record.fields);
        assert_within_2x(measured, SURICATA_RECORD_BYTES, "SuricataRecord");
    }

    #[test]
    fn measured_generic_record_bytes_matches_constant() {
        use crate::ingest::GenericRecord;
        let fields = serde_json::json!({
            "event": "user login failed",
            "user": "jdoe",
            "src_ip": "10.0.0.5",
            "status": "failure",
            "attempt": 3
        });
        let record = GenericRecord {
            sourcetype: "auth_log".to_string(),
            host: Some("web01.example.com".to_string()),
            time: Some(chrono::Utc::now()),
            fields,
            received_at: chrono::Utc::now(),
        };
        let measured = std::mem::size_of::<GenericRecord>()
            + record.sourcetype.capacity()
            + record.host.as_ref().map_or(0, |s| s.capacity())
            + json_heap_bytes(&record.fields);
        assert_within_2x(measured, GENERIC_RECORD_BYTES, "GenericRecord");
    }

    #[test]
    fn measured_syslog_message_bytes_matches_constant() {
        use crate::syslog::{SyslogMessage, SyslogProtocol};
        use std::collections::HashMap;

        let mut sd_inner = HashMap::new();
        sd_inner.insert("iut".to_string(), "3".to_string());
        sd_inner.insert("eventSource".to_string(), "Application".to_string());
        sd_inner.insert("eventID".to_string(), "1011".to_string());
        let mut sd = HashMap::new();
        sd.insert("exampleSDID@32473".to_string(), sd_inner);

        let msg = SyslogMessage {
            priority: 165,
            severity: 5,
            facility: 20,
            timestamp: Some(chrono::Utc::now()),
            hostname: Some("router1.example.com".to_string()),
            app_name: Some("sshd".to_string()),
            proc_id: Some("1234".to_string()),
            msg_id: Some("ID47".to_string()),
            message: "Failed password for invalid user admin from 10.0.0.5 port 51234 ssh2"
                .to_string(),
            structured_data: Some(sd),
            protocol: SyslogProtocol::Rfc5424,
        };

        // No `json_heap_bytes` equivalent exists for nested `HashMap`s, so this
        // walks the same shape by hand: map capacity times the entry size, plus
        // each owned String's capacity.
        let sd_heap = msg.structured_data.as_ref().map_or(0, |outer| {
            outer.capacity() * std::mem::size_of::<(String, HashMap<String, String>)>()
                + outer
                    .iter()
                    .map(|(k, inner)| {
                        k.capacity()
                            + inner.capacity() * std::mem::size_of::<(String, String)>()
                            + inner
                                .iter()
                                .map(|(ik, iv)| ik.capacity() + iv.capacity())
                                .sum::<usize>()
                    })
                    .sum::<usize>()
        });

        let measured = std::mem::size_of::<SyslogMessage>()
            + msg.hostname.as_ref().map_or(0, |s| s.capacity())
            + msg.app_name.as_ref().map_or(0, |s| s.capacity())
            + msg.proc_id.as_ref().map_or(0, |s| s.capacity())
            + msg.msg_id.as_ref().map_or(0, |s| s.capacity())
            + msg.message.capacity()
            + sd_heap;
        assert_within_2x(measured, SYSLOG_MESSAGE_BYTES, "SyslogMessage");
    }

    #[test]
    fn measured_sflow_record_bytes_matches_constant() {
        use crate::sflow::{SampleType, SflowRecord};
        let record = SflowRecord {
            sample_type: SampleType::Flow,
            exporter: "10.0.0.1".parse().unwrap(),
            received_at: chrono::Utc::now(),
            src_addr: Some("192.168.1.10".parse().unwrap()),
            dst_addr: Some("93.184.216.34".parse().unwrap()),
            src_port: Some(51234),
            dst_port: Some(443),
            ip_protocol: Some(6),
            sampling_rate: Some(1000),
            input_ifindex: Some(1),
            output_ifindex: Some(2),
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
            extra: serde_json::json!([]),
        };
        // sFlow is a flat struct with no owned heap besides `extra`, which is
        // typically empty for curated flow/counter samples.
        let measured = std::mem::size_of::<SflowRecord>() + json_heap_bytes(&record.extra);
        assert_within_2x(measured, SFLOW_RECORD_BYTES, "SflowRecord");
    }

    #[test]
    fn measured_ipfix_datagram_bytes_matches_constant() {
        use crate::ipfix::FlowRecord;
        // 10 flows/datagram matches the fixture built in
        // `forwarding::ipfix_s3::tests::integration_flows_produce_parquet_in_s3`
        // (`(0..10).map(|i| make_flow_record(...))`), the closest thing this
        // repo has to a representative datagram size.
        let flows: Vec<FlowRecord> = (0..10)
            .map(|i| FlowRecord {
                observation_domain_id: 1,
                template_id: 256,
                protocol_version: 10,
                exporter: "10.0.0.1".parse().unwrap(),
                export_time: chrono::Utc::now(),
                src_addr: Some("192.168.1.10".parse().unwrap()),
                dst_addr: Some("93.184.216.34".parse().unwrap()),
                src_port: Some(51234),
                dst_port: Some(443),
                ip_protocol: Some(6),
                octet_delta_count: Some(1000 + i),
                packet_delta_count: Some(10),
                flow_start: Some(chrono::Utc::now()),
                flow_end: Some(chrono::Utc::now()),
                tcp_flags: Some(0x18),
                input_interface: Some(1),
                output_interface: Some(2),
                // Real templates carry IEs beyond the curated set above —
                // `apply_field_to_record` (`src/ipfix/decoder.rs:671-770`)
                // routes anything not explicitly matched (ToS, TTLs, flow-end
                // reason, biflow direction, vendor/enterprise IEs, ...) into
                // `extra`. An empty `extra` on every flow understates a
                // typical router's export template.
                extra: serde_json::json!({
                    "ipClassOfService": 0,
                    "minimumTTL": 64,
                    "maximumTTL": 64,
                    "flowEndReason": 3,
                    "biflowDirection": 1
                }),
            })
            .collect();
        let measured = std::mem::size_of::<Vec<FlowRecord>>()
            + flows.capacity() * std::mem::size_of::<FlowRecord>()
            + flows
                .iter()
                .map(|f| json_heap_bytes(&f.extra))
                .sum::<usize>();
        assert_within_2x(measured, IPFIX_DATAGRAM_BYTES, "IPFIX Vec<FlowRecord>");
    }

    #[test]
    fn measured_wef_event_bytes_counts_the_pointee_not_the_pointer() {
        use crate::models::{EventLevel, ParsedEvent, WindowsEvent};
        // `parsed` must be `Some(..)`, not `None`: on the real ingest path
        // `parse_single_event` (`src/protocol/mod.rs:187-196`) always attaches a
        // `ParsedEvent` — `parse_event_data` has no `Err` path that fires in
        // practice, malformed XML just truncates the read loop and still
        // returns `Ok`. A `parsed: None` fixture measures a record shape that
        // essentially never reaches the channel.
        let parsed = ParsedEvent {
            provider: "Microsoft-Windows-Security-Auditing".to_string(),
            event_id: 4624,
            level: EventLevel::Information,
            task: 12544,
            opcode: 0,
            keywords: 0x8020000000000000,
            time_created: chrono::Utc::now(),
            event_record_id: 918273645,
            process_id: Some(656),
            thread_id: Some(29384),
            // Always empty on the real path: `parse_event_data` never writes
            // to `channel` (src/protocol/mod.rs:307-323).
            channel: String::new(),
            computer: "dc01.corp.example".to_string(),
            security_user_id: None,
            // `message` is populated from the XML `Message`/`Data` tag
            // whenever present — representative Security-log logon text, not
            // a placeholder.
            message: Some(
                "An account was successfully logged on.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-18\n\t\
                 Account Name:\t\tDC01$\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x3E7\n\n\
                 Logon Information:\n\tLogon Type:\t\t3\n\tRestricted Admin Mode:\t-\n\t\
                 Virtual Account:\t\tNo\n\tElevated Token:\t\tYes\n\nImpersonation Level:\t\tImpersonation\n\n\
                 New Logon:\n\tSecurity ID:\t\tS-1-5-21-1234567890-1234567890-1234567890-1001\n\t\
                 Account Name:\t\tjdoe\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x1A2B3C4\n\t\
                 Linked Logon ID:\t\t0x0\n\tNetwork Account Name:\t-\n\tNetwork Account Domain:\t-\n\t\
                 Logon GUID:\t\t{00000000-0000-0000-0000-000000000000}"
                    .to_string(),
            ),
            // Always None on the real path: `parse_event_data` never sets it.
            data: None,
        };
        let event = WindowsEvent {
            id: uuid::Uuid::new_v4(),
            received_at: chrono::Utc::now(),
            source_host: "dc01.corp.example".to_string(),
            subscription_id: Some("sub-1".to_string()),
            raw_xml: "<Event>".to_string() + &"<Data>x</Data>".repeat(400) + "</Event>",
            parsed: Some(parsed),
        };
        let measured = std::mem::size_of::<WindowsEvent>()
            + event.source_host.capacity()
            + event.subscription_id.as_ref().map_or(0, |s| s.capacity())
            + event.raw_xml.capacity()
            + event.parsed.as_ref().map_or(0, |p| {
                p.provider.capacity()
                    + p.channel.capacity()
                    + p.computer.capacity()
                    + p.message.as_ref().map_or(0, |m| m.capacity())
                    + p.data.as_ref().map_or(0, json_heap_bytes)
            });
        // Guard the methodology itself: an Arc slot is 8 bytes, so measuring the
        // pointer instead of the pointee would yield a capacity in the millions.
        assert!(
            measured > std::mem::size_of::<std::sync::Arc<WindowsEvent>>() * 100,
            "must measure the pointee, not the Arc pointer"
        );
        assert_within_2x(measured, WEF_EVENT_BYTES, "WindowsEvent");
    }

    #[test]
    fn every_derived_capacity_is_nonzero_and_within_budget() {
        for (name, bytes) in [
            ("zeek", ZEEK_RECORD_BYTES),
            ("suricata", SURICATA_RECORD_BYTES),
            ("generic", GENERIC_RECORD_BYTES),
            ("syslog", SYSLOG_MESSAGE_BYTES),
            ("sflow", SFLOW_RECORD_BYTES),
            ("ipfix", IPFIX_DATAGRAM_BYTES),
            ("wef", WEF_EVENT_BYTES),
        ] {
            let cap = capacity_for(bytes);
            assert!(cap >= 1, "{name} capacity must be >= 1");
            assert!(
                cap * bytes <= CHANNEL_BUDGET_BYTES,
                "{name}: {cap} records x {bytes} bytes exceeds the budget"
            );
        }
    }
}
