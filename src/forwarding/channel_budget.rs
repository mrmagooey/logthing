//! Bounded-channel sizing from a fixed per-channel memory budget.
//!
//! `channel_capacity` is expressed in **records**, but the operational
//! constraint is **bytes**: a Zeek record and an IPFIX datagram's worth of
//! flows differ by an order of magnitude, so one shared record count would
//! mean 100 MiB for one source and gigabytes for another. Each source's
//! default is therefore `CHANNEL_BUDGET_BYTES / <measured bytes per record>`.
//!
//! The per-record figures below are **measured**, not guessed — see the tests
//! at the bottom of this file, which rebuild a representative record for each
//! type and fail if the constant has drifted by more than 2x, and
//! `tests/channel_budget_allocator.rs`, which checks the *estimator* those
//! tests use against a counting global allocator. A memory ceiling computed
//! from an unverified divisor is fiction, and adding a field to a record type
//! would otherwise silently inflate the real ceiling.
//!
//! Each constant is the measured figure **rounded up to the next 256 bytes**.
//! Rounding up is the conservative direction (a bigger divisor means a smaller
//! capacity means less memory), and 256 B is fine enough not to throw away
//! most of a channel the way rounding to the next power of two does.
//!
//! # The budget is per *channel*, not per source
//!
//! `CHANNEL_BUDGET_BYTES` bounds **one** bounded mpsc channel. A source
//! configured with both `.s3` and `.local` gets two independent
//! `ParquetWriterHandle`s — two channels — and the `Multi*Handler` fan-out
//! `record.clone()`s into each, so those really are two distinct copies of
//! every record, not two references to one. Syslog can reach three (`.s3`,
//! `.local`, and `structured_s3` when `parse_payloads` is on).
//!
//! A deployment with every source enabled and every destination configured
//! therefore has 15 channels — zeek 2, suricata 2, syslog 3, sflow 2, ipfix 2,
//! HEC/OTLP 2 (OTLP shares HEC's handles), WEF 2 — for a **~1.46 GiB**
//! worst-case ceiling, not 100 MiB and not 700 MiB. One exception: WEF queues
//! `Arc<WindowsEvent>` and clones the same `Arc` into both of its channels, so
//! its two channels share one set of pointees and the true WEF worst case is
//! ~100 MiB rather than 200 MiB, putting the realistic ceiling at ~1.37 GiB.
//!
//! That is a ceiling, not a reservation (see `CHANNEL_BUDGET_BYTES`): only
//! Zeek and Suricata apply backpressure and so are the only channels *designed*
//! to dwell near capacity, ~200 MiB per configured destination pair.
//!
//! See `docs/superpowers/specs/2026-08-07-ingest-backpressure-design.md` §4.

/// Memory budget for **one** bounded channel, in bytes.
///
/// Per channel, not per source: see this module's header for what a
/// fully-configured deployment adds up to.
///
/// This is a **ceiling, not a reservation**: tokio's bounded mpsc is a linked
/// list of 32-slot blocks, not a ring buffer sized to capacity, so a channel
/// starts life holding exactly one block — 32 B of header plus
/// `32 * size_of::<T>()` — and allocates another only per 32 records actually
/// queued. All 15 channels of a fully-configured deployment come to ~50 KB at
/// startup. Only Zeek and Suricata apply backpressure, so only those two are
/// designed to dwell near capacity under sustained load.
///
/// **Lazy on the way up, sticky on the way down.** Drained blocks are recycled
/// onto the sender's tail for reuse (`Rx::reclaim_blocks`), not freed; the
/// whole list is released only when the channel itself drops, at shutdown. A
/// channel's block footprint is therefore a high-water mark held for the
/// process lifetime: one burst that fills the syslog channel pins ~25 MB of
/// slots (136 533 records * 184 B) until exit, however idle it goes afterwards.
/// RSS does not come back down after a spike.
///
/// That stickiness applies to the *slots* only. The per-record heap this
/// budget actually counts — `String`s, `serde_json::Value` BTreeMap nodes — is
/// owned by the records and freed as they drain, and it dominates the slot
/// array for every type except `SflowRecord`, which is flat and owns no heap.
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

/// Bytes of `BTreeMap<String, Value>` **node** allocations for `entries` entries.
///
/// This crate does not enable serde_json's `preserve_order` feature, so
/// `Value::Object` is a `BTreeMap`, and a B-tree's dominant allocation is its
/// nodes, not its entries. std uses `B = 6`, so one node holds up to 11
/// entries in `[MaybeUninit<String>; 11]` / `[MaybeUninit<Value>; 11]` arrays
/// that are allocated in full whether or not they are occupied — a 5-key
/// object therefore costs the same 632 bytes as an 11-key one. The `String`
/// and `Value` structs themselves live *inside* those arrays, which is why
/// the per-entry term below counts only `k.capacity()` and the value's own
/// heap, never `size_of::<String>()` or `size_of::<Value>()`.
///
/// Node counts assume packed nodes (`entries / 11`), which is the floor: a map
/// built by repeated insertion can leave nodes about half full after a split,
/// so this can understate by up to ~2x for maps large enough to have split.
/// Accepted — the accuracy contract is 2x, and every fixture measured in
/// `tests/channel_budget_allocator.rs` lands on the exact byte.
fn btreemap_node_bytes(entries: usize) -> usize {
    // An empty `BTreeMap` allocates no root node at all.
    if entries == 0 {
        return 0;
    }
    const NODE_ENTRIES: usize = 11; // 2 * B - 1, B = 6
    // `LeafNode`: parent pointer + parent_idx + len, padded to pointer
    // alignment, then the two fully-allocated arrays.
    let leaf = std::mem::size_of::<usize>()
        + std::mem::size_of::<usize>()
        + NODE_ENTRIES * (std::mem::size_of::<String>() + std::mem::size_of::<serde_json::Value>());
    // `InternalNode` is a `LeafNode` plus one child pointer per subtree.
    let internal = leaf + (NODE_ENTRIES + 1) * std::mem::size_of::<usize>();

    let mut nodes = entries.div_ceil(NODE_ENTRIES);
    let mut total = nodes * leaf;
    while nodes > 1 {
        nodes = nodes.div_ceil(NODE_ENTRIES + 1);
        total += nodes * internal;
    }
    total
}

/// Heap bytes owned by a `serde_json::Value`, following nesting.
///
/// Three allocation sources are modelled: a `String`'s buffer, an array's
/// `Vec` buffer, and an object's `BTreeMap` nodes (see `btreemap_node_bytes`,
/// which is where most of an object's bytes actually live — omitting it
/// undercounted real allocation by 2.4-3.1x).
///
/// Verified against a counting global allocator in
/// `tests/channel_budget_allocator.rs`, which fails if this estimate drifts
/// from real allocation. The 2x drift tolerance in this file's tests is the
/// accuracy contract for the *constants*; that test is the contract for the
/// estimator itself.
pub fn json_heap_bytes(v: &serde_json::Value) -> usize {
    use serde_json::Value;
    match v {
        Value::Null | Value::Bool(_) | Value::Number(_) => 0,
        Value::String(s) => s.capacity(),
        Value::Array(a) => {
            a.capacity() * std::mem::size_of::<Value>()
                + a.iter().map(json_heap_bytes).sum::<usize>()
        }
        Value::Object(m) => {
            btreemap_node_bytes(m.len())
                + m.iter()
                    .map(|(k, val)| k.capacity() + json_heap_bytes(val))
                    .sum::<usize>()
        }
    }
}

/// Measured heap footprint of one `ZeekRecord` carrying a representative
/// `conn` log line: 2310 bytes measured, rounded up to 2560. See
/// `measured_zeek_record_bytes_matches_constant`. Most of it is the 21-key
/// `fields` object's BTreeMap nodes (1992 of 2234 JSON bytes), not the field
/// text.
pub const ZEEK_RECORD_BYTES: usize = 2560;

/// Measured heap footprint of one `SuricataRecord` carrying a representative
/// `alert` event: 4454 bytes measured, rounded up to 4608. Same shape as
/// `ZeekRecord` (String + Value + DateTime), but larger — EVE `alert` events
/// carry nested `alert`/`http`/`flow` sub-objects that a Zeek `conn` line does
/// not, and each nested object costs a BTreeMap node of its own.
pub const SURICATA_RECORD_BYTES: usize = 4608;

/// Measured heap footprint of one `GenericRecord` (HEC/NDJSON, OTLP): 825
/// bytes measured for a representative HEC event, rounded up to 1024.
pub const GENERIC_RECORD_BYTES: usize = 1024;

/// Measured heap footprint of one `SyslogMessage`: 697 bytes measured for a
/// representative RFC 5424 message with structured data, rounded up to 768.
/// Unaffected by the BTreeMap correction — `SyslogMessage` carries `HashMap`s,
/// not `serde_json::Value`.
pub const SYSLOG_MESSAGE_BYTES: usize = 768;

/// Measured worst-case heap footprint of one `SflowRecord`, **a ceiling for
/// the capped shape, not an average**. The struct itself is flat and owns no
/// heap besides `extra` (`size_of::<SflowRecord>()` = 256 bytes, already a
/// multiple of 256).
///
/// `extra` is **not** typically empty. `decode_flow_sample`/
/// `decode_counter_sample` (`src/sflow/decoder.rs`) only curate
/// `raw_packet_header`/`sampled_ipv4`/`sampled_ipv6` flow records and
/// `generic_if_counters` counter records; every other record format —
/// enterprise-specific *and* standard extension records such as
/// `extended_switch` (VLAN tag/priority, close to universal on switch-sourced
/// flow samples) — is pushed into `extra` verbatim as
/// `{ "format", "length", "data_hex" }`. This is expected, not exceptional:
/// the ingestion design doc's own scope guard ("vendor/enterprise-specific
/// counter records and other non-generic record types are not decoded")
/// exists because real exporters send them
/// (`docs/superpowers/specs/2026-06-27-ingestion-formats-expansion-design.md`
/// §7).
///
/// **This must be a ceiling, not an average, because a single sample's
/// `extra` is attacker-influenced up to a hard cap.**
/// `decoder::MAX_UNKNOWN_RECORDS_PER_SAMPLE` (8) bounds how many non-curated
/// records one sample can contribute to one `SflowRecord`, and
/// `decoder::MAX_UNKNOWN_RECORDS_PER_DATAGRAM` (512) bounds the total across
/// a whole datagram -- but that datagram-wide budget resets on every
/// `decode_datagram` call and starts *full*, so it does not bound any single
/// record: the very first sample in a fresh datagram can still fill its own
/// `MAX_UNKNOWN_RECORDS_PER_SAMPLE` cap before the datagram-wide budget ever
/// bites. The worst case a real attacker can produce for one queued record is
/// therefore exactly that: the per-sample cap's worth of records, packed into
/// one sample.
///
/// Measured (not estimated -- via the counting allocator in
/// `tests/channel_budget_allocator.rs`'s
/// `measured_worst_case_single_sflow_record_bytes`, which is the source of
/// truth for this constant): `size_of::<SflowRecord>()` (256) plus the real
/// heap of `extra` holding 8 accepted `extended_switch`-shaped records
/// (enterprise 0, 16-byte body -- the same representative shape used
/// throughout this file) plus one `sample_cap` truncation marker for the 9th
/// declared record that tips the sample over the cap: 256 + 6641 = 6897
/// bytes, rounded up to 6912. See `measured_sflow_record_bytes_matches_constant`.
///
/// At 6912 bytes, `capacity_for` gives a channel depth of 15,170 records
/// (100 MiB / 6912), versus 81,920 at the old (unsound) 1280-byte average --
/// a ~5.4x depth cut, the tradeoff `decoder::MAX_UNKNOWN_RECORDS_PER_SAMPLE`'s
/// doc comment explains for choosing 8 over absorbing the full pre-round-2
/// cap of 32 into this constant (which would have cut depth ~19x instead).
/// 15,170 x 6912 = 104,855,040 bytes, genuinely under `CHANNEL_BUDGET_BYTES`
/// (104,857,600) -- the model this constant feeds is now sound for the
/// worst case, not just the common case.
pub const SFLOW_RECORD_BYTES: usize = 6912;

/// Measured footprint of one IPFIX channel message, which is a `Vec<FlowRecord>`
/// holding **all flows from one UDP datagram**: 8904 bytes measured for the
/// 10-flow representative datagram used by this repo's IPFIX fixtures — each
/// flow carrying a handful of non-curated IEs in `extra` (ToS, TTLs,
/// flow-end reason, biflow direction), as a real export template does —
/// rounded up to 9216. Note that a *non-empty* `extra` costs a whole 632-byte
/// BTreeMap node per flow whatever its key count, which is why five small
/// integer IEs cost 696 bytes each.
///
/// **Average-case, not a ceiling.** Flows-per-datagram is variable; this uses a
/// representative count from the repo's IPFIX test fixtures. Datagrams denser
/// than that average will push this source past `CHANNEL_BUDGET_BYTES`. Known
/// and accepted limitation — see the spec §4.3.
pub const IPFIX_DATAGRAM_BYTES: usize = 9216;

/// Measured footprint of one `Arc<WindowsEvent>` — the **pointee**, not the
/// 8-byte pointer in the channel slot. Each queued `Arc` is a distinct event;
/// the `Arc` is a transfer mechanism, not sharing. WEF fan-out to `.s3` and
/// `.local` clones the same `Arc` into both channels, so counting it once per
/// channel overcounts, which is the safe direction. Dominated by `raw_xml`
/// plus a populated `ParsedEvent.message` (real events are parsed on receipt,
/// not left `None` — see `measured_wef_event_bytes_counts_the_pointee_not_the_pointer`):
/// 12146 bytes measured for a ~5.6KB raw event with a representative parsed
/// Security-log message, rounded up to 12288. Unaffected by the BTreeMap
/// correction — the dominant `raw_xml`/`message` are plain `String`s and
/// `ParsedEvent.data` is always `None` on the real path.
pub const WEF_EVENT_BYTES: usize = 12288;

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

    /// The term the pre-correction estimator missed entirely: an object's
    /// bytes are dominated by BTreeMap nodes, which are allocated whole.
    #[test]
    fn json_heap_bytes_counts_btreemap_nodes_not_just_entries() {
        assert_eq!(json_heap_bytes(&serde_json::json!({})), 0);
        let one_key = json_heap_bytes(&serde_json::json!({"a": 1}));
        assert!(
            one_key > 600,
            "a single-key object still pays for a whole node; got {one_key}"
        );
        // Eleven keys fit in that same node, so the only growth is key bytes.
        let eleven_keys = json_heap_bytes(&serde_json::json!({
            "a": 1, "b": 1, "c": 1, "d": 1, "e": 1, "f": 1,
            "g": 1, "h": 1, "i": 1, "j": 1, "k": 1
        }));
        assert_eq!(eleven_keys, one_key + 10);
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

    /// Builds a minimal sFlow v5 datagram: header plus one flow_sample
    /// carrying `records` flow records in a format this decoder does not
    /// curate, each modelling a real switch's `extended_switch` record
    /// (VLAN tag/priority, enterprise 0, 16-byte body) — see
    /// `SFLOW_RECORD_BYTES`'s doc comment for why that per-record shape is
    /// representative, not an edge case, for switch-sourced sFlow, and for
    /// why `records` = `MAX_UNKNOWN_RECORDS_PER_SAMPLE_MIRROR + 1` (one over
    /// the cap, so the fixture also exercises the `sample_cap` truncation
    /// marker) is the worst case that actually bounds one channel slot.
    ///
    /// Hand-built rather than reusing `crate::sflow::decoder::tests`'s
    /// fixtures: none of them exercise the non-curated path with a
    /// representative (non-trivial) body size, and driving the real decoder
    /// — rather than hand-writing the resulting `serde_json::Value` — is what
    /// makes this measurement trustworthy (see the doc comment above).
    fn build_sflow_flow_sample_with_n_extension_records(records: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        // ── Datagram header (28 bytes) ──
        buf.extend_from_slice(&5u32.to_be_bytes()); // version = 5
        buf.extend_from_slice(&1u32.to_be_bytes()); // agent_addr_type = IPv4
        buf.extend_from_slice(&[10, 0, 0, 1]); // agent_addr
        buf.extend_from_slice(&0u32.to_be_bytes()); // sub_agent_id
        buf.extend_from_slice(&1u32.to_be_bytes()); // sequence_number
        buf.extend_from_slice(&1u32.to_be_bytes()); // uptime_ms
        buf.extend_from_slice(&1u32.to_be_bytes()); // num_samples = 1

        // ── flow_sample envelope ──
        let sample_body_len = 32 + (records as usize) * (8 + 16);
        buf.extend_from_slice(&1u32.to_be_bytes()); // data_format = flow_sample
        buf.extend_from_slice(&(sample_body_len as u32).to_be_bytes());

        // ── flow_sample body header (32 bytes, format 1 layout) ──
        buf.extend_from_slice(&1u32.to_be_bytes()); // sequence_number
        buf.extend_from_slice(&1u32.to_be_bytes()); // source_id
        buf.extend_from_slice(&1000u32.to_be_bytes()); // sampling_rate
        buf.extend_from_slice(&1000u32.to_be_bytes()); // sample_pool
        buf.extend_from_slice(&0u32.to_be_bytes()); // drops
        buf.extend_from_slice(&1u32.to_be_bytes()); // input ifindex
        buf.extend_from_slice(&2u32.to_be_bytes()); // output ifindex
        buf.extend_from_slice(&records.to_be_bytes()); // num_flow_records

        // ── flow records: extended_switch-shaped, enterprise=0 format=1001 ──
        // Not one of the three curated formats (1, 3, 4), so
        // `decode_flow_sample` stores each verbatim in `extra` (up to the
        // per-sample cap; any excess trips the `sample_cap` marker instead).
        for _ in 0..records {
            buf.extend_from_slice(&1001u32.to_be_bytes()); // flow_data_format
            buf.extend_from_slice(&16u32.to_be_bytes()); // flow_data_length
            buf.extend_from_slice(&[0u8; 16]); // in_vlan, in_pri, out_vlan, out_pri
        }

        buf
    }

    #[test]
    fn measured_sflow_record_bytes_matches_constant() {
        use crate::sflow::decoder::decode_datagram;
        use std::net::{IpAddr, Ipv4Addr};

        // Mirrors the private `decoder::MAX_UNKNOWN_RECORDS_PER_SAMPLE` (8):
        // this test cannot see that constant (module-private, different
        // module), so it duplicates the value with a comment, same
        // convention `tests/channel_budget_allocator.rs` uses for the same
        // reason. One more than the cap so the fixture also exercises the
        // `sample_cap` truncation marker -- see `SFLOW_RECORD_BYTES`'s doc
        // comment for why 8 accepted + 1 marker is the worst case that
        // actually bounds a single channel slot.
        const MAX_UNKNOWN_RECORDS_PER_SAMPLE_MIRROR: u32 = 8;

        let buf = build_sflow_flow_sample_with_n_extension_records(
            MAX_UNKNOWN_RECORDS_PER_SAMPLE_MIRROR + 1,
        );
        let mut records = decode_datagram(&buf, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
            .expect("representative datagram must decode");
        assert_eq!(records.len(), 1);
        let record = records.pop().unwrap();
        let extra = record
            .extra
            .as_array()
            .expect("fixture must populate extra with an array");
        assert_eq!(
            extra.len(),
            (MAX_UNKNOWN_RECORDS_PER_SAMPLE_MIRROR + 1) as usize,
            "fixture must land 8 accepted records plus 1 sample_cap marker; got {extra:?}"
        );

        // sFlow is a flat struct with no owned heap besides `extra`.
        let measured =
            std::mem::size_of::<crate::sflow::SflowRecord>() + json_heap_bytes(&record.extra);
        // SFLOW_RECORD_BYTES must be a ceiling for this worst-case-but-legitimate
        // shape, not merely "within 2x" -- see its doc comment. The real,
        // counting-allocator-measured number lives in
        // `tests/channel_budget_allocator.rs`'s
        // `measured_worst_case_single_sflow_record_bytes`, which is this
        // constant's actual source of truth; this test only confirms the
        // cheaper `json_heap_bytes` estimator used elsewhere in this file
        // agrees closely enough with that ceiling to trust it isn't
        // drastically wrong.
        assert!(
            measured <= SFLOW_RECORD_BYTES,
            "SflowRecord: measured {measured} bytes exceeds the SFLOW_RECORD_BYTES ceiling \
             ({SFLOW_RECORD_BYTES}); re-measure via the allocator test and raise the constant"
        );
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
