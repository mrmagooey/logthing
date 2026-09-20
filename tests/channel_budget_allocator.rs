//! Validates the channel-budget **estimator**, not the constants it feeds.
//!
//! `channel_budget.rs`'s own tests compare each `*_BYTES` constant against
//! `json_heap_bytes`, so they only ever prove the constant agrees with the
//! estimator — if the estimator is wrong, everything downstream is wrong and
//! every test still passes. (It was: before this test existed, `json_heap_bytes`
//! ignored `BTreeMap` node allocation and undercounted real heap by 2.4-3.1x,
//! so the "100 MiB" budget was really ~250 MiB.)
//!
//! This measures what the process actually allocates, with a counting global
//! allocator, and fails if the estimator drifts from it. It lives in its own
//! integration-test binary precisely because `#[global_allocator]` is
//! process-wide and must not perturb any other test.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    /// Net live bytes allocated by *this* thread. Thread-local rather than
    /// global so concurrently-running tests and the harness's own threads
    /// cannot pollute a measurement. Const-initialised and `Drop`-free, so
    /// touching it from inside the allocator cannot recurse or allocate.
    static LIVE: Cell<isize> = const { Cell::new(0) };
}

fn bump(delta: isize) {
    let _ = LIVE.try_with(|live| live.set(live.get() + delta));
}

struct CountingAlloc;

// SAFETY: every method forwards to `System` unchanged; the only addition is a
// non-allocating thread-local counter update.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        bump(layout.size() as isize);
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        bump(layout.size() as isize);
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        bump(-(layout.size() as isize));
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        bump(new_size as isize - layout.size() as isize);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

/// Heap bytes that `build` allocates and does **not** free — i.e. the real
/// footprint of the value it returns.
fn live_heap_of<T>(build: impl FnOnce() -> T) -> (T, usize) {
    let before = LIVE.with(Cell::get);
    let value = build();
    let after = LIVE.with(Cell::get);
    (value, (after - before).max(0) as usize)
}

/// Real allocation must be within 10% of the estimate, in either direction.
///
/// Not exact-equality: `btreemap_node_bytes` assumes packed nodes, and std's
/// node layout is an implementation detail that may shift. Not looser than
/// 10% either — the whole point is to catch the class of error that made this
/// test necessary, which was 144-211% off.
fn assert_within_10pct(real: usize, estimated: usize, what: &str) {
    let low = real * 9 / 10;
    let high = real * 11 / 10;
    assert!(
        estimated >= low && estimated <= high,
        "{what}: json_heap_bytes estimated {estimated} bytes but the allocator \
         saw {real} bytes ({:.2}x) -- expected {low}..={high}. Fix the \
         estimator, then re-derive every *_BYTES constant in \
         src/forwarding/channel_budget.rs from the new measurements.",
        real as f64 / estimated.max(1) as f64
    );
}

/// Flat object, one nesting level: the Zeek `conn` fixture from
/// `channel_budget.rs`'s `measured_zeek_record_bytes_matches_constant`.
/// Duplicated rather than shared because that fixture lives in a `#[cfg(test)]`
/// module the integration-test binary cannot see.
#[test]
fn json_heap_bytes_matches_real_allocation_for_a_zeek_conn_record() {
    let (fields, real) = live_heap_of(|| {
        serde_json::json!({
            "_path": "conn", "ts": 1717171717.123456, "uid": "CHhAvVGS1DHFjwGM9",
            "id.orig_h": "192.168.7.102", "id.orig_p": 33764,
            "id.resp_h": "93.184.216.34", "id.resp_p": 443,
            "proto": "tcp", "service": "ssl", "duration": 0.253,
            "orig_bytes": 1420, "resp_bytes": 5320, "conn_state": "SF",
            "local_orig": true, "local_resp": false, "missed_bytes": 0,
            "history": "ShADadFf", "orig_pkts": 12, "orig_ip_bytes": 1948,
            "resp_pkts": 14, "resp_ip_bytes": 5892
        })
    });
    let estimated = logthing::forwarding::channel_budget::json_heap_bytes(&fields);
    assert_within_10pct(real, estimated, "zeek conn fields");
}

/// Nested objects, where the old estimator was furthest off: every sub-object
/// costs a whole BTreeMap node of its own.
#[test]
fn json_heap_bytes_matches_real_allocation_for_a_nested_suricata_alert() {
    let (fields, real) = live_heap_of(|| {
        serde_json::json!({
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
        })
    });
    let estimated = logthing::forwarding::channel_budget::json_heap_bytes(&fields);
    assert_within_10pct(real, estimated, "suricata alert fields");
}

/// A small object of scalars — the shape IPFIX `extra` and HEC payloads take.
/// Five integer IEs own no string bytes at all, so this is almost pure node
/// overhead: the case the old estimator got most wrong (3.11x).
#[test]
fn json_heap_bytes_matches_real_allocation_for_a_small_scalar_object() {
    let (extra, real) = live_heap_of(|| {
        serde_json::json!({
            "ipClassOfService": 0,
            "minimumTTL": 64,
            "maximumTTL": 64,
            "flowEndReason": 3,
            "biflowDirection": 1
        })
    });
    let estimated = logthing::forwarding::channel_budget::json_heap_bytes(&extra);
    assert_within_10pct(real, estimated, "ipfix extra");
}

/// Guards the measurement rig itself: if `live_heap_of` silently returned 0
/// (TLS not wired up, allocator not installed), every assertion above would
/// pass vacuously for an estimator that also returned 0.
#[test]
fn the_counting_allocator_actually_counts() {
    let (v, real) = live_heap_of(|| vec![0u8; 4096]);
    assert_eq!(v.len(), 4096);
    assert!(real >= 4096, "counting allocator saw only {real} bytes");
}

/// An array wrapping one small object with a string value — the shape
/// sFlow's `extra` takes for a non-curated record (`{ "format", "length",
/// "data_hex" }`, produced by `push`ing onto a `Vec` one record at a time,
/// per `decode_flow_sample`/`decode_counter_sample` in `src/sflow/decoder.rs`).
///
/// This shape is not covered by the small-scalar-object or nested-object
/// cases above: it is the *array* wrapper, and the `Vec<Value>` it wraps is
/// built by repeated `push` rather than allocated at its final size in one
/// shot (as `serde_json::json!` array literals and IPFIX's `.collect()`
/// fixture are). A `push`-built `Vec`'s capacity can differ from a literal's
/// exact-capacity allocation, so this drives the *real* sFlow decoder over a
/// hand-built datagram rather than typing out an equivalent `json!` value,
/// to measure what production code actually allocates.
///
/// Backs `SFLOW_RECORD_BYTES` in `src/forwarding/channel_budget.rs`, whose
/// own unit test (`measured_sflow_record_bytes_matches_constant`) only
/// proves the constant agrees with `json_heap_bytes` — same rationale as
/// this file's header comment.
#[test]
fn json_heap_bytes_matches_real_allocation_for_a_populated_sflow_extra() {
    use logthing::sflow::decoder::decode_datagram;
    use std::net::{IpAddr, Ipv4Addr};

    // Minimal sFlow v5 datagram: one flow_sample (format 1) carrying one
    // flow record of format 1001 (not one of the three curated formats: 1
    // raw_packet_header, 3 sampled_ipv4, 4 sampled_ipv6), modelling a real
    // switch's `extended_switch` VLAN/priority record. Byte layout matches
    // `build_sflow_flow_sample_with_extension_record` in
    // `src/forwarding/channel_budget.rs`'s tests -- duplicated rather than
    // shared for the same reason this file's header comment gives for the
    // zeek/suricata fixtures.
    let mut buf = Vec::new();
    buf.extend_from_slice(&5u32.to_be_bytes()); // version = 5
    buf.extend_from_slice(&1u32.to_be_bytes()); // agent_addr_type = IPv4
    buf.extend_from_slice(&[10, 0, 0, 1]); // agent_addr
    buf.extend_from_slice(&0u32.to_be_bytes()); // sub_agent_id
    buf.extend_from_slice(&1u32.to_be_bytes()); // sequence_number
    buf.extend_from_slice(&1u32.to_be_bytes()); // uptime_ms
    buf.extend_from_slice(&1u32.to_be_bytes()); // num_samples = 1
    buf.extend_from_slice(&1u32.to_be_bytes()); // data_format = flow_sample
    buf.extend_from_slice(&56u32.to_be_bytes()); // sample_length = 32+8+16
    buf.extend_from_slice(&1u32.to_be_bytes()); // sequence_number
    buf.extend_from_slice(&1u32.to_be_bytes()); // source_id
    buf.extend_from_slice(&1000u32.to_be_bytes()); // sampling_rate
    buf.extend_from_slice(&1000u32.to_be_bytes()); // sample_pool
    buf.extend_from_slice(&0u32.to_be_bytes()); // drops
    buf.extend_from_slice(&1u32.to_be_bytes()); // input ifindex
    buf.extend_from_slice(&2u32.to_be_bytes()); // output ifindex
    buf.extend_from_slice(&1u32.to_be_bytes()); // num_flow_records = 1
    buf.extend_from_slice(&1001u32.to_be_bytes()); // flow_data_format = 1001
    buf.extend_from_slice(&16u32.to_be_bytes()); // flow_data_length = 16
    buf.extend_from_slice(&[0u8; 16]); // in_vlan, in_pri, out_vlan, out_pri

    let exporter = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let (extra, real) = live_heap_of(|| {
        let mut records = decode_datagram(&buf, exporter).expect("must decode");
        records.pop().expect("one record").extra
    });
    assert!(
        extra.as_array().is_some_and(|a| !a.is_empty()),
        "fixture must populate extra; got {extra}"
    );
    let estimated = logthing::forwarding::channel_budget::json_heap_bytes(&extra);
    assert_within_10pct(real, estimated, "sflow populated extra");
}

/// The core regression test for the sFlow `extra` amplification bug
/// (`MAX_UNKNOWN_RECORDS_PER_SAMPLE` in `src/sflow/decoder.rs`): a hostile
/// sample that declares thousands of unknown records must not retain heap
/// proportional to the attacker-declared record count.
///
/// Before the cap, this exact fixture (8,177 unknown records, matching the
/// demonstrated exploit) retained several MiB. The cap bounds retention to
/// a small, fixed footprint -- at most `MAX_UNKNOWN_RECORDS_PER_SAMPLE` (8)
/// `serde_json` records plus one truncation marker -- regardless of how many
/// records the sample claims.
#[test]
fn hostile_sflow_sample_heap_retention_is_bounded_by_the_cap_not_the_record_count() {
    use logthing::sflow::decoder::decode_datagram;
    use std::net::{IpAddr, Ipv4Addr};

    const NUM_RECORDS: u32 = 8177; // matches the demonstrated exploit shape
    let mut buf = Vec::new();
    buf.extend_from_slice(&5u32.to_be_bytes()); // version = 5
    buf.extend_from_slice(&1u32.to_be_bytes()); // agent_addr_type = IPv4
    buf.extend_from_slice(&[10, 0, 0, 1]); // agent_addr
    buf.extend_from_slice(&0u32.to_be_bytes()); // sub_agent_id
    buf.extend_from_slice(&1u32.to_be_bytes()); // sequence_number
    buf.extend_from_slice(&1u32.to_be_bytes()); // uptime_ms
    buf.extend_from_slice(&1u32.to_be_bytes()); // num_samples = 1

    let sample_body_len = 32 + (NUM_RECORDS as usize) * 8;
    buf.extend_from_slice(&1u32.to_be_bytes()); // data_format = flow_sample
    buf.extend_from_slice(&(sample_body_len as u32).to_be_bytes());
    buf.extend_from_slice(&1u32.to_be_bytes()); // sequence_number
    buf.extend_from_slice(&1u32.to_be_bytes()); // source_id
    buf.extend_from_slice(&1000u32.to_be_bytes()); // sampling_rate
    buf.extend_from_slice(&1000u32.to_be_bytes()); // sample_pool
    buf.extend_from_slice(&0u32.to_be_bytes()); // drops
    buf.extend_from_slice(&1u32.to_be_bytes()); // input ifindex
    buf.extend_from_slice(&2u32.to_be_bytes()); // output ifindex
    buf.extend_from_slice(&NUM_RECORDS.to_be_bytes()); // num_flow_records
    for _ in 0..NUM_RECORDS {
        buf.extend_from_slice(&1001u32.to_be_bytes()); // enterprise 0, format 1001 (unknown)
        buf.extend_from_slice(&0u32.to_be_bytes()); // flow_data_length = 0
    }

    let exporter = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let (extra, real) = live_heap_of(|| {
        let mut records = decode_datagram(&buf, exporter).expect("must decode");
        records.pop().expect("one record").extra
    });

    let array = extra.as_array().expect("extra must be an array");
    assert!(
        array.len() <= 9,
        "extra must be capped, not proportional to the declared {NUM_RECORDS} records; \
         got {} entries",
        array.len()
    );
    assert!(
        real < 50_000,
        "hostile sflow sample retained {real} bytes -- expected the cap to bound this \
         to a small, fixed footprint regardless of the attacker-declared record count"
    );
}

/// The real attack shape: a per-sample cap alone does not bound retention,
/// because an attacker can split records across many samples in one
/// datagram, each staying under the per-sample cap
/// (`MAX_UNKNOWN_RECORDS_PER_SAMPLE`). `decode_datagram` shares a single
/// `MAX_UNKNOWN_RECORDS_PER_DATAGRAM` budget across every sample it decodes,
/// which is the bound this test exercises.
///
/// Fixture: the maximum-density packing of capped samples into one
/// 65,535-byte UDP datagram. Each sample costs 8 (envelope) + 32
/// (flow-sample header) + 8*8 (8 unknown-record envelopes, zero-length
/// bodies) = 104 bytes on the wire, so (65535 - 28) / 104 = 629 samples fit
/// -- 629 * 8 = 5,032 unknown records *declared*, matching the worst-case
/// arithmetic in `MAX_UNKNOWN_RECORDS_PER_DATAGRAM`'s doc comment. Before
/// the datagram-wide budget, this shape retained ~5 MB (matching the
/// single-sample exploit, since the per-sample cap alone barely bit).
#[test]
fn multi_sample_hostile_sflow_datagram_heap_retention_is_bounded_by_the_datagram_budget() {
    use logthing::sflow::decoder::decode_datagram;
    use std::net::{IpAddr, Ipv4Addr};

    const NUM_SAMPLES: u32 = 629;
    const RECORDS_PER_SAMPLE: u32 = 8; // == MAX_UNKNOWN_RECORDS_PER_SAMPLE

    let mut buf = Vec::new();
    buf.extend_from_slice(&5u32.to_be_bytes()); // version = 5
    buf.extend_from_slice(&1u32.to_be_bytes()); // agent_addr_type = IPv4
    buf.extend_from_slice(&[10, 0, 0, 1]); // agent_addr
    buf.extend_from_slice(&0u32.to_be_bytes()); // sub_agent_id
    buf.extend_from_slice(&1u32.to_be_bytes()); // sequence_number
    buf.extend_from_slice(&1u32.to_be_bytes()); // uptime_ms
    buf.extend_from_slice(&NUM_SAMPLES.to_be_bytes()); // num_samples

    let sample_body_len = 32 + (RECORDS_PER_SAMPLE as usize) * 8;
    for _ in 0..NUM_SAMPLES {
        buf.extend_from_slice(&1u32.to_be_bytes()); // data_format = flow_sample
        buf.extend_from_slice(&(sample_body_len as u32).to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes()); // sequence_number
        buf.extend_from_slice(&1u32.to_be_bytes()); // source_id
        buf.extend_from_slice(&1000u32.to_be_bytes()); // sampling_rate
        buf.extend_from_slice(&1000u32.to_be_bytes()); // sample_pool
        buf.extend_from_slice(&0u32.to_be_bytes()); // drops
        buf.extend_from_slice(&1u32.to_be_bytes()); // input ifindex
        buf.extend_from_slice(&2u32.to_be_bytes()); // output ifindex
        buf.extend_from_slice(&RECORDS_PER_SAMPLE.to_be_bytes()); // num_flow_records
        for _ in 0..RECORDS_PER_SAMPLE {
            buf.extend_from_slice(&1001u32.to_be_bytes()); // enterprise 0, format 1001
            buf.extend_from_slice(&0u32.to_be_bytes()); // flow_data_length = 0
        }
    }
    assert!(
        buf.len() <= 65_535,
        "fixture must fit one UDP datagram; got {} bytes",
        buf.len()
    );

    // Measures the whole `Vec<SflowRecord>` decode_datagram returns, not just
    // the `extra` fields: each record's fixed struct fields are exactly what
    // occupies a channel slot alongside its heap (see `channel_budget.rs`'s
    // module doc on block-array slot cost), so this is the faithful proxy
    // for what queueing every one of these records would actually cost.
    let exporter = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let (records, real) = live_heap_of(|| decode_datagram(&buf, exporter).expect("must decode"));

    let total_accepted_records: usize = records
        .iter()
        .filter_map(|r| r.extra.as_array())
        .flat_map(|a| a.iter())
        .filter(|v| v.get("data_hex").is_some())
        .count();
    assert_eq!(
        total_accepted_records,
        512,
        "total accepted unknown records across the whole datagram must be bounded by \
         the datagram budget (512), not by {NUM_SAMPLES} samples x {RECORDS_PER_SAMPLE} \
         records/sample = {}",
        NUM_SAMPLES * RECORDS_PER_SAMPLE
    );

    // Before the datagram-wide budget, this shape retained several MB (the
    // per-sample cap alone barely reduced the single-sample exploit's ~5.34
    // MB). Measured post-fix: ~613,142 bytes total for 629 queued records --
    // 629 * 256 = 161,024 bytes of struct overhead (every sample still
    // produces one `SflowRecord`, whether or not its `extra` holds
    // anything) plus ~452,118 bytes of heap for the 512 accepted records
    // and one aggregate marker (see `decode_datagram`'s post-loop handling
    // and `MAX_UNKNOWN_RECORDS_PER_DATAGRAM`'s doc comment) -- a small,
    // fixed footprint regardless of how records are spread across samples,
    // and nowhere near the original ~5.34 MB.
    assert!(
        real < 700_000,
        "multi-sample hostile datagram retained {real} bytes -- expected the datagram \
         budget to bound this regardless of how records are spread across samples"
    );
}

/// Round-2 review finding: `MAX_UNKNOWN_RECORDS_PER_DATAGRAM` bounds a
/// *datagram's* total retention, but it resets on every `decode_datagram`
/// call and so does not bound the cost of any *one* queued `SflowRecord` --
/// the very first sample in a fresh datagram can still accept a full
/// `MAX_UNKNOWN_RECORDS_PER_SAMPLE` worth of records. That per-record figure
/// is what actually bounds one channel slot, so it is what
/// `channel_budget::SFLOW_RECORD_BYTES` must measure and ceiling.
///
/// Round-3 review finding: the count cap alone still understated the true
/// worst case, because it says nothing about how large each *individual*
/// record's body is. `flow_data_length` is an attacker-controlled `u32`
/// bounded only by the remaining sample body (i.e. up to the ~65 KB UDP
/// receive buffer), and the whole body used to be `hex::encode`d verbatim --
/// so one oversized record could cost ~120 KB on its own, regardless of the
/// per-sample/per-datagram count caps. `decoder::MAX_UNKNOWN_RECORD_BODY_
/// BYTES` (128) now caps the hex-encoded body length per record.
///
/// Round-4 review finding: `decoder::unknown_record_json` produces two
/// different shapes depending on the call site -- the enterprise-specific
/// sites (`rec_enterprise != 0`, in both `decode_flow_sample` and
/// `decode_counter_sample`) pass `Some(rec_enterprise)` and get one extra
/// `"enterprise"` key per record; the "other unknown format" site
/// (enterprise 0, an unrecognised format) passes `None` and does not. A
/// prior version of this test only measured the cheaper (enterprise-absent)
/// shape despite claiming to measure the true worst case. This measures
/// BOTH shapes and asserts the enterprise-specific one -- the genuinely more
/// expensive of the two -- is what `channel_budget::SFLOW_RECORD_BYTES`
/// ceilings.
///
/// Both shapes use `MAX_UNKNOWN_RECORDS_PER_SAMPLE` (8) accepted records,
/// each with a body far larger than `MAX_UNKNOWN_RECORD_BODY_BYTES` (7000
/// bytes -- comfortably larger than the 128-byte cap while still letting 9
/// such records fit in one UDP datagram, matching how an attacker would
/// actually pack this shape on the wire), plus one `sample_cap` truncation
/// marker (a 9th declared record tips the sample over the cap -- pack the
/// per-sample cap's worth of records into the first sample of a datagram,
/// before the datagram-wide budget can bite at all).
///
/// `std::mem::size_of::<SflowRecord>()` is added because that fixed part of
/// the struct is what actually occupies the channel slot alongside the
/// heap-allocated `extra` -- same methodology as
/// `measured_sflow_record_bytes_matches_constant` in `channel_budget.rs`,
/// except here the heap portion is the real counting-allocator measurement,
/// not the `json_heap_bytes` estimator, per the round-2 review's explicit
/// "measure it, do not estimate it" instruction.
#[test]
fn measured_worst_case_single_sflow_record_bytes() {
    use logthing::sflow::SflowRecord;
    use logthing::sflow::decoder::decode_datagram;
    use std::net::{IpAddr, Ipv4Addr};

    const MAX_UNKNOWN_RECORDS_PER_SAMPLE_MIRROR: u32 = 8; // == decoder::MAX_UNKNOWN_RECORDS_PER_SAMPLE (private)
    const RECORDS_IN_SAMPLE: u32 = MAX_UNKNOWN_RECORDS_PER_SAMPLE_MIRROR + 1; // 9: 8 accepted, 1 dropped
    const BODY_LEN: u32 = 7000; // far larger than MAX_UNKNOWN_RECORD_BODY_BYTES (128)

    // Builds a datagram with one flow_sample carrying `RECORDS_IN_SAMPLE`
    // flow records, all with `flow_data_format`, each with a `BODY_LEN`-byte
    // body.
    fn build(flow_data_format: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&5u32.to_be_bytes()); // version = 5
        buf.extend_from_slice(&1u32.to_be_bytes()); // agent_addr_type = IPv4
        buf.extend_from_slice(&[10, 0, 0, 1]); // agent_addr
        buf.extend_from_slice(&0u32.to_be_bytes()); // sub_agent_id
        buf.extend_from_slice(&1u32.to_be_bytes()); // sequence_number
        buf.extend_from_slice(&1u32.to_be_bytes()); // uptime_ms
        buf.extend_from_slice(&1u32.to_be_bytes()); // num_samples = 1

        let sample_body_len = 32 + (RECORDS_IN_SAMPLE as usize) * (8 + BODY_LEN as usize);
        buf.extend_from_slice(&1u32.to_be_bytes()); // data_format = flow_sample
        buf.extend_from_slice(&(sample_body_len as u32).to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes()); // sequence_number
        buf.extend_from_slice(&1u32.to_be_bytes()); // source_id
        buf.extend_from_slice(&1000u32.to_be_bytes()); // sampling_rate
        buf.extend_from_slice(&1000u32.to_be_bytes()); // sample_pool
        buf.extend_from_slice(&0u32.to_be_bytes()); // drops
        buf.extend_from_slice(&1u32.to_be_bytes()); // input ifindex
        buf.extend_from_slice(&2u32.to_be_bytes()); // output ifindex
        buf.extend_from_slice(&RECORDS_IN_SAMPLE.to_be_bytes()); // num_flow_records
        for _ in 0..RECORDS_IN_SAMPLE {
            buf.extend_from_slice(&flow_data_format.to_be_bytes());
            buf.extend_from_slice(&BODY_LEN.to_be_bytes());
            buf.extend_from_slice(&vec![0xABu8; BODY_LEN as usize]); // oversized body
        }
        assert!(
            buf.len() <= 65_535,
            "fixture must fit one UDP datagram; got {} bytes",
            buf.len()
        );
        buf
    }

    // Decodes `flow_data_format`'s fixture, asserts the common shape
    // (8 accepted + 1 sample_cap marker, each accepted record's body
    // truncated to the cap, "enterprise" key presence matching
    // `expect_enterprise_key`), and returns the measured total bytes for
    // one queued `SflowRecord`.
    fn measure(flow_data_format: u32, expect_enterprise_key: bool) -> usize {
        let buf = build(flow_data_format);
        let exporter = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let (extra, real_extra_heap) = live_heap_of(|| {
            let mut records = decode_datagram(&buf, exporter).expect("must decode");
            records.pop().expect("one record").extra
        });

        let array = extra.as_array().expect("extra must be an array");
        assert_eq!(
            array.len(),
            9,
            "fixture must land exactly 8 accepted records plus 1 sample_cap marker; \
             got {array:?}"
        );
        assert_eq!(
            array.last().and_then(|v| v.get("reason")),
            Some(&serde_json::json!("sample_cap")),
            "the 9th declared record must trip the per-sample cap, not the datagram budget"
        );
        assert!(
            array[..8]
                .iter()
                .all(|v| v.get("body_truncated") == Some(&serde_json::json!(true))),
            "every accepted 7000-byte-body record must be flagged as body_truncated; \
             got {array:?}"
        );
        assert!(
            array[..8].iter().all(|v| v
                .get("data_hex")
                .and_then(|h| h.as_str())
                .is_some_and(|h| h.len() == 128 * 2)),
            "every accepted record's data_hex must be capped at MAX_UNKNOWN_RECORD_BODY_BYTES \
             (128 bytes = 256 hex chars) regardless of the 7000-byte declared body; got {array:?}"
        );
        assert_eq!(
            array[..8].iter().all(|v| v.get("enterprise").is_some()),
            expect_enterprise_key,
            "\"enterprise\" key presence must match the call site exercised; got {array:?}"
        );

        std::mem::size_of::<SflowRecord>() + real_extra_heap
    }

    // Enterprise-absent: the "other unknown format" push site
    // (`unknown_record_json(None, ...)`) -- enterprise 0, an unrecognised
    // format.
    let enterprise_absent = measure(1001, false);
    // Enterprise-specific: `rec_enterprise != 0` push site
    // (`unknown_record_json(Some(rec_enterprise), ...)`) -- an arbitrary
    // nonzero SMI-private-enterprise-shaped value (4991), format 1001.
    let enterprise_specific = measure((4991u32 << 12) | 1001, true);

    eprintln!(
        "measured worst-case single SflowRecord: enterprise-absent={enterprise_absent} bytes, \
         enterprise-specific={enterprise_specific} bytes"
    );

    assert!(
        enterprise_specific > enterprise_absent,
        "the enterprise-specific shape (one extra JSON key per accepted record) must be the \
         more expensive of the two reachable shapes -- got \
         enterprise_absent={enterprise_absent}, enterprise_specific={enterprise_specific}; \
         if this no longer holds, `channel_budget::SFLOW_RECORD_BYTES` must be re-derived \
         from whichever shape is now more expensive"
    );

    // Both reachable shapes must clear the ceiling (>=, not an average) --
    // see `channel_budget::SFLOW_RECORD_BYTES`'s doc comment. The
    // enterprise-specific shape is expected to be the tighter of the two.
    for (label, total) in [
        ("enterprise-absent", enterprise_absent),
        ("enterprise-specific", enterprise_specific),
    ] {
        assert!(
            total <= logthing::forwarding::channel_budget::SFLOW_RECORD_BYTES,
            "{label} worst-case single record is {total} bytes, which exceeds \
             SFLOW_RECORD_BYTES={}; re-measure and raise the constant",
            logthing::forwarding::channel_budget::SFLOW_RECORD_BYTES
        );
    }
}

/// Round-3 review regression: a single record with a near-maximum body (the
/// shape that used to cost ~120 KB on its own, per `MAX_UNKNOWN_RECORD_BODY_
/// BYTES`'s doc comment) must have its hex-encoded body capped and its real
/// retained heap bounded to a small, fixed footprint -- nowhere near
/// proportional to the ~60,000-byte body an attacker actually sent.
#[test]
fn near_max_body_unknown_record_is_truncated_and_bounded() {
    use logthing::sflow::decoder::decode_datagram;
    use std::net::{IpAddr, Ipv4Addr};

    const BODY_LEN: u32 = 60_000; // near the largest that fits one UDP datagram

    let mut buf = Vec::new();
    buf.extend_from_slice(&5u32.to_be_bytes()); // version = 5
    buf.extend_from_slice(&1u32.to_be_bytes()); // agent_addr_type = IPv4
    buf.extend_from_slice(&[10, 0, 0, 1]); // agent_addr
    buf.extend_from_slice(&0u32.to_be_bytes()); // sub_agent_id
    buf.extend_from_slice(&1u32.to_be_bytes()); // sequence_number
    buf.extend_from_slice(&1u32.to_be_bytes()); // uptime_ms
    buf.extend_from_slice(&1u32.to_be_bytes()); // num_samples = 1

    let sample_body_len = 32 + 8 + BODY_LEN as usize;
    buf.extend_from_slice(&1u32.to_be_bytes()); // data_format = flow_sample
    buf.extend_from_slice(&(sample_body_len as u32).to_be_bytes());
    buf.extend_from_slice(&1u32.to_be_bytes()); // sequence_number
    buf.extend_from_slice(&1u32.to_be_bytes()); // source_id
    buf.extend_from_slice(&1000u32.to_be_bytes()); // sampling_rate
    buf.extend_from_slice(&1000u32.to_be_bytes()); // sample_pool
    buf.extend_from_slice(&0u32.to_be_bytes()); // drops
    buf.extend_from_slice(&1u32.to_be_bytes()); // input ifindex
    buf.extend_from_slice(&2u32.to_be_bytes()); // output ifindex
    buf.extend_from_slice(&1u32.to_be_bytes()); // num_flow_records = 1
    buf.extend_from_slice(&1001u32.to_be_bytes()); // enterprise 0, format 1001
    buf.extend_from_slice(&BODY_LEN.to_be_bytes()); // flow_data_length = 60000
    buf.extend_from_slice(&vec![0xCDu8; BODY_LEN as usize]);
    assert!(
        buf.len() <= 65_535,
        "fixture must fit one UDP datagram; got {} bytes",
        buf.len()
    );

    let exporter = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let (extra, real) = live_heap_of(|| {
        let mut records = decode_datagram(&buf, exporter).expect("must decode");
        records.pop().expect("one record").extra
    });

    let array = extra.as_array().expect("extra must be an array");
    assert_eq!(array.len(), 1, "the single record must survive, capped");
    let record = &array[0];
    assert_eq!(
        record.get("length"),
        Some(&serde_json::json!(BODY_LEN)),
        "the original declared length must still be reported, uncapped"
    );
    assert_eq!(record.get("body_truncated"), Some(&serde_json::json!(true)));
    assert_eq!(
        record
            .get("data_hex")
            .and_then(|h| h.as_str())
            .map(str::len),
        Some(128 * 2),
        "data_hex must be capped at 256 hex chars regardless of the 60,000-byte body"
    );

    // Before the cap: ~800 bytes of BTreeMap node + 2 bytes of hex per input
    // byte =~ 800 + 2*60,000 =~ 120,800 bytes for this one record. After the
    // cap, retention must be a small, fixed footprint unrelated to BODY_LEN.
    assert!(
        real < 5_000,
        "near-max-body unknown record retained {real} bytes -- expected the body cap to \
         bound this regardless of the attacker-declared body length"
    );
}

/// Round-3 review requirement: confirm the body cap does not touch a normal,
/// small unknown record -- no truncation flag, full hex content preserved.
#[test]
fn normal_small_unknown_record_body_is_not_truncated() {
    use logthing::sflow::decoder::decode_datagram;
    use std::net::{IpAddr, Ipv4Addr};

    // Same fixture shape as `json_heap_bytes_matches_real_allocation_for_a_
    // populated_sflow_extra` above: a 16-byte extended_switch-shaped body,
    // comfortably under MAX_UNKNOWN_RECORD_BODY_BYTES (128).
    let mut buf = Vec::new();
    buf.extend_from_slice(&5u32.to_be_bytes());
    buf.extend_from_slice(&1u32.to_be_bytes());
    buf.extend_from_slice(&[10, 0, 0, 1]);
    buf.extend_from_slice(&0u32.to_be_bytes());
    buf.extend_from_slice(&1u32.to_be_bytes());
    buf.extend_from_slice(&1u32.to_be_bytes());
    buf.extend_from_slice(&1u32.to_be_bytes());
    buf.extend_from_slice(&1u32.to_be_bytes());
    buf.extend_from_slice(&56u32.to_be_bytes());
    buf.extend_from_slice(&1u32.to_be_bytes());
    buf.extend_from_slice(&1u32.to_be_bytes());
    buf.extend_from_slice(&1000u32.to_be_bytes());
    buf.extend_from_slice(&1000u32.to_be_bytes());
    buf.extend_from_slice(&0u32.to_be_bytes());
    buf.extend_from_slice(&1u32.to_be_bytes());
    buf.extend_from_slice(&2u32.to_be_bytes());
    buf.extend_from_slice(&1u32.to_be_bytes());
    buf.extend_from_slice(&1001u32.to_be_bytes());
    buf.extend_from_slice(&16u32.to_be_bytes());
    buf.extend_from_slice(&[0xEFu8; 16]);

    let exporter = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let mut records = decode_datagram(&buf, exporter).expect("must decode");
    let extra = records.pop().unwrap().extra;
    let array = extra.as_array().expect("extra must be an array");
    assert_eq!(array.len(), 1);
    let record = &array[0];
    assert_eq!(
        record.get("body_truncated"),
        None,
        "a normal 16-byte body must not be flagged"
    );
    assert_eq!(
        record
            .get("data_hex")
            .and_then(|h| h.as_str())
            .map(str::len),
        Some(16 * 2),
        "a normal 16-byte body's hex must be preserved in full"
    );
}
