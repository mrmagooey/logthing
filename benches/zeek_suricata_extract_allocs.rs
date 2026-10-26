//! Allocation-count + criterion micro-benchmark for the writer-side field extraction of the Zeek
//! (conn/dns/http/envelope) and Suricata (envelope) accumulators -- perf fix 4.
//!
//! A counting `#[global_allocator]` wrapper counts allocations (alloc, alloc_zeroed, realloc) and
//! requested bytes only while `COUNTING` is set (one relaxed load per allocation otherwise).
//! `print_alloc_counts` runs each case once to warm lazy statics, then once more under the
//! counter, and prints `ALLOCS case=.. allocs_per_record=.. bytes_per_record=..` BEFORE criterion
//! starts. Counts cover `try_append` for N records plus the single `finish`, i.e. exactly the
//! writer-side extraction cost; record construction happens before the counted window.
//!
//! Public API only, so this file applies unchanged to a pre-fix checkout.
//!
//! Run with: `cargo bench --bench zeek_suricata_extract_allocs`
//! Smoke:    `cargo bench --bench zeek_suricata_extract_allocs -- --test`

use arrow::datatypes::Schema;
use arrow::record_batch::RecordBatch;
use chrono::Utc;
use criterion::{Criterion, Throughput, criterion_group};
use logthing::forwarding::buffered_writer::ParquetSink;
use logthing::forwarding::suricata_s3::SuricataSink;
use logthing::forwarding::zeek_s3::ZeekSink;
use logthing::suricata::SuricataRecord;
use logthing::suricata::schema::envelope_schema as suricata_envelope_schema;
use logthing::zeek::ZeekRecord;
use logthing::zeek::schema::{
    conn_schema, dns_schema, envelope_schema as zeek_envelope_schema, http_schema,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const N: usize = 1000;

struct CountingAlloc;

static COUNTING: AtomicBool = AtomicBool::new(false);
static ALLOCS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);

fn note(bytes: usize) {
    if COUNTING.load(Ordering::Relaxed) {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
    }
}

// SAFETY: every method forwards to `System` with the caller's arguments unchanged.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note(new_size);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

fn counted<R>(f: impl FnOnce() -> R) -> (R, u64, u64) {
    ALLOCS.store(0, Ordering::Relaxed);
    BYTES.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    let r = f();
    COUNTING.store(false, Ordering::Relaxed);
    (
        r,
        ALLOCS.load(Ordering::Relaxed),
        BYTES.load(Ordering::Relaxed),
    )
}

fn zeek_record(log_path: &str, fields: serde_json::Value) -> ZeekRecord {
    ZeekRecord {
        log_path: log_path.to_string(),
        fields,
        received_at: Utc::now(),
    }
}

/// loadgen's conn shape plus the extra fields a real Zeek conn.log carries.
fn conn_record(i: usize, mismatch: bool) -> ZeekRecord {
    let orig_p: serde_json::Value = if mismatch {
        serde_json::json!("not-a-port")
    } else {
        serde_json::json!(1024 + (i % 60_000))
    };
    zeek_record(
        "conn",
        serde_json::json!({
            "_path": "conn",
            "ts": 1700000000.0 + i as f64,
            "uid": format!("CLoadgen{i:016x}"),
            "id.orig_h": format!("10.0.{}.{}", (i / 256) % 256, i % 256),
            "id.orig_p": orig_p,
            "id.resp_h": "10.1.0.1",
            "id.resp_p": 443,
            "proto": "tcp",
            "service": "ssl",
            "conn_state": "SF",
            "history": "ShADadFf",
            "orig_bytes": 100 + (i % 10_000),
            "resp_bytes": 200 + ((i * 7) % 20_000),
            "duration": 0.01 + (i % 1000) as f64 / 1000.0,
            "orig_pkts": 4,
            "resp_pkts": 5,
            "local_orig": true,
            "local_resp": false,
            "missed_bytes": 0,
            "orig_ip_bytes": 260,
            "resp_ip_bytes": 300,
            "tunnel_parents": [],
        }),
    )
}

fn dns_record(i: usize) -> ZeekRecord {
    zeek_record(
        "dns",
        serde_json::json!({
            "_path": "dns",
            "ts": 1700000100.0 + i as f64,
            "uid": format!("CDns{i:016x}"),
            "id.orig_h": "192.168.1.100",
            "id.orig_p": 53322 + (i % 1000),
            "id.resp_h": "8.8.8.8",
            "id.resp_p": 53,
            "proto": "udp",
            "trans_id": 4242,
            "query": format!("h{i}.example.com"),
            "qclass_name": "C_INTERNET",
            "qtype_name": "A",
            "rcode_name": "NOERROR",
            "answers": ["1.2.3.4", "5.6.7.8"],
            "TTLs": [60.0, 60.0],
            "rejected": false,
        }),
    )
}

fn http_record(i: usize) -> ZeekRecord {
    zeek_record(
        "http",
        serde_json::json!({
            "_path": "http",
            "ts": 1700000200.0 + i as f64,
            "uid": format!("CHttp{i:016x}"),
            "id.orig_h": "192.168.1.100",
            "id.orig_p": 51234 + (i % 1000),
            "id.resp_h": "93.184.216.34",
            "id.resp_p": 80,
            "method": "GET",
            "host": "www.example.com",
            "uri": format!("/path/to/a/reasonably/long/resource/{i}?with=query&params=here"),
            "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "status_code": 200,
            "request_body_len": 0,
            "response_body_len": 1256,
            "version": "1.1",
            "trans_depth": 1,
        }),
    )
}

/// An unmodelled stream: goes through the Zeek envelope accumulator.
fn weird_record(i: usize) -> ZeekRecord {
    zeek_record(
        "weird",
        serde_json::json!({
            "_path": "weird",
            "ts": 1700000300.0 + i as f64,
            "uid": format!("CWeird{i:016x}"),
            "id.orig_h": "10.0.0.9",
            "id.orig_p": 40000,
            "id.resp_h": "10.0.0.10",
            "id.resp_p": 80,
            "name": "bad_HTTP_request",
            "notice": false,
            "peer": "zeek",
        }),
    )
}

fn alert_record(i: usize) -> SuricataRecord {
    SuricataRecord {
        event_type: "alert".to_string(),
        fields: serde_json::json!({
            "timestamp": "2026-10-25T12:00:00.000000+0000",
            "flow_id": 1_234_567_890_123_456_u64 + i as u64,
            "event_type": "alert",
            "src_ip": format!("10.0.{}.{}", (i / 256) % 256, i % 256),
            "src_port": 1024 + (i % 60_000),
            "dest_ip": "10.1.0.1",
            "dest_port": 443,
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2_013_028,
                "rev": 6,
                "signature": "ET POLICY curl User-Agent Outbound",
                "category": "Attempted Information Leak",
                "severity": 1 + (i % 3),
            },
            "flow": {
                "pkts_toserver": 4 + (i % 20),
                "pkts_toclient": 3 + (i % 15),
                "bytes_toserver": 500 + (i % 10_000),
                "bytes_toclient": 1200 + ((i * 7) % 20_000),
            },
        }),
        received_at: Utc::now(),
    }
}

struct ZeekCase {
    name: &'static str,
    schema: Arc<Schema>,
    records: Vec<ZeekRecord>,
}

fn zeek_cases() -> Vec<ZeekCase> {
    vec![
        ZeekCase {
            name: "conn_extras",
            schema: conn_schema(),
            records: (0..N).map(|i| conn_record(i, false)).collect(),
        },
        ZeekCase {
            name: "conn_mismatch_orig_p",
            schema: conn_schema(),
            records: (0..N).map(|i| conn_record(i, true)).collect(),
        },
        ZeekCase {
            name: "dns",
            schema: dns_schema(),
            records: (0..N).map(dns_record).collect(),
        },
        ZeekCase {
            name: "http",
            schema: http_schema(),
            records: (0..N).map(http_record).collect(),
        },
        ZeekCase {
            name: "envelope_weird",
            schema: zeek_envelope_schema(),
            records: (0..N).map(weird_record).collect(),
        },
    ]
}

fn run_zeek(case: &ZeekCase) -> RecordBatch {
    let mut acc = ZeekSink
        .new_batch(&case.schema)
        .expect("ZeekSink must opt into the amortized path for every schema");
    let now = Utc::now();
    for r in &case.records {
        assert!(
            acc.try_append(r, now).unwrap(),
            "record must match {}",
            case.name
        );
    }
    acc.finish().unwrap()
}

fn run_suricata(records: &[SuricataRecord]) -> RecordBatch {
    let schema = suricata_envelope_schema();
    let mut acc = SuricataSink
        .new_batch(&schema)
        .expect("SuricataSink must opt into the amortized path");
    let now = Utc::now();
    for r in records {
        assert!(acc.try_append(r, now).unwrap());
    }
    acc.finish().unwrap()
}

fn print_one(name: &str, run: impl Fn() -> RecordBatch) {
    black_box(run()); // warm lazy statics (schema registry, LazyLock schemas)
    let (batch, allocs, bytes) = counted(&run);
    assert_eq!(batch.num_rows(), N);
    println!(
        "ALLOCS case={name} n={N} allocs_per_record={:.2} bytes_per_record={:.1}",
        allocs as f64 / N as f64,
        bytes as f64 / N as f64
    );
    black_box(batch);
}

fn print_alloc_counts() {
    for case in zeek_cases() {
        print_one(&format!("zeek_{}", case.name), || run_zeek(&case));
    }
    let alerts: Vec<SuricataRecord> = (0..N).map(alert_record).collect();
    print_one("suricata_alert", || run_suricata(&alerts));
}

fn bench_zeek(c: &mut Criterion) {
    let mut group = c.benchmark_group("zeek_extract_amortized_1000");
    group.throughput(Throughput::Elements(N as u64));
    for case in zeek_cases() {
        group.bench_function(case.name, |b| {
            b.iter(|| black_box(run_zeek(black_box(&case))))
        });
    }
    group.finish();
}

fn bench_suricata(c: &mut Criterion) {
    let alerts: Vec<SuricataRecord> = (0..N).map(alert_record).collect();
    let mut group = c.benchmark_group("suricata_extract_amortized_1000");
    group.throughput(Throughput::Elements(N as u64));
    group.bench_function("alert", |b| {
        b.iter(|| black_box(run_suricata(black_box(&alerts))))
    });
    group.finish();
}

criterion_group!(benches, bench_zeek, bench_suricata);

fn main() {
    print_alloc_counts();
    benches();
    Criterion::default().configure_from_args().final_summary();
}
