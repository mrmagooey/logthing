//! Criterion micro-benchmark for the HEC / NDJSON body parsers
//! (`parse_hec_event_body`, `parse_ndjson_body`), plus deterministic allocation counts.
//!
//! A counting `#[global_allocator]` wraps `System` and counts only while `COUNTING` is set
//! (one relaxed load per allocation otherwise). Before criterion runs, `main` prints
//! `ALLOC_COUNT <case> allocs_per_record=<n> bytes_per_record=<n>` for each case.
//! `realloc` counts as one allocation of the new size.
//!
//! Run with: `cargo bench --bench hec_parse_event_body`

use criterion::{Criterion, Throughput, criterion_group};
use logthing::ingest::{parse_hec_event_body, parse_ndjson_body};
use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

struct CountingAlloc;

static COUNTING: AtomicBool = AtomicBool::new(false);
static ALLOCS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);

#[inline]
fn record(size: usize) {
    if COUNTING.load(Ordering::Relaxed) {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(size as u64, Ordering::Relaxed);
    }
}

// SAFETY: every method forwards to `System` unchanged; counting has no effect on layouts.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record(new_size);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

/// One HEC envelope line with a nested `event` object, indexed `fields` and envelope metadata.
fn hec_line(i: usize) -> String {
    serde_json::json!({
        "event": {
            "action": "login",
            "user": {"name": "alice", "id": i, "groups": ["admins", "ops", "dev"]},
            "http": {"method": "GET", "path": "/api/v1/widgets", "status": 200},
            "message": "user alice logged in from 10.0.0.5",
        },
        "sourcetype": "audit",
        "host": "srv1",
        "time": 1700000000.5,
        "source": "/var/log/app.log",
        "index": "main",
        "fields": {"env": "prod", "dc": "eu1", "n": 3},
    })
    .to_string()
}

/// One plain NDJSON line (generic `/ingest`).
fn ndjson_line(i: usize) -> String {
    serde_json::json!({
        "host": "h1", "msg": "hello world", "seq": i,
        "tags": ["a", "b"], "nested": {"k": "v", "n": 1},
    })
    .to_string()
}

fn body(lines: usize, make: fn(usize) -> String) -> Vec<u8> {
    (0..lines)
        .map(make)
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes()
}

fn print_alloc_counts(case: &str, lines: usize, f: &dyn Fn()) {
    const ITERS: u64 = 200;
    f(); // warm up lazy statics outside the counted window
    ALLOCS.store(0, Ordering::SeqCst);
    BYTES.store(0, Ordering::SeqCst);
    COUNTING.store(true, Ordering::SeqCst);
    for _ in 0..ITERS {
        f();
    }
    COUNTING.store(false, Ordering::SeqCst);
    let records = ITERS * lines as u64;
    println!(
        "ALLOC_COUNT {case} allocs_per_record={:.1} bytes_per_record={:.0}",
        ALLOCS.load(Ordering::SeqCst) as f64 / records as f64,
        BYTES.load(Ordering::SeqCst) as f64 / records as f64,
    );
}

fn report_alloc_counts() {
    for lines in [10usize, 100] {
        let hec = body(lines, hec_line);
        print_alloc_counts(&format!("hec_event_{lines}"), lines, &|| {
            black_box(parse_hec_event_body(black_box(&hec), "t").unwrap());
        });
        let nd = body(lines, ndjson_line);
        print_alloc_counts(&format!("ndjson_{lines}"), lines, &|| {
            black_box(parse_ndjson_body(black_box(&nd), "t").unwrap());
        });
    }
}

fn bench_parsers(c: &mut Criterion) {
    for lines in [10usize, 100] {
        let hec = body(lines, hec_line);
        let mut group = c.benchmark_group("hec_parse_event_body");
        group.throughput(Throughput::Elements(lines as u64));
        group.bench_function(format!("{lines}_lines"), |b| {
            b.iter(|| black_box(parse_hec_event_body(black_box(&hec), "t").unwrap()));
        });
        group.finish();

        let nd = body(lines, ndjson_line);
        let mut group = c.benchmark_group("parse_ndjson_body");
        group.throughput(Throughput::Elements(lines as u64));
        group.bench_function(format!("{lines}_lines"), |b| {
            b.iter(|| black_box(parse_ndjson_body(black_box(&nd), "t").unwrap()));
        });
        group.finish();
    }
}

criterion_group!(benches, bench_parsers);

fn main() {
    report_alloc_counts();
    benches();
    Criterion::default().configure_from_args().final_summary();
}
