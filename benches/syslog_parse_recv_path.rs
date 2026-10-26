//! Criterion micro-benchmarks: the syslog UDP *receive-path* message-parsing
//! cost that runs once per ingested datagram on the listener task, upstream of
//! the `ParquetSink::to_record_batch` layer the other benches in this suite
//! cover. They measure `String::from_utf8_lossy` -> `SyslogMessage::parse` ->
//! `payload::dispatch`, exactly as `SyslogListener`'s UDP receive arm runs them
//! (see `src/syslog/listener.rs`'s `result = udp_socket.recv_from(..)` arm and
//! `DefaultSyslogHandler::handle_message`).
//!
//! This is the parsing work only, not the whole per-datagram cost:
//! `handle_message` also emits an `info!` line, runs a DNS-log check, and (when
//! `parse_payloads` is set) builds a `StructuredSyslogRecord` and `try_send`s it
//! to the writer channel. None of that is measured here.
//!
//! This path had zero benchmark coverage before this file existed. The headline
//! finding is that the **RFC 3164 envelope parse dominates it**: on the default
//! (unstructured) loadgen wire shape, envelope parse is ~4.6-5.1us of a ~6.1us
//! end-to-end receive path, `payload::dispatch` adds ~1.0us, and
//! `from_utf8_lossy` is close to free. Optimization effort on this path belongs
//! in `SyslogMessage::parse`, not in the dispatch try-chain.
//!
//! **Scope caveat -- do not compare these to the 94.6us/datagram profile
//! figure.** A separate profiling run reported 81.54 CPU-sec / 862,145
//! datagrams = 94.6us/datagram, but that is *whole-process CPU across all
//! threads* (writer tasks, parquet encode, tokio, syscalls, logging),
//! measured in a different run at `info` logging. These benchmarks are
//! single-threaded, single-datagram parse costs. That profile could not
//! itself produce a percentage breakdown of the 94.6us/datagram figure;
//! subtracting or ratioing these numbers against it would repeat that same
//! error. What can be said: the recv-path parse cost measured here (~6.1us)
//! is the same order as the writer-side `syslog_message_to_record_batch`
//! (~7.07us/record), so neither layer's parse/encode work is where the bulk of
//! that 94.6us goes.
//!
//! Figures above are medians across two runs on one machine; treat them as
//! magnitudes, and re-run rather than trusting them as committed constants.
//!
//! Wire payloads are reproduced here (not imported from `tools/loadgen`, which
//! is a separate, non-default workspace member) to match what `loadgen
//! syslog-udp`'s `build_message(n, structured)` sends. The one deviation is the
//! tag's pid: loadgen uses `std::process::id()`, this file hardcodes 4242, so
//! real traffic carries a pid of a few more digits. The RFC 3164 tag parser captures it
//! as a run of digits, so the digit count does not measurably affect parse cost.
//! - `structured = false` (the default): a plain RFC 3164 line whose message
//!   body matches NO payload sub-parser, so all seven are attempted and all
//!   reject -- the most attempts for `dispatch`, though not the most expensive
//!   case (see `bench_payload_dispatch`). This is the shape the profiled load
//!   referenced above actually used.
//! - `structured = true`: the RFC 3164 message body is a CEF payload, which
//!   matches `dispatch`'s first sub-parser via a fast prefix check.
//!
//! Allocation counts: before criterion runs, `main` prints `ALLOC <case> allocs_per_record=..
//! bytes_per_record=..` lines measured by a counting `#[global_allocator]` that counts only while a flag is
//! set (one relaxed load per allocation otherwise). Realloc counts as one allocation of the new size.
//! Cases added for the RFC 3164 hand-rolled parser work: no-PRI 3164, RFC 5424 with structured data, a
//! `<PRI>`-only fallback line, and a garbage line that parses to `None`.
//! Run with: `cargo bench --bench syslog_parse_recv_path`

use criterion::{Criterion, Throughput, criterion_group};
use logthing::syslog::{SyslogMessage, payload};
use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Fixed RFC 3164 timestamp matching loadgen's `"Mon D HH:MM:SS"` shape
/// (day not zero-padded); the parser accepts either.
const TIMESTAMP: &str = "Jan 15 10:30:45";
const HOSTNAME: &str = "loadgen-host";
/// facility=16 (local0) * 8 + severity=6 (informational), per loadgen.
const PRI: u16 = 134;

/// Allocator wrapper that counts allocations and requested bytes only while `COUNTING` is set.
struct CountingAlloc;

static COUNTING: AtomicBool = AtomicBool::new(false);
static ALLOCS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);

#[inline]
fn count(bytes: usize) {
    if COUNTING.load(Ordering::Relaxed) {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
    }
}

// SAFETY: every method forwards to `System` unchanged; counting only touches atomics.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count(new_size);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

/// Build the default (`--structured` off) loadgen wire message: a plain
/// RFC 3164 line whose body matches no `payload::dispatch` sub-parser.
fn build_raw_message(n: u64) -> String {
    format!("<{PRI}>{TIMESTAMP} {HOSTNAME} loadgen[4242]: synthetic load-test message #{n}")
}

/// Same shape without the `<PRI>` prefix (some devices omit it).
fn build_nopri_message(n: u64) -> String {
    format!("{TIMESTAMP} {HOSTNAME} loadgen[4242]: synthetic load-test message #{n}")
}

/// A real RFC 5424 line with structured data.
fn build_rfc5424_message(n: u64) -> String {
    format!(
        "<{PRI}>1 2024-01-15T10:30:45.000Z {HOSTNAME} loadgen 4242 ID47 \
         [meta@1 seq=\"{n}\" src=\"10.0.0.1\"] synthetic load-test message #{n}"
    )
}

/// Valid `<PRI>` but no parseable header: exercises the `<PRI>`-only fallback.
fn build_fallback_message(n: u64) -> String {
    format!("<{PRI}>unparsable free text without a header #{n}")
}

/// Not syslog at all: every attempt fails and `parse` returns `None`.
fn build_garbage_message(n: u64) -> String {
    format!("this is not a syslog line at all #{n}")
}

/// Build the `--structured` loadgen wire message: the RFC 3164 body is a CEF
/// payload, which `payload::dispatch` matches on its first sub-parser.
fn build_cef_message(n: u64) -> String {
    format!(
        "<{PRI}>{TIMESTAMP} {HOSTNAME} loadgen: CEF:0|Loadgen|SyntheticFirewall|1.0|100|\
         Synthetic Blocked Connection|5|src=10.0.{}.{} dst=10.1.0.1 spt={} dpt=443 cnt={n}",
        (n / 256) % 256,
        n % 256,
        1024 + (n % 60_000),
    )
}

/// Envelope-parse cases shared by criterion and the allocation counter.
fn envelope_cases() -> Vec<(&'static str, String)> {
    vec![
        ("rfc3164", build_raw_message(1)),
        ("rfc3164_nopri", build_nopri_message(1)),
        ("rfc3164_cef_after_host", build_cef_message(1)),
        ("rfc5424_sd", build_rfc5424_message(1)),
        ("fallback_pri_only", build_fallback_message(1)),
        ("garbage_none", build_garbage_message(1)),
    ]
}

/// Benchmark: `SyslogMessage::parse` on each envelope shape.
fn bench_syslog_envelope_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("syslog_envelope_parse");
    group.throughput(Throughput::Elements(1));
    for (name, line) in envelope_cases() {
        group.bench_function(name, |b| {
            b.iter(|| {
                let msg = SyslogMessage::parse(black_box(&line));
                black_box(msg);
            });
        });
    }
    group.finish();
}

/// Benchmark: `payload::dispatch`'s sub-parser try-chain, miss and hit reported separately.
/// They differ by roughly 3x, so they must not be averaged together, and the direction is
/// counterintuitive: the *miss* is the cheap case and the *hit* the expensive one. Attempt count
/// is not what costs; committing to a payload (parsing it, allocating the struct) is.
fn bench_payload_dispatch(c: &mut Criterion) {
    let all_miss = SyslogMessage::parse(&build_raw_message(1)).expect("must parse");
    let cef_hit = SyslogMessage::parse(&build_cef_message(1)).expect("must parse");

    let mut group = c.benchmark_group("payload_dispatch");
    group.throughput(Throughput::Elements(1));
    // No sub-parser matches, so all seven are attempted and all fail. Despite being the most
    // attempts this is the cheapest case: every parser rejects on a fast prefix check and nothing
    // is allocated. This is the shape the default (unstructured) loadgen mode sends.
    group.bench_function("all_miss_seven_parser_attempts", |b| {
        b.iter(|| {
            let payload = payload::dispatch(black_box(&all_miss));
            black_box(payload);
        });
    });
    // CEF matches on the very first sub-parser, so only one attempt is made, yet this is far more
    // expensive than seven misses because a match parses the payload and allocates the result.
    // "Early hit" describes where it matches in the chain, not that it is faster.
    group.bench_function("cef_early_hit", |b| {
        b.iter(|| {
            let payload = payload::dispatch(black_box(&cef_hit));
            black_box(payload);
        });
    });
    group.finish();
}

/// One datagram through `from_utf8_lossy` -> `parse` -> `dispatch`, as the UDP receive arm runs it.
fn recv_path(bytes: &[u8]) {
    let text = String::from_utf8_lossy(black_box(bytes));
    if let Some(msg) = SyslogMessage::parse(&text) {
        let payload = payload::dispatch(&msg);
        black_box(payload);
    }
}

/// Benchmark: the full per-datagram receive-path pipeline on the all-miss wire shape, exactly as
/// `SyslogListener`'s UDP receive arm runs it. `from_utf8_lossy` costs almost nothing, so the two
/// component benchmarks should roughly account for this one (a consistency check on all three).
/// See the module docs for why this figure must not be compared against the whole-process
/// per-datagram profile number.
fn bench_combined_recv_path(c: &mut Criterion) {
    let bytes = build_raw_message(1).into_bytes();

    let mut group = c.benchmark_group("combined_recv_path");
    group.throughput(Throughput::Elements(1));
    group.bench_function("utf8_lossy_parse_dispatch", |b| {
        b.iter(|| recv_path(&bytes))
    });
    group.finish();
}

/// Run `f` once to warm lazies and pools, then `iters` times with counting on; return
/// `(allocs, bytes)` per call.
fn measure(mut f: impl FnMut(), iters: u64) -> (f64, f64) {
    f();
    ALLOCS.store(0, Ordering::Relaxed);
    BYTES.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    for _ in 0..iters {
        f();
    }
    COUNTING.store(false, Ordering::Relaxed);
    let n = iters as f64;
    (
        ALLOCS.load(Ordering::Relaxed) as f64 / n,
        BYTES.load(Ordering::Relaxed) as f64 / n,
    )
}

/// Print one `ALLOC` line per case (deterministic; the primary evidence for this fix).
fn print_alloc_counts() {
    const ITERS: u64 = 1000;
    for (name, line) in envelope_cases() {
        let (allocs, bytes) = measure(
            || {
                black_box(SyslogMessage::parse(black_box(&line)));
            },
            ITERS,
        );
        println!("ALLOC envelope/{name} allocs_per_record={allocs:.2} bytes_per_record={bytes:.1}");
    }
    let bytes = build_raw_message(1).into_bytes();
    let (allocs, b) = measure(|| recv_path(&bytes), ITERS);
    println!(
        "ALLOC combined/utf8_lossy_parse_dispatch allocs_per_record={allocs:.2} bytes_per_record={b:.1}"
    );
}

criterion_group!(
    benches,
    bench_syslog_envelope_parse,
    bench_payload_dispatch,
    bench_combined_recv_path
);

fn main() {
    // ALLOC lines only for a real run: not for `--list`, nor `--test` / `cargo test --benches`.
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--bench") && !args.iter().any(|a| a == "--list" || a == "--test") {
        print_alloc_counts();
    }
    benches();
    Criterion::default().configure_from_args().final_summary();
}
