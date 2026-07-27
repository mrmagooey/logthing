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
//! figure.** `docs/performance/2026-07-25-syslog-udp-cpu-profile.md` reports
//! 81.54 CPU-sec / 862,145 datagrams = 94.6us/datagram, but that is
//! *whole-process CPU across all threads* (writer tasks, parquet encode, tokio,
//! syscalls, logging), measured in a different run at `info` logging. These
//! benchmarks are single-threaded, single-datagram parse costs. The profile doc
//! states outright that it "does not, and cannot, produce a percentage
//! breakdown of the 94.6us/datagram figure" (§4.3); subtracting or ratioing
//! these numbers against it is exactly the error that doc was written to
//! correct. What can be said: the recv-path parse cost measured here (~6.1us)
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
//! real traffic carries a pid of a few more digits. `RFC3164_TAG_RE` captures it
//! with `\d+`, so the digit count does not measurably affect parse cost.
//! - `structured = false` (the default): a plain RFC 3164 line whose message
//!   body matches NO payload sub-parser, so all seven are attempted and all
//!   reject -- the most attempts for `dispatch`, though not the most expensive
//!   case (see `bench_payload_dispatch`). This is the shape the profiled load
//!   referenced above actually used.
//! - `structured = true`: the RFC 3164 message body is a CEF payload, which
//!   matches `dispatch`'s first sub-parser via a fast prefix check.
//!
//! Run with: `cargo bench --bench syslog_parse_recv_path`

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use logthing::syslog::{SyslogMessage, payload};
use std::hint::black_box;

/// Fixed RFC 3164 timestamp matching loadgen's `"Mon D HH:MM:SS"` shape
/// (day not zero-padded); `SyslogMessage`'s `RFC3164_TS_RE` accepts either.
const TIMESTAMP: &str = "Jan 15 10:30:45";
const HOSTNAME: &str = "loadgen-host";
/// facility=16 (local0) * 8 + severity=6 (informational), per loadgen.
const PRI: u16 = 134;

/// Build the default (`--structured` off) loadgen wire message: a plain
/// RFC 3164 line whose body matches no `payload::dispatch` sub-parser.
fn build_raw_message(n: u64) -> String {
    format!("<{PRI}>{TIMESTAMP} {HOSTNAME} loadgen[4242]: synthetic load-test message #{n}")
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

/// Benchmark: `SyslogMessage::parse` on the RFC 3164 envelope alone (the
/// wire format the load generator's default mode sends).
fn bench_syslog_envelope_parse(c: &mut Criterion) {
    let raw = build_raw_message(1);

    let mut group = c.benchmark_group("syslog_envelope_parse");
    group.throughput(Throughput::Elements(1));
    group.bench_function("rfc3164", |b| {
        b.iter(|| {
            let msg = SyslogMessage::parse(black_box(&raw));
            black_box(msg);
        });
    });
    group.finish();
}

/// Benchmark: `payload::dispatch`'s sub-parser try-chain, in both cases this
/// task cares about. These differ by ~3x, so they must be reported separately
/// rather than averaged together -- and the direction is counterintuitive: the
/// *miss* is the cheap case (~1.0us) and the *hit* is the expensive one
/// (~2.8-3.0us). Attempt count is not what costs; committing to a payload is.
fn bench_payload_dispatch(c: &mut Criterion) {
    let all_miss = SyslogMessage::parse(&build_raw_message(1)).expect("must parse");
    let cef_hit = SyslogMessage::parse(&build_cef_message(1)).expect("must parse");

    let mut group = c.benchmark_group("payload_dispatch");
    group.throughput(Throughput::Elements(1));

    // No sub-parser matches, so all seven are attempted and all fail. Despite
    // being the most attempts, this is the *cheapest* case (~1.0us): every
    // parser rejects on a fast prefix check and nothing is allocated. This is
    // the shape the default (unstructured) loadgen mode sends.
    group.bench_function("all_miss_seven_parser_attempts", |b| {
        b.iter(|| {
            let payload = payload::dispatch(black_box(&all_miss));
            black_box(payload);
        });
    });

    // CEF matches on the very first sub-parser, so only one attempt is made --
    // yet this is ~3x more expensive than seven misses, because a match means
    // actually parsing the payload and allocating the resulting struct. "Early
    // hit" describes where it matches in the chain, not that it is faster.
    group.bench_function("cef_early_hit", |b| {
        b.iter(|| {
            let payload = payload::dispatch(black_box(&cef_hit));
            black_box(payload);
        });
    });

    group.finish();
}

/// Benchmark: the full per-datagram receive-path pipeline --
/// `String::from_utf8_lossy` -> `SyslogMessage::parse` -> `payload::dispatch`
/// -- exactly as `SyslogListener`'s UDP receive arm runs it. Uses the all-miss
/// (default, unstructured) wire shape.
///
/// Measures ~6.1us, of which the envelope parse alone is ~4.6-5.1us and
/// dispatch ~1.0us -- so `from_utf8_lossy` costs almost nothing and the two
/// component benchmarks roughly account for this one, which is a useful
/// consistency check on all three. See the module docs for why this figure must
/// not be compared against the 94.6us/datagram whole-process profile number.
fn bench_combined_recv_path(c: &mut Criterion) {
    let bytes = build_raw_message(1).into_bytes();

    let mut group = c.benchmark_group("combined_recv_path");
    group.throughput(Throughput::Elements(1));
    group.bench_function("utf8_lossy_parse_dispatch", |b| {
        b.iter(|| {
            let text = String::from_utf8_lossy(black_box(&bytes));
            if let Some(msg) = SyslogMessage::parse(&text) {
                let payload = payload::dispatch(&msg);
                black_box(payload);
            }
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_syslog_envelope_parse,
    bench_payload_dispatch,
    bench_combined_recv_path
);
criterion_main!(benches);
