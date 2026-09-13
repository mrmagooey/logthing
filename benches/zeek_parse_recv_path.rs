//! Criterion micro-benchmarks: the Zeek TCP *receive-path* parse cost that runs
//! once per ingested NDJSON line on the listener task, upstream of the
//! `ZeekSink::to_record_batch` layer that `zeek_conn_batch_amortization.rs` and
//! `zeek_schema_encode.rs` cover. Measures `std::str::from_utf8` ->
//! `zeek::parse_line`, exactly as `ZeekListener::handle_tcp_connection` runs
//! them.
//!
//! Deliberately NOT measured: the bounded `read_until` and its oversize guard,
//! the per-record metric increments, and `handler.handle_record` (which for a
//! real deployment is a channel `try_send` into the writer task). This is parse
//! only.
//!
//! Four fixtures, chosen because they are the highest-volume Zeek streams and
//! they differ in field count and type mix, which is what drives serde_json
//! cost: `conn` (numeric-heavy), `dns` (string-heavy), `http` (long string
//! values), plus a rotated `_path` so `normalize_log_path`'s `split_once('.')`
//! arm runs rather than its passthrough arm — shippers emit that shape after
//! log rotation, so it is a real steady-state case, not a synthetic one.
//! Fixtures are written inline rather than imported: `src/zeek/listener.rs`'s
//! are `#[cfg(test)]` and this bench compiles as an external crate.
//!
//! Do not compare these numbers to the 94.6us/datagram figure in
//! `docs/performance/2026-07-25-syslog-udp-cpu-profile.md` — that is
//! whole-process CPU across all threads, and ratioing single-threaded parse
//! costs against it is the exact error that doc was written to correct.
//!
//! Run with: `cargo bench --bench zeek_parse_recv_path`

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use logthing::zeek::parse_line;
use std::hint::black_box;

const CONN_LINE: &str = r#"{"_path":"conn","ts":1700000000.0,"uid":"CHhAvVGS1DHFjwGM9","id.orig_h":"10.0.0.1","id.orig_p":12345,"id.resp_h":"10.0.0.2","id.resp_p":443,"proto":"tcp","conn_state":"SF","orig_bytes":1024,"resp_bytes":8192,"duration":0.253}"#;

const DNS_LINE: &str = r#"{"_path":"dns","ts":1700000100.0,"uid":"CsRx2w1PZTBaJ9Wvd","id.orig_h":"192.168.1.100","id.orig_p":53322,"id.resp_h":"8.8.8.8","id.resp_p":53,"query":"api.example.com","qtype_name":"A","rcode_name":"NOERROR"}"#;

const HTTP_LINE: &str = r#"{"_path":"http","ts":1700000200.0,"uid":"CqL8Kj3nBvW2mXr4a","id.orig_h":"192.168.1.100","id.orig_p":51234,"id.resp_h":"93.184.216.34","id.resp_p":80,"method":"GET","host":"www.example.com","uri":"/path/to/a/reasonably/long/resource?with=query&params=here","user_agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36","status_code":200}"#;

const ROTATED_LINE: &str = r#"{"_path":"conn.2026-08-14-16-08-44","ts":1700000000.0,"uid":"CHhAvVGS1DHFjwGM9","id.orig_h":"10.0.0.1","id.orig_p":12345,"id.resp_h":"10.0.0.2","id.resp_p":443,"proto":"tcp","conn_state":"SF","orig_bytes":1024,"resp_bytes":8192}"#;

fn bench_parse_line(c: &mut Criterion) {
    let mut group = c.benchmark_group("zeek_parse_recv_path");
    group.throughput(Throughput::Elements(1));

    for (name, line) in [
        ("conn", CONN_LINE),
        ("dns", DNS_LINE),
        ("http", HTTP_LINE),
        ("conn_rotated_path", ROTATED_LINE),
    ] {
        let at = chrono::Utc::now();
        // Fail loudly at setup rather than silently timing an error return: a
        // typo in the JSON literal above would otherwise look like a very fast
        // parse. Same guard the ipfix/sflow benches use.
        assert!(
            parse_line(line, at).is_ok(),
            "fixture {name} must parse; check the JSON literal"
        );
        group.bench_function(name, |b| {
            b.iter(|| black_box(parse_line(black_box(line), black_box(at))))
        });
    }
    group.finish();
}

/// The full receive-path chain including the UTF-8 validation the listener runs
/// on the raw buffer before it ever sees a `&str`.
fn bench_utf8_plus_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("zeek_recv_path_end_to_end");
    group.throughput(Throughput::Elements(1));

    let bytes = CONN_LINE.as_bytes();
    let at = chrono::Utc::now();
    group.bench_function("conn_from_utf8_then_parse", |b| {
        b.iter(|| {
            let s = std::str::from_utf8(black_box(bytes)).unwrap();
            black_box(parse_line(s, black_box(at)))
        })
    });
    group.finish();
}

criterion_group!(benches, bench_parse_line, bench_utf8_plus_parse);
criterion_main!(benches);
