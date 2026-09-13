//! Criterion micro-benchmarks: the IPFIX *receive-path* binary decode cost that
//! runs once per ingested UDP datagram on the listener task, upstream of the
//! `IpfixSink::to_record_batch` layer that
//! `ipfix_flow_batch_to_record_batch.rs` covers. Measures
//! `ipfix::decoder::decode_datagram`, exactly as `IpfixListener`'s
//! `recv_from` arm runs it.
//!
//! IPFIX is stateful, and that is the whole point of this file. A template set
//! populates the decoder's cache; every later data set is decoded against it.
//! Real steady-state traffic is overwhelmingly cache hits, so the two cases are
//! benched separately and must not be averaged together:
//!
//! - `warm_cache_data_only`: the steady state. The template is installed once,
//!   outside the timed loop; each iteration decodes a data-only datagram.
//!   **This is the number to quote for per-datagram decode cost.**
//! - `cold_cache_template_then_data`: a fresh `IpfixDecoder` per iteration
//!   decoding a combined template+data datagram. This is what an exporter
//!   sends on its template-refresh interval (typically every few minutes),
//!   not what it sends per flow.
//!
//! Deliberately NOT measured: `recv_from`, the allowed-IPs check, and
//! `handler.handle_flows`.
//!
//! Byte fixtures are reproduced inline: `src/ipfix/decoder.rs`'s are
//! `#[cfg(test)] pub(crate)` and this bench compiles as an external crate
//! against the lib, so they are unreachable. The bytes below are copied from
//! `FIXTURE_IPFIX_TEMPLATE_THEN_DATA` (`src/ipfix/decoder.rs:213`) and split
//! into its template and data halves — if that fixture changes, this one must
//! be updated in step or the two will silently diverge.
//!
//! Run with: `cargo bench --bench ipfix_decode_recv_path`

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use logthing::ipfix::decoder::{IpfixDecoder, decode_datagram};
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};

/// Template set + data set in one datagram. Total length 44 = 16 header +
/// 16 template set + 12 data set. Template 256 declares IE 8 (sourceIPv4Address,
/// 4 bytes) and IE 12 (destinationIPv4Address, 4 bytes).
const TEMPLATE_THEN_DATA: &[u8] = &[
    0x00, 0x0A, // version = 10
    0x00, 0x2C, // total length = 44
    0x67, 0x5C, 0xB0, 0x20, // export_time
    0x00, 0x00, 0x00, 0x01, // sequence
    0x00, 0x00, 0x00, 0x00, // observation domain id = 0
    0x00, 0x02, // set id = 2 (template)
    0x00, 0x10, // set length = 16
    0x01, 0x00, // template id = 256
    0x00, 0x02, // field count = 2
    0x00, 0x08, 0x00, 0x04, // ie 8, len 4
    0x00, 0x0C, 0x00, 0x04, // ie 12, len 4
    0x01, 0x00, // set id = 256 (data)
    0x00, 0x0C, // set length = 12
    0xC0, 0xA8, 0x01, 0x01, // 192.168.1.1
    0x0A, 0x00, 0x00, 0x01, // 10.0.0.1
];

/// Data set only, against template 256 — the steady-state shape. Total length
/// 28 = 16 header + 12 data set.
const DATA_ONLY: &[u8] = &[
    0x00, 0x0A, // version = 10
    0x00, 0x1C, // total length = 28
    0x67, 0x5C, 0xB0, 0x21, // export_time
    0x00, 0x00, 0x00, 0x02, // sequence
    0x00, 0x00, 0x00, 0x00, // observation domain id = 0
    0x01, 0x00, // set id = 256 (data)
    0x00, 0x0C, // set length = 12
    0xC0, 0xA8, 0x01, 0x02, // 192.168.1.2
    0x0A, 0x00, 0x00, 0x02, // 10.0.0.2
];

fn exporter() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254))
}

fn bench_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipfix_decode_recv_path");
    group.throughput(Throughput::Elements(1));

    // Steady state: template installed once, outside the timed loop.
    let mut warm = IpfixDecoder::new();
    let installed = decode_datagram(&mut warm, TEMPLATE_THEN_DATA, exporter())
        .expect("fixture must decode");
    assert_eq!(installed.len(), 1, "template+data fixture yields one flow");

    group.bench_function("warm_cache_data_only", |b| {
        b.iter(|| {
            let flows = decode_datagram(black_box(&mut warm), black_box(DATA_ONLY), exporter());
            black_box(flows)
        })
    });

    // Template-refresh case: a fresh decoder each iteration. `IpfixDecoder::new`
    // allocates an empty HashMap, which is cheap but is inside the timed loop
    // by necessity — a cold cache is exactly what is being measured.
    group.bench_function("cold_cache_template_then_data", |b| {
        b.iter(|| {
            let mut decoder = IpfixDecoder::new();
            let flows = decode_datagram(
                black_box(&mut decoder),
                black_box(TEMPLATE_THEN_DATA),
                exporter(),
            );
            black_box(flows)
        })
    });

    group.finish();
}

criterion_group!(benches, bench_decode);
criterion_main!(benches);
