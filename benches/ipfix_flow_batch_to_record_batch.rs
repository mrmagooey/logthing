//! Criterion micro-benchmark: baseline cost of `IpfixSink::to_record_batch`.
//! Unlike the other `ParquetSink` adapters, IPFIX's `Record` type is
//! `Vec<FlowRecord>` (one push = one datagram's worth of flows, matching
//! `IpfixHandler::handle_flows`'s batch API) -- so `to_record_batch` already
//! amortizes builder allocation across every flow in one datagram. This
//! benchmark measures that per-datagram cost at two representative batch
//! sizes: a single-flow datagram and a 10-flow datagram.
//!
//! Run with: `cargo bench --bench ipfix_flow_batch_to_record_batch`

use chrono::Utc;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use logthing::forwarding::buffered_writer::ParquetSink;
use logthing::forwarding::ipfix_s3::IpfixSink;
use logthing::ipfix::FlowRecord;
use std::hint::black_box;
use std::net::IpAddr;

fn make_flow_record(i: usize) -> FlowRecord {
    FlowRecord {
        observation_domain_id: 1,
        template_id: 256,
        protocol_version: 10,
        exporter: "192.0.2.1".parse::<IpAddr>().unwrap(),
        export_time: Utc::now(),
        src_addr: Some(format!("10.0.{}.{}", i / 256, i % 256).parse().unwrap()),
        dst_addr: Some("10.1.0.1".parse().unwrap()),
        src_port: Some(1024 + (i as u16 % 1000)),
        dst_port: Some(443),
        ip_protocol: Some(6),
        octet_delta_count: Some(1500 + i as u64),
        packet_delta_count: Some(10 + i as u64),
        flow_start: Some(Utc::now()),
        flow_end: Some(Utc::now()),
        tcp_flags: Some(0x18),
        input_interface: Some(1),
        output_interface: Some(2),
        extra: serde_json::json!({"ie136": "0x00", "ie137": i}),
    }
}

fn bench_ipfix_batch_construction(c: &mut Criterion) {
    let sink = IpfixSink;
    let schema = sink.schema(None);

    let mut group = c.benchmark_group("ipfix_flow_batch_construction");

    for batch_size in [1usize, 10] {
        let flows: Vec<FlowRecord> = (0..batch_size).map(make_flow_record).collect();
        group.throughput(Throughput::Elements(batch_size as u64));
        group.bench_function(format!("datagram_of_{batch_size}_flows"), |b| {
            b.iter(|| {
                let batch = sink
                    .to_record_batch(black_box(&flows), black_box(&schema))
                    .unwrap();
                black_box(batch);
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_ipfix_batch_construction);
criterion_main!(benches);
