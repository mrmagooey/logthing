//! Criterion micro-benchmark: baseline cost of `SflowSink::to_record_batch`
//! for both sample kinds. Flow samples and counter samples use entirely
//! separate builder sets and separate partitions/schemas (see
//! `src/forwarding/sflow_s3.rs`'s `flow_to_record_batch`/
//! `counter_to_record_batch`), so both are benchmarked independently.
//!
//! Run with: `cargo bench --bench sflow_to_record_batch`

use chrono::Utc;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use logthing::forwarding::buffered_writer::ParquetSink;
use logthing::forwarding::sflow_s3::SflowSink;
use logthing::sflow::{SampleType, SflowRecord};
use std::hint::black_box;
use std::net::IpAddr;

fn make_flow_record() -> SflowRecord {
    SflowRecord {
        sample_type: SampleType::Flow,
        exporter: "10.0.0.1".parse::<IpAddr>().unwrap(),
        received_at: Utc::now(),
        src_addr: Some("10.1.2.3".parse().unwrap()),
        dst_addr: Some("10.4.5.6".parse().unwrap()),
        src_port: Some(51820),
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
    }
}

fn make_counter_record() -> SflowRecord {
    SflowRecord {
        sample_type: SampleType::Counter,
        exporter: "10.0.0.1".parse::<IpAddr>().unwrap(),
        received_at: Utc::now(),
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        ip_protocol: None,
        sampling_rate: None,
        input_ifindex: None,
        output_ifindex: None,
        if_index: Some(1),
        if_type: Some(6),
        if_speed: Some(1_000_000_000),
        if_direction: Some(1),
        if_in_octets: Some(123_456_789),
        if_out_octets: Some(987_654_321),
        if_in_ucast_pkts: Some(100_000),
        if_out_ucast_pkts: Some(90_000),
        if_in_errors: Some(0),
        if_out_errors: Some(0),
        extra: serde_json::json!([]),
    }
}

fn bench_sflow_record_construction(c: &mut Criterion) {
    let sink = SflowSink;
    let flow_schema = sink.schema(Some("flow"));
    let counter_schema = sink.schema(Some("counter"));
    let flow_record = make_flow_record();
    let counter_record = make_counter_record();

    let mut group = c.benchmark_group("sflow_record_construction");
    group.throughput(Throughput::Elements(1));

    group.bench_function("flow_sample", |b| {
        b.iter(|| {
            let batch = sink
                .to_record_batch(black_box(&flow_record), black_box(&flow_schema))
                .unwrap();
            black_box(batch);
        });
    });

    group.bench_function("counter_sample", |b| {
        b.iter(|| {
            let batch = sink
                .to_record_batch(black_box(&counter_record), black_box(&counter_schema))
                .unwrap();
            black_box(batch);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_sflow_record_construction);
criterion_main!(benches);
