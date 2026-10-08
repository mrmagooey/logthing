//! Criterion micro-benchmark: baseline cost of `GenericSink::to_record_batch`
//! -- the HEC writer path. OTLP does NOT share it: OTLP has its own `OtlpSink` with its own
//! accumulator (see `benches/otlp_record_batch.rs`).
//!
//! Run with: `cargo bench --bench generic_hec_to_record_batch`

use chrono::Utc;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use logthing::forwarding::buffered_writer::ParquetSink;
use logthing::forwarding::generic_s3::GenericSink;
use logthing::ingest::GenericRecord;
use std::hint::black_box;

fn make_hec_record() -> GenericRecord {
    GenericRecord {
        sourcetype: "access_log".to_string(),
        host: Some("web-01".to_string()),
        time: Some(Utc::now()),
        fields: serde_json::json!({
            "method": "GET",
            "path": "/api/v1/widgets",
            "status": 200,
            "bytes": 1834,
            "user_agent": "curl/8.4.0"
        }),
        received_at: Utc::now(),
        ..Default::default()
    }
}

fn bench_generic_record_construction(c: &mut Criterion) {
    let sink = GenericSink;
    let schema = sink.schema(None);
    let record = make_hec_record();

    let mut group = c.benchmark_group("generic_hec_record_construction");
    group.throughput(Throughput::Elements(1));
    group.bench_function("per_record_fresh_arrays", |b| {
        b.iter(|| {
            let batch = sink
                .to_record_batch(black_box(&record), black_box(&schema))
                .unwrap();
            black_box(batch);
        });
    });
    group.finish();
}

criterion_group!(benches, bench_generic_record_construction);
criterion_main!(benches);
