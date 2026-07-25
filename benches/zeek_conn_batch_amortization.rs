//! Criterion micro-benchmark comparing Zeek's "conn" record→RecordBatch
//! construction cost before vs. after amortized builder reuse (see
//! `docs/superpowers/specs/2026-07-24-record-batch-amortization-design.md`).
//!
//! Both code paths are exercised through already-public API:
//! - "Before" (fresh Arrow builders allocated and finished on every single
//!   record): `ZeekSink::to_record_batch`, unchanged by the amortization
//!   work -- every other Zeek log type and every other `ParquetSink`
//!   adapter still goes through exactly this path today.
//! - "After" (one persistent `ConnAccumulator`, reused across N records via
//!   `try_append`, finished once): `ZeekSink::new_batch` +
//!   `RecordBatchAccumulator`.
//!
//! Run with: `cargo bench --bench zeek_conn_batch_amortization`

use chrono::Utc;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use logthing::forwarding::buffered_writer::ParquetSink;
use logthing::forwarding::zeek_s3::ZeekSink;
use logthing::zeek::ZeekRecord;
use logthing::zeek::schema::conn_schema;
use std::hint::black_box;

fn make_conn_record(i: usize) -> ZeekRecord {
    ZeekRecord {
        log_path: "conn".to_string(),
        fields: serde_json::json!({
            "ts": 1700000000.0 + i as f64,
            "uid": format!("C{i}"),
            "id.orig_h": "10.0.0.1",
            "id.orig_p": 12345,
            "id.resp_h": "10.0.0.2",
            "id.resp_p": 443,
            "proto": "tcp",
            "service": "http",
            "duration": 1.5,
            "orig_bytes": 100,
            "resp_bytes": 200,
            "conn_state": "SF",
            "history": "ShADadFf",
            "orig_pkts": 3,
            "resp_pkts": 4,
        }),
        received_at: Utc::now(),
    }
}

fn bench_conn_record_construction(c: &mut Criterion) {
    let schema = conn_schema();
    let sink = ZeekSink;
    let mut group = c.benchmark_group("zeek_conn_record_construction");

    // "Before": one fresh builder set allocated and finished per record.
    group.throughput(Throughput::Elements(1));
    let single_record = make_conn_record(0);
    group.bench_function("per_record_fresh_builders", |b| {
        b.iter(|| {
            let batch = sink
                .to_record_batch(black_box(&single_record), black_box(&schema))
                .unwrap();
            black_box(batch);
        });
    });

    // "After": one persistent accumulator, N records appended, one finish.
    // Multiple batch sizes show whether the amortization benefit changes
    // with batch size (it should plateau once builder-allocation cost is
    // fully amortized away, leaving only the irreducible per-record
    // field-extraction/JSON-access cost).
    for batch_size in [10usize, 100, 1000] {
        let records: Vec<ZeekRecord> = (0..batch_size).map(make_conn_record).collect();
        group.throughput(Throughput::Elements(batch_size as u64));
        group.bench_function(format!("amortized_batch_of_{batch_size}"), |b| {
            b.iter(|| {
                let mut acc = sink
                    .new_batch(black_box(&schema))
                    .expect("ZeekSink must opt into the amortized path for the conn schema");
                for r in &records {
                    acc.try_append(black_box(r)).unwrap();
                }
                let batch = acc.finish().unwrap();
                black_box(batch);
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_conn_record_construction);
criterion_main!(benches);
