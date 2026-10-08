//! Criterion micro-benchmark: OTLP record -> Arrow cost for 10k records.
//!
//! - `legacy_one_row_batch_per_record_plus_concat`: the pre-fix writer path (21 one-row
//!   arrays per record built with `Array::from(vec![..])`, then `concat_batches`), kept here
//!   as a frozen baseline. This is what capped a single OTLP writer near 13k rec/s.
//! - `to_record_batch_per_record_plus_concat`: today's `OtlpSink::to_record_batch` (one-row
//!   wrapper over the accumulator) per record, then `concat_batches`.
//! - `accumulator_append_then_finish`: `OtlpSink::new_batch` + `try_append` x N + one
//!   `finish`, which is what the writer does now.
//!
//! Run with: `cargo bench --bench otlp_record_batch`

use arrow_array::{
    ArrayRef, Int32Array, RecordBatch, StringArray, TimestampMicrosecondArray, UInt32Array,
};
use chrono::{DateTime, TimeZone, Utc};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use logthing::forwarding::buffered_writer::ParquetSink;
use logthing::forwarding::otlp_s3::{OtlpRecord, OtlpSink, otlp_schema};
use std::hint::black_box;
use std::sync::Arc;

const N: usize = 10_000;

fn make_record(i: usize) -> OtlpRecord {
    let now = Utc.with_ymd_and_hms(2026, 10, 6, 12, 0, 1).unwrap();
    OtlpRecord {
        event_uuid: Some(format!("0199c4e0-7d2a-7b3c-9a10-{i:012}")),
        time: Some(now),
        observed_time: None,
        received_at: now,
        severity_number: Some(9),
        severity_text: Some("INFO".to_string()),
        body: Some(format!("GET /api/v1/widgets/{i} 200 1834 bytes")),
        service_name: Some("checkout".to_string()),
        service_namespace: Some("shop".to_string()),
        service_instance_id: Some(format!("i-{}", i % 16)),
        host_name: Some("web-01".to_string()),
        peer_addr: Some("10.0.0.7".to_string()),
        trace_id: Some("0af7651916cd43dd8448eb211c80319c".to_string()),
        span_id: Some("b7ad6b7169203331".to_string()),
        flags: Some(1),
        event_name: None,
        scope_name: Some("lib".to_string()),
        scope_version: Some("1.2".to_string()),
        resource_attributes: serde_json::json!({
            "service.name": "checkout", "host.name": "web-01", "k8s.pod.name": "p1"
        }),
        attributes: serde_json::json!({"http.route": "/x", "http.status_code": 200}),
    }
}

/// Frozen copy of the pre-fix `OtlpSink::to_record_batch`.
fn legacy_batch(r: &OtlpRecord) -> RecordBatch {
    let ts = |v: Option<DateTime<Utc>>| -> ArrayRef {
        Arc::new(
            TimestampMicrosecondArray::from(vec![v.map(|d| d.timestamp_micros())])
                .with_timezone("UTC"),
        )
    };
    let utf8 = |v: Option<&str>| -> ArrayRef { Arc::new(StringArray::from(vec![v])) };
    let resource_attributes = serde_json::to_string(&r.resource_attributes).unwrap();
    let attributes = serde_json::to_string(&r.attributes).unwrap();
    let columns: Vec<ArrayRef> = vec![
        utf8(r.event_uuid.as_deref()),
        ts(r.time),
        ts(r.observed_time),
        ts(Some(r.received_at)),
        Arc::new(Int32Array::from(vec![r.severity_number])),
        utf8(r.severity_text.as_deref()),
        utf8(r.body.as_deref()),
        utf8(r.service_name.as_deref()),
        utf8(r.service_namespace.as_deref()),
        utf8(r.service_instance_id.as_deref()),
        utf8(r.host_name.as_deref()),
        utf8(r.peer_addr.as_deref()),
        utf8(r.trace_id.as_deref()),
        utf8(r.span_id.as_deref()),
        Arc::new(UInt32Array::from(vec![r.flags])),
        utf8(r.event_name.as_deref()),
        utf8(r.scope_name.as_deref()),
        utf8(r.scope_version.as_deref()),
        utf8(Some(&resource_attributes)),
        utf8(Some(&attributes)),
        ts(Some(r.time.unwrap_or(r.received_at))),
    ];
    RecordBatch::try_new(otlp_schema(), columns).unwrap()
}

fn bench_otlp_record_batch(c: &mut Criterion) {
    let records: Vec<OtlpRecord> = (0..N).map(make_record).collect();
    let schema = otlp_schema();
    let mut group = c.benchmark_group("otlp_record_batch_10k");
    group.throughput(Throughput::Elements(N as u64));
    group.sample_size(20);

    group.bench_function("legacy_one_row_batch_per_record_plus_concat", |b| {
        b.iter(|| {
            let batches: Vec<RecordBatch> = records.iter().map(legacy_batch).collect();
            black_box(arrow::compute::concat_batches(&schema, &batches).unwrap())
        })
    });
    group.bench_function("to_record_batch_per_record_plus_concat", |b| {
        b.iter(|| {
            let batches: Vec<RecordBatch> = records
                .iter()
                .map(|r| OtlpSink.to_record_batch(r, &schema).unwrap())
                .collect();
            black_box(arrow::compute::concat_batches(&schema, &batches).unwrap())
        })
    });
    group.bench_function("accumulator_append_then_finish", |b| {
        let now = Utc::now();
        b.iter(|| {
            let mut acc = OtlpSink.new_batch(&schema).unwrap();
            for r in &records {
                acc.try_append(r, now).unwrap();
            }
            black_box(acc.finish().unwrap())
        })
    });
    group.finish();
}

criterion_group!(benches, bench_otlp_record_batch);
criterion_main!(benches);
