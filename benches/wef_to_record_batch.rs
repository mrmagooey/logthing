//! Criterion micro-benchmark: baseline cost of `WefSink::to_record_batch`.
//!
//! Run with: `cargo bench --bench wef_to_record_batch`

use chrono::Utc;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use logthing::forwarding::buffered_writer::ParquetSink;
use logthing::forwarding::parquet_s3::WefSink;
use logthing::models::{EventLevel, ParsedEvent, WindowsEvent};
use std::hint::black_box;
use std::sync::Arc;
use uuid::Uuid;

fn make_wef_event() -> Arc<WindowsEvent> {
    Arc::new(WindowsEvent {
        id: Uuid::new_v4(),
        received_at: Utc::now(),
        source_host: "workstation01.example.com".to_string(),
        subscription_id: Some("sub-001".to_string()),
        raw_xml: "<Event><System><EventID>4624</EventID></System></Event>".to_string(),
        parsed: Some(ParsedEvent {
            provider: "Microsoft-Windows-Security-Auditing".to_string(),
            event_id: 4624,
            level: EventLevel::Information,
            task: 12544,
            opcode: 0,
            keywords: 0x8020000000000000,
            time_created: Utc::now(),
            event_record_id: 123456,
            process_id: Some(544),
            thread_id: Some(892),
            channel: "Security".to_string(),
            computer: "workstation01.example.com".to_string(),
            security_user_id: Some("S-1-5-21-1234-5678-9012-1001".to_string()),
            message: Some("An account was successfully logged on.".to_string()),
            data: Some(serde_json::json!({"TargetUserName": "jdoe", "LogonType": 3})),
        }),
    })
}

fn bench_wef_record_construction(c: &mut Criterion) {
    let sink = WefSink;
    let schema = sink.schema(None);
    let event = make_wef_event();

    let mut group = c.benchmark_group("wef_record_construction");
    group.throughput(Throughput::Elements(1));
    group.bench_function("per_record_fresh_arrays", |b| {
        b.iter(|| {
            let batch = sink
                .to_record_batch(black_box(&event), black_box(&schema))
                .unwrap();
            black_box(batch);
        });
    });
    group.finish();
}

criterion_group!(benches, bench_wef_record_construction);
criterion_main!(benches);
