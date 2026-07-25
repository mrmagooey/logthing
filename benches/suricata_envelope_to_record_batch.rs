//! Criterion micro-benchmark: baseline cost of `SuricataSink::to_record_batch`
//! (`map_envelope`) -- one call per ingested Suricata EVE JSON record. This is
//! the "before" measurement for any future amortized-builder work on the
//! Suricata adapter (see
//! `docs/superpowers/specs/2026-07-24-record-batch-amortization-design.md`
//! for the pattern already applied to Zeek's "conn" mapper), and a
//! regression-tracking baseline in its own right.
//!
//! Run with: `cargo bench --bench suricata_envelope_to_record_batch`

use chrono::Utc;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use logthing::forwarding::buffered_writer::ParquetSink;
use logthing::forwarding::suricata_s3::SuricataSink;
use logthing::suricata::SuricataRecord;
use logthing::suricata::schema::envelope_schema;
use std::hint::black_box;

fn make_alert_record() -> SuricataRecord {
    SuricataRecord {
        event_type: "alert".to_string(),
        fields: serde_json::json!({
            "event_type": "alert",
            "src_ip": "192.168.1.100",
            "dest_ip": "1.2.3.4",
            "src_port": 51820,
            "dest_port": 443,
            "proto": "TCP",
            "alert": {
                "signature": "ET POLICY Suspicious User-Agent",
                "category": "Attempted Information Leak",
                "severity": 2
            }
        }),
        received_at: Utc::now(),
    }
}

fn bench_suricata_envelope_construction(c: &mut Criterion) {
    let schema = envelope_schema();
    let sink = SuricataSink;
    let record = make_alert_record();

    let mut group = c.benchmark_group("suricata_envelope_record_construction");
    group.throughput(Throughput::Elements(1));
    group.bench_function("per_record_fresh_builders", |b| {
        b.iter(|| {
            let batch = sink
                .to_record_batch(black_box(&record), black_box(&schema))
                .unwrap();
            black_box(batch);
        });
    });
    group.finish();
}

criterion_group!(benches, bench_suricata_envelope_construction);
criterion_main!(benches);
