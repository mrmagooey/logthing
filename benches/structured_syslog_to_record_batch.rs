//! Criterion micro-benchmark: baseline cost of
//! `StructuredSyslogSink::to_record_batch` for two structurally different
//! payload types recognised by `syslog::payload::dispatch`: CEF (pipe-
//! delimited header + `key=value` extensions) and Linux auditd (pure
//! `key=value` body, no header delimiter). This is the only `ParquetSink`
//! adapter in the repo that previously had zero encode coverage -- every
//! other sink has a `*_to_record_batch` bench; `syslog_message_to_record_batch.rs`
//! is the plain (unstructured) syslog baseline this is meant to be compared
//! against.
//!
//! All nine `ParquetSink` schemas (including this one) gained a non-null
//! `partition_time` column in v0.16.0 (2026-09-06), so figures measured
//! here are NOT comparable to anything recorded before that date.
//!
//! Run with: `cargo bench --bench structured_syslog_to_record_batch`

use chrono::Utc;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use logthing::forwarding::buffered_writer::ParquetSink;
use logthing::forwarding::structured_syslog_s3::StructuredSyslogSink;
use logthing::syslog::payload::{StructuredSyslogRecord, dispatch};
use logthing::syslog::{SyslogMessage, SyslogProtocol};
use std::hint::black_box;

const CEF_MESSAGE: &str = "CEF:0|ArcSight|ArcSight Management Center|2.0|base:system:remotelogin:success|\
     Remote Login Success|3|src=10.0.0.1 dst=10.0.0.2 spt=51234 dpt=22";

const AUDITD_MESSAGE: &str = "type=SYSCALL msg=audit(1609459200.000:1234): arch=c000003e syscall=59 \
     success=yes exit=0 a0=7f1234 a1=0 a2=0 a3=0 items=3 ppid=1000 pid=2000 \
     auid=1001 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 \
     tty=pts0 ses=42 comm=\"bash\" exe=\"/bin/bash\" key=\"exec\"";

fn make_message(text: &str) -> SyslogMessage {
    SyslogMessage {
        priority: 86,
        severity: 6,
        facility: 10,
        timestamp: Some(Utc::now()),
        hostname: Some("fw01.example.com".to_string()),
        app_name: Some("ArcSight".to_string()),
        proc_id: None,
        msg_id: None,
        message: text.to_string(),
        structured_data: None,
        protocol: SyslogProtocol::Rfc3164,
    }
}

fn make_record(text: &str, expected_payload_type: &str) -> StructuredSyslogRecord {
    let msg = make_message(text);
    let payload = dispatch(&msg);
    let record = StructuredSyslogRecord::from_syslog_and_payload(&msg, &payload)
        .expect("fixture must dispatch to a recognised payload type");
    assert_eq!(
        record.payload_type, expected_payload_type,
        "fixture dispatched to an unexpected payload type"
    );
    record
}

fn bench_structured_syslog_record_construction(c: &mut Criterion) {
    let sink = StructuredSyslogSink;
    let schema = sink.schema(None);
    let cef_record = make_record(CEF_MESSAGE, "cef");
    let auditd_record = make_record(AUDITD_MESSAGE, "auditd");

    let batch = sink.to_record_batch(&cef_record, &schema).unwrap();
    assert_eq!(batch.num_rows(), 1, "cef fixture must encode to one row");
    let batch = sink.to_record_batch(&auditd_record, &schema).unwrap();
    assert_eq!(batch.num_rows(), 1, "auditd fixture must encode to one row");

    let mut group = c.benchmark_group("structured_syslog_record_construction");
    group.throughput(Throughput::Elements(1));

    group.bench_function("cef", |b| {
        b.iter(|| {
            let batch = sink
                .to_record_batch(black_box(&cef_record), black_box(&schema))
                .unwrap();
            black_box(batch);
        });
    });

    group.bench_function("auditd", |b| {
        b.iter(|| {
            let batch = sink
                .to_record_batch(black_box(&auditd_record), black_box(&schema))
                .unwrap();
            black_box(batch);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_structured_syslog_record_construction);
criterion_main!(benches);
