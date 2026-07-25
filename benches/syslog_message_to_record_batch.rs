//! Criterion micro-benchmark: baseline cost of `SyslogSink::to_record_batch`
//! (`syslog_message_to_batch`) -- one call per ingested syslog message.
//!
//! Run with: `cargo bench --bench syslog_message_to_record_batch`

use chrono::Utc;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use logthing::forwarding::buffered_writer::ParquetSink;
use logthing::forwarding::syslog_s3::SyslogSink;
use logthing::syslog::{SyslogMessage, SyslogProtocol};
use std::hint::black_box;

fn make_rfc5424_message() -> SyslogMessage {
    SyslogMessage {
        priority: 34,
        severity: 2,
        facility: 4,
        timestamp: Some(Utc::now()),
        hostname: Some("mymachine.example.com".to_string()),
        app_name: Some("su".to_string()),
        proc_id: Some("2001".to_string()),
        msg_id: Some("ID47".to_string()),
        message: "'su root' failed for lonvick on /dev/pts/8".to_string(),
        structured_data: None,
        protocol: SyslogProtocol::Rfc5424,
    }
}

fn bench_syslog_message_construction(c: &mut Criterion) {
    let sink = SyslogSink;
    let schema = sink.schema(None);
    let message = make_rfc5424_message();

    let mut group = c.benchmark_group("syslog_message_construction");
    group.throughput(Throughput::Elements(1));
    group.bench_function("per_record_fresh_arrays", |b| {
        b.iter(|| {
            let batch = sink
                .to_record_batch(black_box(&message), black_box(&schema))
                .unwrap();
            black_box(batch);
        });
    });
    group.finish();
}

criterion_group!(benches, bench_syslog_message_construction);
criterion_main!(benches);
