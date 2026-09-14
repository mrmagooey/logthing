//! Criterion micro-benchmark: baseline cost of `otlp::map_otlp_request` --
//! the protobuf-struct -> `GenericRecord` mapping layer that OTLP log
//! ingest feeds into the shared writer path (see
//! `generic_hec_to_record_batch.rs` for that shared writer-path cost).
//! `map_otlp_request` itself has never been measured.
//!
//! Two cases: a single log record (the minimal request) and a 100-record
//! batch (OTLP clients batch aggressively in practice, so batch size 1
//! alone would not represent the real operating point).
//!
//! `map_otlp_request` takes `ExportLogsServiceRequest` BY VALUE and consumes
//! it, so each iteration needs its own owned copy. We use `iter_batched` to
//! clone the request in the (untimed) setup closure and only time the call
//! to `map_otlp_request` itself -- cloning inside the timed closure would
//! measure the clone, not the mapping.
//!
//! `opentelemetry-proto`/`prost` are optional deps gated behind the `otlp`
//! Cargo feature, and `map_otlp_request` only exists when that feature is
//! on -- so the real benchmark lives in a `#[cfg(feature = "otlp")]` module
//! with its own `main`, and a bare fallback `main` covers
//! `--no-default-features` builds (a bench binary needs some `main`).
//!
//! Run with: `cargo bench --bench otlp_map_request`

#[cfg(feature = "otlp")]
mod imp {
    use criterion::{BatchSize, Criterion, Throughput};
    use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
    use opentelemetry_proto::tonic::common::v1::{
        AnyValue, InstrumentationScope, KeyValue, any_value::Value as AnyVal,
    };
    use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
    use opentelemetry_proto::tonic::resource::v1::Resource;
    use std::hint::black_box;

    fn make_kv(key: &str, val: &str) -> KeyValue {
        KeyValue {
            key: key.to_string(),
            value: Some(AnyValue {
                value: Some(AnyVal::StringValue(val.to_string())),
            }),
            ..Default::default()
        }
    }

    /// One log record shaped like a realistic trace-correlated log line: a
    /// string body, INFO severity, a handful of log attributes, and 16/8-byte
    /// trace/span IDs (exercises the hex-encode paths in `map_otlp_request`).
    fn make_log_record(i: usize) -> LogRecord {
        LogRecord {
            time_unix_nano: 1_700_000_000_000_000_000 + i as u64,
            observed_time_unix_nano: 0,
            severity_number: 9, // INFO
            severity_text: "INFO".to_string(),
            body: Some(AnyValue {
                value: Some(AnyVal::StringValue(format!(
                    "request {i} completed successfully"
                ))),
            }),
            attributes: vec![
                make_kv("log.level", "info"),
                make_kv("http.method", "GET"),
                make_kv("http.route", "/api/v1/widgets"),
            ],
            dropped_attributes_count: 0,
            flags: 0,
            span_id: vec![0xAB; 8],
            trace_id: vec![0xCD; 16],
            event_name: String::new(),
        }
    }

    /// Build one `ExportLogsServiceRequest` with a single ResourceLogs ->
    /// single ScopeLogs -> `n` LogRecords, matching the shape `otlp.rs`'s own
    /// tests use (see `make_request` in `src/server/otlp.rs`'s test module).
    fn make_request(n: usize) -> ExportLogsServiceRequest {
        ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: Some(Resource {
                    attributes: vec![
                        make_kv("service.name", "my-service"),
                        make_kv("host.name", "prod-01"),
                    ],
                    ..Default::default()
                }),
                scope_logs: vec![ScopeLogs {
                    scope: Some(InstrumentationScope {
                        attributes: vec![make_kv("scope.name", "my-scope")],
                        ..Default::default()
                    }),
                    log_records: (0..n).map(make_log_record).collect(),
                    schema_url: String::new(),
                }],
                schema_url: String::new(),
            }],
        }
    }

    pub(crate) fn bench_map_otlp_request(c: &mut Criterion) {
        let mut group = c.benchmark_group("otlp_map_request");

        for batch_size in [1usize, 100] {
            let req = make_request(batch_size);

            // Setup assertion: confirm the mapping actually produces one
            // GenericRecord per LogRecord before benching, so a malformed
            // request can't silently time an empty mapping.
            let sanity =
                logthing::server::otlp::map_otlp_request(req.clone(), "10.0.0.1".to_string());
            assert_eq!(sanity.len(), batch_size);

            group.throughput(Throughput::Elements(batch_size as u64));
            group.bench_function(format!("batch_of_{batch_size}"), |b| {
                b.iter_batched(
                    || req.clone(),
                    |req| {
                        let records = logthing::server::otlp::map_otlp_request(
                            black_box(req),
                            black_box("10.0.0.1".to_string()),
                        );
                        black_box(records);
                    },
                    BatchSize::SmallInput,
                );
            });
        }

        group.finish();
    }
}

#[cfg(feature = "otlp")]
criterion::criterion_group!(benches, imp::bench_map_otlp_request);
#[cfg(feature = "otlp")]
criterion::criterion_main!(benches);

#[cfg(not(feature = "otlp"))]
fn main() {}
