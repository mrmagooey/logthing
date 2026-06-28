// This file tests that the feature gate compiles cleanly and the proto types
// are importable. It will fail to compile until Cargo.toml is updated.
//
// Note: module paths for opentelemetry-proto 0.32 (as used here) match the
// brief's paths exactly. The `logs` feature is required to gate
// tonic::logs::v1 and tonic::collector::logs::v1; `gen-tonic-messages`
// gives the prost types; `with-serde` adds serde support.

#[cfg(feature = "otlp")]
#[test]
fn otlp_proto_types_importable() {
    use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
    use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue};
    use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
    // Constructing a default is enough to confirm the types are present.
    let _req = ExportLogsServiceRequest::default();
    let _lr = LogRecord::default();
    let _kv = KeyValue::default();
    let _av = AnyValue::default();
    let _rl = ResourceLogs::default();
    let _sl = ScopeLogs::default();
}

#[cfg(not(feature = "otlp"))]
#[test]
fn otlp_feature_absent_compiles_cleanly() {
    // When `otlp` is not enabled the crate still compiles — verified by the
    // test runner reaching this point without a compile error.
}
