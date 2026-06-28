//! OTLP/HTTP log record ingestion — mapping layer.
//!
//! Converts an `ExportLogsServiceRequest` (protobuf or JSON) into a Vec of
//! `GenericRecord`s suitable for the Unit-4 generic S3 sink.
//!
//! Attribute precedence (highest wins on key collision):
//!   log attributes > scope attributes > resource attributes
//!
//! This module is compiled only when the `otlp` Cargo feature is enabled.

use crate::ingest::GenericRecord;
use chrono::{DateTime, TimeZone, Utc};
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value::Value as AnyVal};
use serde_json::{Map, Value};

/// Convert an OTLP `ExportLogsServiceRequest` to a flat list of `GenericRecord`s.
///
/// Flattening strategy: resource attributes are inserted first, then scope
/// attributes (overwrite on collision), then log-level attributes (overwrite on
/// collision).  This gives log-level attributes the highest precedence, matching
/// the OpenTelemetry semantic: the closer to the signal, the more specific.
///
/// `source_host` is set as `Some(source_host)` on every record (the TCP peer
/// address supplied by the caller).
pub fn map_otlp_request(req: ExportLogsServiceRequest, source_host: String) -> Vec<GenericRecord> {
    let received_at = Utc::now();
    let mut records = Vec::new();

    for resource_logs in req.resource_logs {
        // Collect resource-level attributes once per ResourceLogs block.
        let resource_attrs: Map<String, Value> = resource_logs
            .resource
            .map(|r| kv_list_to_map(r.attributes))
            .unwrap_or_default();

        for scope_logs in resource_logs.scope_logs {
            // Scope attributes live inside `InstrumentationScope` (if present).
            let scope_attrs: Map<String, Value> = scope_logs
                .scope
                .map(|s| kv_list_to_map(s.attributes))
                .unwrap_or_default();

            for log_record in scope_logs.log_records {
                // Build merged fields: resource < scope < log attributes.
                let mut fields: Map<String, Value> = Map::new();
                fields.extend(resource_attrs.clone());
                fields.extend(scope_attrs.clone());
                fields.extend(kv_list_to_map(log_record.attributes));

                // Log body — map AnyValue to JSON and store under "body".
                if let Some(body_av) = log_record.body {
                    fields.insert("body".to_string(), any_value_to_json(body_av));
                }

                // Severity metadata (only insert when present / non-default).
                if !log_record.severity_text.is_empty() {
                    fields.insert(
                        "severity_text".to_string(),
                        Value::String(log_record.severity_text),
                    );
                }
                if log_record.severity_number != 0 {
                    fields.insert(
                        "severity_number".to_string(),
                        Value::Number(log_record.severity_number.into()),
                    );
                }

                // Trace context (hex-encoded, only when non-empty).
                if !log_record.trace_id.is_empty() {
                    fields.insert(
                        "trace_id".to_string(),
                        Value::String(hex::encode(&log_record.trace_id)),
                    );
                }
                if !log_record.span_id.is_empty() {
                    fields.insert(
                        "span_id".to_string(),
                        Value::String(hex::encode(&log_record.span_id)),
                    );
                }

                // Timestamp: None when time_unix_nano is 0 (OTLP "unset") or
                // would overflow i64 (after year 2262). No panic path.
                let time: Option<DateTime<Utc>> =
                    nanos_to_datetime(log_record.time_unix_nano);

                records.push(GenericRecord {
                    sourcetype: "otlp".to_string(),
                    host: Some(source_host.clone()),
                    time,
                    fields: Value::Object(fields),
                    received_at,
                });
            }
        }
    }

    records
}

/// Convert an OTLP nanosecond timestamp to `DateTime<Utc>`.
///
/// Returns `None` when:
/// - `nanos` is 0 (OTLP sentinel for "unset/unknown")
/// - `nanos` exceeds `i64::MAX` (overflow guard; would be after year 2262)
/// - The resulting `(secs, subsec_nanos)` pair is not representable (chrono
///   `timestamp_opt` returns `LocalResult::None`)
///
/// Never panics.
#[inline]
fn nanos_to_datetime(nanos: u64) -> Option<DateTime<Utc>> {
    if nanos == 0 {
        return None;
    }
    // Guard against u64 → i64 overflow (timestamps after year 2262).
    if nanos > i64::MAX as u64 {
        return None;
    }
    let secs = (nanos / 1_000_000_000) as i64;
    let subsec_nanos = (nanos % 1_000_000_000) as u32;
    // `single()` returns None for ambiguous or invalid timestamps.
    Utc.timestamp_opt(secs, subsec_nanos).single()
}

/// Convert an OTLP `AnyValue` to a `serde_json::Value`.
///
/// | OTLP variant    | JSON mapping                                     |
/// |-----------------|--------------------------------------------------|
/// | StringValue     | `Value::String`                                  |
/// | IntValue        | `Value::Number` (i64)                            |
/// | DoubleValue     | `Value::Number` (f64); `Null` when non-finite    |
/// | BoolValue       | `Value::Bool`                                    |
/// | BytesValue      | `Value::String` (lowercase hex)                  |
/// | ArrayValue      | `Value::Array` (recursive)                       |
/// | KvlistValue     | `Value::Object` (recursive via `kv_list_to_map`) |
/// | None            | `Value::Null`                                    |
///
/// Never panics.  Recursion terminates because protobuf message graphs are
/// finite and acyclic.
pub fn any_value_to_json(av: AnyValue) -> Value {
    match av.value {
        Some(AnyVal::StringValue(s)) => Value::String(s),
        Some(AnyVal::IntValue(i)) => Value::Number(i.into()),
        Some(AnyVal::DoubleValue(f)) => {
            // serde_json::Number only accepts finite f64; map NaN/±∞ to Null.
            serde_json::Number::from_f64(f)
                .map(Value::Number)
                .unwrap_or(Value::Null)
        }
        Some(AnyVal::BoolValue(b)) => Value::Bool(b),
        Some(AnyVal::BytesValue(b)) => Value::String(hex::encode(&b)),
        Some(AnyVal::ArrayValue(arr)) => {
            Value::Array(arr.values.into_iter().map(any_value_to_json).collect())
        }
        Some(AnyVal::KvlistValue(kl)) => Value::Object(kv_list_to_map(kl.values)),
        None => Value::Null,
        // `StringValueStrindex` is a Profiling-signal index; the OTLP spec says
        // non-profiling receivers should treat it as absent.  Any future unknown
        // variants are also mapped to Null so the match stays exhaustive.
        Some(_) => Value::Null,
    }
}

/// Convert a `Vec<KeyValue>` to a `serde_json::Map<String, Value>`.
///
/// Keys with `None` values are mapped to `Value::Null` (safe default).
pub fn kv_list_to_map(kvs: Vec<KeyValue>) -> Map<String, Value> {
    kvs.into_iter()
        .map(|kv| {
            let val = kv.value.map(any_value_to_json).unwrap_or(Value::Null);
            (kv.key, val)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
    use opentelemetry_proto::tonic::common::v1::{
        AnyValue, ArrayValue, InstrumentationScope, KeyValue, KeyValueList,
        any_value::Value as AnyVal,
    };
    use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
    use opentelemetry_proto::tonic::resource::v1::Resource;

    fn make_kv(key: &str, val: &str) -> KeyValue {
        KeyValue {
            key: key.to_string(),
            value: Some(AnyValue {
                value: Some(AnyVal::StringValue(val.to_string())),
            }),
            ..Default::default()
        }
    }

    fn make_int_kv(key: &str, val: i64) -> KeyValue {
        KeyValue {
            key: key.to_string(),
            value: Some(AnyValue {
                value: Some(AnyVal::IntValue(val)),
            }),
            ..Default::default()
        }
    }

    fn make_bool_kv(key: &str, val: bool) -> KeyValue {
        KeyValue {
            key: key.to_string(),
            value: Some(AnyValue {
                value: Some(AnyVal::BoolValue(val)),
            }),
            ..Default::default()
        }
    }

    fn make_double_kv(key: &str, val: f64) -> KeyValue {
        KeyValue {
            key: key.to_string(),
            value: Some(AnyValue {
                value: Some(AnyVal::DoubleValue(val)),
            }),
            ..Default::default()
        }
    }

    /// Build a minimal `ExportLogsServiceRequest` with one ResourceLogs →
    /// one ScopeLogs → one LogRecord.
    ///
    /// NOTE: Scope attributes live inside `ScopeLogs.scope` (`InstrumentationScope`),
    /// NOT directly on `ScopeLogs`.  The brief placed them on `ScopeLogs.attributes`
    /// which does not exist on the real struct.
    fn make_request(
        resource_attrs: Vec<KeyValue>,
        scope_attrs: Vec<KeyValue>,
        log_attrs: Vec<KeyValue>,
        time_unix_nano: u64,
        body_str: &str,
    ) -> ExportLogsServiceRequest {
        ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: Some(Resource {
                    attributes: resource_attrs,
                    ..Default::default()
                }),
                scope_logs: vec![ScopeLogs {
                    // Scope attributes belong to InstrumentationScope, not ScopeLogs.
                    scope: Some(InstrumentationScope {
                        attributes: scope_attrs,
                        ..Default::default()
                    }),
                    log_records: vec![LogRecord {
                        time_unix_nano,
                        observed_time_unix_nano: 0,
                        severity_number: 9, // INFO
                        severity_text: "INFO".to_string(),
                        body: Some(AnyValue {
                            value: Some(AnyVal::StringValue(body_str.to_string())),
                        }),
                        attributes: log_attrs,
                        dropped_attributes_count: 0,
                        flags: 0,
                        span_id: vec![],
                        trace_id: vec![],
                        // event_name added in OTLP v1.2; default to empty string.
                        event_name: String::new(),
                    }],
                    schema_url: String::new(),
                }],
                schema_url: String::new(),
            }],
        }
    }

    // ── Test 1: basic mapping — time, body, sourcetype ─────────────────────
    #[test]
    fn map_otlp_request_sets_sourcetype_and_time() {
        // time_unix_nano = 1_700_000_000_000_000_000 ns = 2023-11-14T22:13:20Z
        let req = make_request(vec![], vec![], vec![], 1_700_000_000_000_000_000, "hello world");
        let records = map_otlp_request(req, "10.0.0.1".to_string());
        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert_eq!(r.sourcetype, "otlp");
        // host is Option<String> — the REAL GenericRecord type
        assert_eq!(r.host.as_deref(), Some("10.0.0.1"));
        // time is Option<DateTime<Utc>> — the REAL GenericRecord type
        let t = r.time.expect("time must be Some for non-zero time_unix_nano");
        assert!(t.timestamp() > 0, "timestamp must be after epoch");
        // body field
        assert_eq!(r.fields.get("body").and_then(|v| v.as_str()), Some("hello world"));
        // severity
        assert_eq!(r.fields.get("severity_text").and_then(|v| v.as_str()), Some("INFO"));
    }

    // ── Test 2: resource + scope + log attribute flattening ─────────────────
    #[test]
    fn map_otlp_request_flattens_all_attribute_layers() {
        let resource_attrs = vec![
            make_kv("service.name", "my-service"),
            make_kv("host.name", "prod-01"),
        ];
        let scope_attrs = vec![make_kv("scope.name", "my-scope")];
        let log_attrs = vec![
            make_kv("log.level", "info"),
            make_int_kv("http.status_code", 200),
        ];
        let req = make_request(
            resource_attrs,
            scope_attrs,
            log_attrs,
            1_700_000_000_000_000_000,
            "test",
        );
        let records = map_otlp_request(req, "10.0.0.2".to_string());
        assert_eq!(records.len(), 1);
        let fields = &records[0].fields;
        // resource attrs
        assert_eq!(
            fields.get("service.name").and_then(|v| v.as_str()),
            Some("my-service")
        );
        assert_eq!(
            fields.get("host.name").and_then(|v| v.as_str()),
            Some("prod-01")
        );
        // scope attrs (from InstrumentationScope)
        assert_eq!(
            fields.get("scope.name").and_then(|v| v.as_str()),
            Some("my-scope")
        );
        // log attrs
        assert_eq!(
            fields.get("log.level").and_then(|v| v.as_str()),
            Some("info")
        );
        assert_eq!(
            fields.get("http.status_code").and_then(|v| v.as_i64()),
            Some(200)
        );
    }

    // ── Test 3: attribute collision — log attrs win over scope, scope over resource ──
    #[test]
    fn map_otlp_request_log_attrs_override_resource_attrs_on_collision() {
        let resource_attrs = vec![make_kv("key", "from-resource")];
        let scope_attrs = vec![make_kv("key", "from-scope")];
        let log_attrs = vec![make_kv("key", "from-log")];
        let req = make_request(resource_attrs, scope_attrs, log_attrs, 0, "collision");
        let records = map_otlp_request(req, "10.0.0.3".to_string());
        // log attrs have highest precedence
        assert_eq!(
            records[0].fields.get("key").and_then(|v| v.as_str()),
            Some("from-log")
        );
    }

    // ── Test 4: zero time_unix_nano → time is None ──────────────────────────
    //
    // The REAL GenericRecord.time is Option<DateTime<Utc>>.  Per the OTLP spec,
    // time_unix_nano == 0 means "unset/unknown"; the correct mapping is None,
    // letting consumers fall back to received_at.  The brief incorrectly assumed
    // time would be filled with received_at (it was using the wrong GenericRecord
    // shape where time was non-optional).
    #[test]
    fn map_otlp_request_zero_time_maps_to_none() {
        let req = make_request(vec![], vec![], vec![], 0, "no time");
        let records = map_otlp_request(req, "10.0.0.4".to_string());
        assert_eq!(records.len(), 1);
        // received_at is always set (wall-clock time of ingest)
        assert!(records[0].received_at <= Utc::now());
        // time is None for OTLP "unset" timestamp
        assert!(
            records[0].time.is_none(),
            "time must be None when time_unix_nano is 0 (OTLP unset)"
        );
    }

    // ── Test 5: multiple ResourceLogs + multiple ScopeLogs ─────────────────
    #[test]
    fn map_otlp_request_handles_multiple_resource_and_scope_logs() {
        let req = ExportLogsServiceRequest {
            resource_logs: vec![
                ResourceLogs {
                    resource: Some(Resource {
                        attributes: vec![make_kv("svc", "a")],
                        ..Default::default()
                    }),
                    scope_logs: vec![ScopeLogs {
                        scope: None,
                        log_records: vec![
                            LogRecord {
                                body: Some(AnyValue {
                                    value: Some(AnyVal::StringValue("msg1".into())),
                                }),
                                time_unix_nano: 1_000,
                                ..Default::default()
                            },
                            LogRecord {
                                body: Some(AnyValue {
                                    value: Some(AnyVal::StringValue("msg2".into())),
                                }),
                                time_unix_nano: 2_000,
                                ..Default::default()
                            },
                        ],
                        schema_url: String::new(),
                    }],
                    schema_url: String::new(),
                },
                ResourceLogs {
                    resource: Some(Resource {
                        attributes: vec![make_kv("svc", "b")],
                        ..Default::default()
                    }),
                    scope_logs: vec![ScopeLogs {
                        scope: None,
                        log_records: vec![LogRecord {
                            body: Some(AnyValue {
                                value: Some(AnyVal::StringValue("msg3".into())),
                            }),
                            time_unix_nano: 3_000,
                            ..Default::default()
                        }],
                        schema_url: String::new(),
                    }],
                    schema_url: String::new(),
                },
            ],
        };
        let records = map_otlp_request(req, "10.0.0.5".to_string());
        assert_eq!(records.len(), 3, "3 log records across 2 resource groups");
        let bodies: Vec<&str> = records
            .iter()
            .map(|r| r.fields["body"].as_str().unwrap_or(""))
            .collect();
        assert!(bodies.contains(&"msg1"));
        assert!(bodies.contains(&"msg2"));
        assert!(bodies.contains(&"msg3"));
        // Each record has its resource's svc attribute
        assert_eq!(
            records[0].fields.get("svc").and_then(|v| v.as_str()),
            Some("a")
        );
        assert_eq!(
            records[2].fields.get("svc").and_then(|v| v.as_str()),
            Some("b")
        );
    }

    // ── Test 6: any_value_to_json covers all AnyValue variants ─────────────
    #[test]
    fn any_value_to_json_maps_all_variants() {
        use serde_json::json;

        let string_av = AnyValue {
            value: Some(AnyVal::StringValue("hello".into())),
        };
        assert_eq!(any_value_to_json(string_av), json!("hello"));

        let int_av = AnyValue {
            value: Some(AnyVal::IntValue(42)),
        };
        assert_eq!(any_value_to_json(int_av), json!(42));

        let double_av = AnyValue {
            value: Some(AnyVal::DoubleValue(3.14)),
        };
        assert!((any_value_to_json(double_av).as_f64().unwrap() - 3.14_f64).abs() < 1e-9);

        let bool_av = AnyValue {
            value: Some(AnyVal::BoolValue(true)),
        };
        assert_eq!(any_value_to_json(bool_av), json!(true));

        let bytes_av = AnyValue {
            value: Some(AnyVal::BytesValue(vec![0xDE, 0xAD])),
        };
        // bytes → lowercase hex string
        let bv = any_value_to_json(bytes_av);
        assert!(bv.is_string());
        let s = bv.as_str().unwrap();
        assert_eq!(s, "dead");

        let none_av = AnyValue { value: None };
        assert_eq!(any_value_to_json(none_av), json!(null));

        let array_av = AnyValue {
            value: Some(AnyVal::ArrayValue(ArrayValue {
                values: vec![
                    AnyValue {
                        value: Some(AnyVal::StringValue("x".into())),
                    },
                    AnyValue {
                        value: Some(AnyVal::IntValue(1)),
                    },
                ],
            })),
        };
        let av_json = any_value_to_json(array_av);
        assert!(av_json.is_array());
        let arr = av_json.as_array().unwrap();
        assert_eq!(arr[0], json!("x"));
        assert_eq!(arr[1], json!(1));

        let kvlist_av = AnyValue {
            value: Some(AnyVal::KvlistValue(KeyValueList {
                values: vec![make_kv("k", "v")],
            })),
        };
        let kv_json = any_value_to_json(kvlist_av);
        assert!(kv_json.is_object());
        assert_eq!(kv_json["k"], json!("v"));
    }

    // ── Test 7: kv_list_to_map ───────────────────────────────────────────────
    #[test]
    fn kv_list_to_map_converts_all_types() {
        use serde_json::json;
        let kvs = vec![
            make_kv("str_key", "hello"),
            make_int_kv("int_key", 99),
            make_bool_kv("bool_key", false),
            make_double_kv("f64_key", 2.71),
        ];
        let map = kv_list_to_map(kvs);
        assert_eq!(map["str_key"], json!("hello"));
        assert_eq!(map["int_key"], json!(99));
        assert_eq!(map["bool_key"], json!(false));
        assert!((map["f64_key"].as_f64().unwrap() - 2.71_f64).abs() < 1e-9);
    }

    // ── Test 8: nanos_to_datetime — overflow and zero guards ─────────────────
    #[test]
    fn nanos_to_datetime_handles_edge_cases() {
        // Zero → None
        assert!(nanos_to_datetime(0).is_none());

        // Overflow (> i64::MAX) → None; no panic
        assert!(nanos_to_datetime(u64::MAX).is_none());
        assert!(nanos_to_datetime(i64::MAX as u64 + 1).is_none());

        // i64::MAX itself is within range; should return Some
        // (i64::MAX ns ≈ year 2262 — valid but far future)
        assert!(nanos_to_datetime(i64::MAX as u64).is_some());

        // Well-known timestamp: 2023-11-14T22:13:20Z = 1_700_000_000 seconds
        let dt = nanos_to_datetime(1_700_000_000_000_000_000).unwrap();
        assert_eq!(dt.timestamp(), 1_700_000_000);
    }

    // ── Test 9: missing body / empty attributes → no panic ──────────────────
    #[test]
    fn map_otlp_request_handles_no_body_and_empty_attrs() {
        let req = ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: None,
                scope_logs: vec![ScopeLogs {
                    scope: None,
                    log_records: vec![LogRecord {
                        body: None,
                        attributes: vec![],
                        ..Default::default()
                    }],
                    schema_url: String::new(),
                }],
                schema_url: String::new(),
            }],
        };
        let records = map_otlp_request(req, "host".to_string());
        assert_eq!(records.len(), 1);
        // No body key when body is None
        assert!(records[0].fields.get("body").is_none());
        assert_eq!(records[0].sourcetype, "otlp");
        assert_eq!(records[0].host.as_deref(), Some("host"));
    }

    // ── Test 10: empty request → empty output ──────────────────────────────
    #[test]
    fn map_otlp_request_empty_request_returns_empty() {
        let req = ExportLogsServiceRequest {
            resource_logs: vec![],
        };
        let records = map_otlp_request(req, "host".to_string());
        assert!(records.is_empty());
    }
}
