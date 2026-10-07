//! OTLP/HTTP log record ingestion — mapping layer.
//!
//! Converts an `ExportLogsServiceRequest` (protobuf or JSON) into a Vec of
//! typed `OtlpRecord`s for the OTLP sink (`crate::forwarding::otlp_s3`).
//!
//! Attribute handling: resource attributes go to `resource_attributes`; scope
//! attributes overlaid with log attributes (log wins) go to `attributes`.
//!
//! This module is compiled only when the `otlp` Cargo feature is enabled.

use crate::forwarding::otlp_s3::OtlpRecord;
use chrono::{DateTime, TimeZone, Utc};
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value::Value as AnyVal};
use serde_json::{Map, Value};

fn non_empty(s: String) -> Option<String> {
    Some(s).filter(|s| !s.is_empty())
}

/// A resource attribute promoted to a column: only non-empty STRING values qualify.
fn string_attr(attrs: &Map<String, Value>, key: &str) -> Option<String> {
    match attrs.get(key) {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

/// String bodies verbatim; every other AnyValue as its JSON text; absent -> `None`.
fn body_to_string(av: AnyValue) -> Option<String> {
    match av.value {
        None => None,
        Some(AnyVal::StringValue(s)) => Some(s),
        Some(other) => Some(any_value_to_json(AnyValue { value: Some(other) }).to_string()),
    }
}

/// Convert an OTLP `ExportLogsServiceRequest` to a flat list of `OtlpRecord`s.
///
/// Rules: `service.name`, `service.namespace`, `service.instance.id` and `host.name` resource
/// attributes are promoted to columns only when they are non-empty strings; ALL resource
/// attributes (promoted ones included) are kept in `resource_attributes`. `attributes` is the
/// scope attributes overlaid with the log attributes (log wins). `body`: string bodies
/// verbatim, any other AnyValue as JSON text, absent -> `None`. OTLP "unset" defaults (zero
/// timestamps, severity 0, empty ids/strings, flags 0) map to `None`. `peer_addr` is the TCP
/// peer IP. `event_uuid` is NOT assigned here (see `crate::ingest::assign_event_uuids`).
pub fn map_otlp_request(req: ExportLogsServiceRequest, peer_addr: String) -> Vec<OtlpRecord> {
    let received_at = Utc::now();
    let mut records = Vec::new();

    for resource_logs in req.resource_logs {
        let resource_attrs: Map<String, Value> = resource_logs
            .resource
            .map(|r| kv_list_to_map(r.attributes))
            .unwrap_or_default();
        let service_name = string_attr(&resource_attrs, "service.name");
        let service_namespace = string_attr(&resource_attrs, "service.namespace");
        let service_instance_id = string_attr(&resource_attrs, "service.instance.id");
        let host_name = string_attr(&resource_attrs, "host.name");
        let resource_json = Value::Object(resource_attrs);

        for scope_logs in resource_logs.scope_logs {
            let (scope_name, scope_version, scope_attrs) = match scope_logs.scope {
                Some(s) => (
                    non_empty(s.name),
                    non_empty(s.version),
                    kv_list_to_map(s.attributes),
                ),
                None => (None, None, Map::new()),
            };

            for lr in scope_logs.log_records {
                let mut attrs = scope_attrs.clone();
                attrs.extend(kv_list_to_map(lr.attributes));

                records.push(OtlpRecord {
                    event_uuid: None,
                    time: nanos_to_datetime(lr.time_unix_nano),
                    observed_time: nanos_to_datetime(lr.observed_time_unix_nano),
                    received_at,
                    severity_number: (lr.severity_number != 0).then_some(lr.severity_number),
                    severity_text: non_empty(lr.severity_text),
                    body: lr.body.and_then(body_to_string),
                    service_name: service_name.clone(),
                    service_namespace: service_namespace.clone(),
                    service_instance_id: service_instance_id.clone(),
                    host_name: host_name.clone(),
                    peer_addr: Some(peer_addr.clone()),
                    trace_id: (!lr.trace_id.is_empty()).then(|| hex::encode(&lr.trace_id)),
                    span_id: (!lr.span_id.is_empty()).then(|| hex::encode(&lr.span_id)),
                    flags: (lr.flags != 0).then_some(lr.flags),
                    event_name: non_empty(lr.event_name),
                    scope_name: scope_name.clone(),
                    scope_version: scope_version.clone(),
                    resource_attributes: resource_json.clone(),
                    attributes: Value::Object(attrs),
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

    #[test]
    fn map_promotes_service_and_host_attrs_and_keeps_all_resource_attrs() {
        let req = make_request(
            vec![
                make_kv("service.name", "Checkout"),
                make_kv("service.namespace", "shop"),
                make_kv("service.instance.id", "i-1"),
                make_kv("host.name", "web01"),
                make_kv("k8s.pod", "p1"),
            ],
            vec![],
            vec![],
            1_700_000_000_000_000_000,
            "hello world",
        );
        let records = map_otlp_request(req, "10.0.0.1".to_string());
        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert_eq!(
            r.service_name.as_deref(),
            Some("Checkout"),
            "raw, unsanitized"
        );
        assert_eq!(r.service_namespace.as_deref(), Some("shop"));
        assert_eq!(r.service_instance_id.as_deref(), Some("i-1"));
        assert_eq!(r.host_name.as_deref(), Some("web01"));
        assert_eq!(r.peer_addr.as_deref(), Some("10.0.0.1"));
        assert_eq!(r.body.as_deref(), Some("hello world"));
        assert_eq!(r.severity_number, Some(9));
        assert_eq!(r.severity_text.as_deref(), Some("INFO"));
        assert_eq!(r.time.unwrap().timestamp(), 1_700_000_000);
        assert!(r.event_uuid.is_none(), "mapper must not assign ids");
        assert_eq!(r.resource_attributes["k8s.pod"], "p1");
        assert_eq!(
            r.resource_attributes["service.name"], "Checkout",
            "promoted keys stay in resource_attributes (lossless)"
        );
    }

    #[test]
    fn map_attributes_merge_log_over_scope_and_exclude_resource() {
        let req = make_request(
            vec![make_kv("key", "from-resource"), make_kv("r", "1")],
            vec![make_kv("key", "from-scope"), make_kv("s", "2")],
            vec![
                make_kv("key", "from-log"),
                make_int_kv("http.status_code", 200),
            ],
            0,
            "collision",
        );
        let r = &map_otlp_request(req, "h".to_string())[0];
        assert_eq!(r.attributes["key"], "from-log");
        assert_eq!(r.attributes["s"], "2");
        assert_eq!(r.attributes["http.status_code"], 200);
        assert!(
            r.attributes.get("r").is_none(),
            "resource attrs live in resource_attributes"
        );
        assert_eq!(r.resource_attributes["key"], "from-resource");
    }

    #[test]
    fn map_zero_defaults_become_null() {
        let req = ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: None,
                scope_logs: vec![ScopeLogs {
                    scope: None,
                    log_records: vec![LogRecord::default()],
                    schema_url: String::new(),
                }],
                schema_url: String::new(),
            }],
        };
        let r = &map_otlp_request(req, "h".to_string())[0];
        assert!(r.time.is_none() && r.observed_time.is_none());
        assert!(r.severity_number.is_none() && r.severity_text.is_none());
        assert!(r.body.is_none());
        assert!(r.trace_id.is_none() && r.span_id.is_none());
        assert!(r.flags.is_none() && r.event_name.is_none());
        assert!(r.service_name.is_none() && r.host_name.is_none());
        assert!(r.scope_name.is_none() && r.scope_version.is_none());
        assert_eq!(r.resource_attributes, serde_json::json!({}));
        assert_eq!(r.attributes, serde_json::json!({}));
    }

    #[test]
    fn map_no_resource_or_unusable_service_name_yields_null_service_name() {
        // Missing resource entirely, empty string, and non-string service.name.
        for attrs in [
            vec![],
            vec![make_kv("service.name", "")],
            vec![make_int_kv("service.name", 42)],
        ] {
            let req = make_request(attrs, vec![], vec![], 0, "x");
            let r = &map_otlp_request(req, "h".to_string())[0];
            assert!(
                r.service_name.is_none(),
                "unusable service.name must map to NULL"
            );
        }
        let req = make_request(
            vec![make_int_kv("service.name", 42)],
            vec![],
            vec![],
            0,
            "x",
        );
        let r = &map_otlp_request(req, "h".to_string())[0];
        assert_eq!(
            r.resource_attributes["service.name"], 42,
            "raw value kept in the JSON"
        );
    }

    #[test]
    fn map_trace_context_scope_flags_and_observed_time() {
        let req = ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: None,
                scope_logs: vec![ScopeLogs {
                    scope: Some(InstrumentationScope {
                        name: "lib".to_string(),
                        version: "1.2".to_string(),
                        ..Default::default()
                    }),
                    log_records: vec![LogRecord {
                        observed_time_unix_nano: 1_700_000_001_000_000_000,
                        trace_id: vec![0xAB; 16],
                        span_id: vec![0xCD; 8],
                        flags: 1,
                        event_name: "http.request".to_string(),
                        ..Default::default()
                    }],
                    schema_url: String::new(),
                }],
                schema_url: String::new(),
            }],
        };
        let r = &map_otlp_request(req, "h".to_string())[0];
        assert_eq!(
            r.trace_id.as_deref(),
            Some("abababababababababababababababab")
        );
        assert_eq!(r.span_id.as_deref(), Some("cdcdcdcdcdcdcdcd"));
        assert_eq!(r.flags, Some(1));
        assert_eq!(r.event_name.as_deref(), Some("http.request"));
        assert_eq!(r.scope_name.as_deref(), Some("lib"));
        assert_eq!(r.scope_version.as_deref(), Some("1.2"));
        assert_eq!(r.observed_time.unwrap().timestamp(), 1_700_000_001);
    }

    /// Map a single record carrying `body` and return the mapped record.
    fn map_with_body(body: Option<AnyValue>) -> OtlpRecord {
        let req = ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: None,
                scope_logs: vec![ScopeLogs {
                    scope: None,
                    log_records: vec![LogRecord {
                        body,
                        ..Default::default()
                    }],
                    schema_url: String::new(),
                }],
                schema_url: String::new(),
            }],
        };
        map_otlp_request(req, "h".to_string()).remove(0)
    }

    /// Nest `depth` levels of array (or kvlist) around an int leaf.
    fn nested(depth: usize, kvlist: bool) -> AnyValue {
        let mut v = AnyValue {
            value: Some(AnyVal::IntValue(1)),
        };
        for _ in 0..depth {
            v = if kvlist {
                AnyValue {
                    value: Some(AnyVal::KvlistValue(KeyValueList {
                        values: vec![KeyValue {
                            key: "k".to_string(),
                            value: Some(v),
                            ..Default::default()
                        }],
                    })),
                }
            } else {
                AnyValue {
                    value: Some(AnyVal::ArrayValue(ArrayValue { values: vec![v] })),
                }
            };
        }
        v
    }

    #[test]
    fn map_body_variants_string_verbatim_others_json() {
        let body_of = |value: Option<AnyVal>| map_with_body(Some(AnyValue { value })).body;
        assert_eq!(
            body_of(Some(AnyVal::StringValue("plain \"quoted\"".into()))).as_deref(),
            Some("plain \"quoted\""),
            "string verbatim, no JSON quoting"
        );
        assert_eq!(body_of(Some(AnyVal::IntValue(7))).as_deref(), Some("7"));
        assert_eq!(
            body_of(Some(AnyVal::BoolValue(true))).as_deref(),
            Some("true")
        );
        assert_eq!(
            body_of(Some(AnyVal::DoubleValue(f64::NAN))).as_deref(),
            Some("null"),
            "non-finite doubles must not panic"
        );
        assert_eq!(
            body_of(Some(AnyVal::BytesValue(vec![0xde, 0xad]))).as_deref(),
            Some("\"dead\"")
        );
        assert_eq!(body_of(None), None);
        assert!(map_with_body(None).body.is_none(), "absent body -> NULL");
    }

    #[test]
    fn map_structured_body_is_json_text() {
        let body = AnyValue {
            value: Some(AnyVal::KvlistValue(KeyValueList {
                values: vec![make_kv("k", "v")],
            })),
        };
        assert_eq!(
            map_with_body(Some(body)).body.as_deref(),
            Some("{\"k\":\"v\"}")
        );
    }

    #[test]
    fn map_deeply_nested_array_and_kvlist_bodies_do_not_panic() {
        for kvlist in [false, true] {
            let r = map_with_body(Some(nested(100, kvlist)));
            let text = r.body.expect("nested body is serialised");
            serde_json::from_str::<Value>(&text).expect("body is valid JSON text");
        }
    }

    #[test]
    fn map_deeply_nested_attribute_values_do_not_panic() {
        let kv = |key: &str, v: AnyValue| KeyValue {
            key: key.to_string(),
            value: Some(v),
            ..Default::default()
        };
        let req = make_request(
            vec![kv("deep.arr", nested(100, false))],
            vec![],
            vec![kv("deep.kv", nested(100, true))],
            0,
            "x",
        );
        let r = &map_otlp_request(req, "h".to_string())[0];
        assert!(r.attributes["deep.kv"].is_object());
        assert!(r.resource_attributes["deep.arr"].is_array());
    }

    #[test]
    fn map_non_finite_double_attributes_become_null() {
        let req = make_request(
            vec![make_double_kv("r", f64::INFINITY)],
            vec![],
            vec![
                make_double_kv("nan", f64::NAN),
                make_double_kv("neg_inf", f64::NEG_INFINITY),
                make_double_kv("ok", 1.5),
            ],
            0,
            "x",
        );
        let r = &map_otlp_request(req, "h".to_string())[0];
        assert!(r.attributes["nan"].is_null());
        assert!(r.attributes["neg_inf"].is_null());
        assert_eq!(r.attributes["ok"], 1.5);
        assert!(r.resource_attributes["r"].is_null());
    }

    #[test]
    fn map_bytes_attribute_is_hex_string() {
        let kv = KeyValue {
            key: "raw".to_string(),
            value: Some(AnyValue {
                value: Some(AnyVal::BytesValue(vec![0xca, 0xfe])),
            }),
            ..Default::default()
        };
        let r = &map_otlp_request(make_request(vec![], vec![], vec![kv], 0, "x"), "h".into())[0];
        assert_eq!(r.attributes["raw"], "cafe");
    }

    #[test]
    fn map_huge_attribute_value_does_not_panic_or_truncate() {
        let big = "x".repeat(1024 * 1024);
        let req = make_request(vec![], vec![], vec![make_kv("blob", &big)], 0, "b");
        let r = &map_otlp_request(req, "h".to_string())[0];
        assert_eq!(r.attributes["blob"].as_str().unwrap().len(), 1024 * 1024);
    }

    #[test]
    fn map_multiple_resources_keep_their_own_service_name() {
        let mk = |svc: &str, bodies: &[&str]| ResourceLogs {
            resource: Some(Resource {
                attributes: vec![make_kv("service.name", svc)],
                ..Default::default()
            }),
            scope_logs: vec![ScopeLogs {
                scope: None,
                log_records: bodies
                    .iter()
                    .map(|b| LogRecord {
                        body: Some(AnyValue {
                            value: Some(AnyVal::StringValue((*b).into())),
                        }),
                        ..Default::default()
                    })
                    .collect(),
                schema_url: String::new(),
            }],
            schema_url: String::new(),
        };
        let req = ExportLogsServiceRequest {
            resource_logs: vec![mk("a", &["msg1", "msg2"]), mk("b", &["msg3"])],
        };
        let records = map_otlp_request(req, "h".to_string());
        let got: Vec<(&str, &str)> = records
            .iter()
            .map(|r| {
                (
                    r.service_name.as_deref().unwrap(),
                    r.body.as_deref().unwrap(),
                )
            })
            .collect();
        assert_eq!(got, vec![("a", "msg1"), ("a", "msg2"), ("b", "msg3")]);
    }

    #[test]
    fn map_otlp_request_handles_multiple_resource_and_scope_logs() {
        let rl = |svc: &str, bodies: &[(&str, u64)]| ResourceLogs {
            resource: Some(Resource {
                attributes: vec![make_kv("svc", svc)],
                ..Default::default()
            }),
            scope_logs: vec![ScopeLogs {
                scope: None,
                log_records: bodies
                    .iter()
                    .map(|(b, t)| LogRecord {
                        body: Some(AnyValue {
                            value: Some(AnyVal::StringValue((*b).into())),
                        }),
                        time_unix_nano: *t,
                        ..Default::default()
                    })
                    .collect(),
                schema_url: String::new(),
            }],
            schema_url: String::new(),
        };
        let req = ExportLogsServiceRequest {
            resource_logs: vec![
                rl("a", &[("msg1", 1_000), ("msg2", 2_000)]),
                rl("b", &[("msg3", 3_000)]),
            ],
        };
        let records = map_otlp_request(req, "10.0.0.5".to_string());
        assert_eq!(records.len(), 3, "3 log records across 2 resource groups");
        let bodies: Vec<&str> = records
            .iter()
            .map(|r| r.body.as_deref().unwrap_or(""))
            .collect();
        assert_eq!(bodies, vec!["msg1", "msg2", "msg3"]);
        assert_eq!(records[0].resource_attributes["svc"], "a");
        assert_eq!(records[2].resource_attributes["svc"], "b");
        assert!(
            records
                .iter()
                .all(|r| r.peer_addr.as_deref() == Some("10.0.0.5"))
        );
        assert!(records.iter().all(|r| r.time.is_some()));
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
            value: Some(AnyVal::DoubleValue(2.5)),
        };
        assert!((any_value_to_json(double_av).as_f64().unwrap() - 2.5_f64).abs() < 1e-9);

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

    #[test]
    fn map_otlp_request_handles_no_body_and_empty_attrs() {
        let r = map_with_body(None);
        assert!(r.body.is_none());
        assert_eq!(r.peer_addr.as_deref(), Some("h"));
        assert_eq!(r.attributes, serde_json::json!({}));
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
