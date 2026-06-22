//! Zeek stream schema registry — typed Arrow schemas for the six curated streams
//! plus a generic envelope fallback for unmodelled stream types.

use arrow::array::{
    ArrayRef, Float64Builder, StringBuilder, UInt16Builder, UInt32Builder, UInt64Builder,
};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A function that maps one JSON record to a one-row RecordBatch.
pub type RowMapper = Arc<dyn Fn(&serde_json::Value) -> anyhow::Result<RecordBatch> + Send + Sync>;

/// A schema paired with its row mapper.
pub struct SchemaEntry {
    pub schema: Arc<Schema>,
    pub mapper: RowMapper,
}

// ---------------------------------------------------------------------------
// Schema definitions
// ---------------------------------------------------------------------------

/// `conn.log` Arrow schema.
/// Note: Zeek JSON uses `id.orig_h` etc.; Arrow column names use `id_orig_h`.
pub fn conn_schema() -> Arc<Schema> {
    static S: LazyLock<Arc<Schema>> = LazyLock::new(|| {
        Arc::new(Schema::new(vec![
            Field::new("ts", DataType::Float64, true),
            Field::new("uid", DataType::Utf8, true),
            Field::new("id_orig_h", DataType::Utf8, true),
            Field::new("id_orig_p", DataType::UInt16, true),
            Field::new("id_resp_h", DataType::Utf8, true),
            Field::new("id_resp_p", DataType::UInt16, true),
            Field::new("proto", DataType::Utf8, true),
            Field::new("service", DataType::Utf8, true),
            Field::new("duration", DataType::Float64, true),
            Field::new("orig_bytes", DataType::UInt64, true),
            Field::new("resp_bytes", DataType::UInt64, true),
            Field::new("conn_state", DataType::Utf8, true),
            Field::new("history", DataType::Utf8, true),
            Field::new("orig_pkts", DataType::UInt64, true),
            Field::new("resp_pkts", DataType::UInt64, true),
            Field::new("_extra", DataType::Utf8, false),
        ]))
    });
    S.clone()
}

/// `dns.log` Arrow schema.
pub fn dns_schema() -> Arc<Schema> {
    static S: LazyLock<Arc<Schema>> = LazyLock::new(|| {
        Arc::new(Schema::new(vec![
            Field::new("ts", DataType::Float64, true),
            Field::new("uid", DataType::Utf8, true),
            Field::new("id_orig_h", DataType::Utf8, true),
            Field::new("id_orig_p", DataType::UInt16, true),
            Field::new("id_resp_h", DataType::Utf8, true),
            Field::new("id_resp_p", DataType::UInt16, true),
            Field::new("proto", DataType::Utf8, true),
            Field::new("trans_id", DataType::UInt32, true),
            Field::new("query", DataType::Utf8, true),
            Field::new("qtype_name", DataType::Utf8, true),
            Field::new("qclass_name", DataType::Utf8, true),
            Field::new("rcode_name", DataType::Utf8, true),
            Field::new("answers", DataType::Utf8, true),
            Field::new("_extra", DataType::Utf8, false),
        ]))
    });
    S.clone()
}

/// `http.log` Arrow schema.
pub fn http_schema() -> Arc<Schema> {
    static S: LazyLock<Arc<Schema>> = LazyLock::new(|| {
        Arc::new(Schema::new(vec![
            Field::new("ts", DataType::Float64, true),
            Field::new("uid", DataType::Utf8, true),
            Field::new("id_orig_h", DataType::Utf8, true),
            Field::new("id_orig_p", DataType::UInt16, true),
            Field::new("id_resp_h", DataType::Utf8, true),
            Field::new("id_resp_p", DataType::UInt16, true),
            Field::new("method", DataType::Utf8, true),
            Field::new("host", DataType::Utf8, true),
            Field::new("uri", DataType::Utf8, true),
            Field::new("status_code", DataType::UInt16, true),
            Field::new("user_agent", DataType::Utf8, true),
            Field::new("request_body_len", DataType::UInt64, true),
            Field::new("response_body_len", DataType::UInt64, true),
            Field::new("_extra", DataType::Utf8, false),
        ]))
    });
    S.clone()
}

/// `ssl.log` Arrow schema.
pub fn ssl_schema() -> Arc<Schema> {
    static S: LazyLock<Arc<Schema>> = LazyLock::new(|| {
        Arc::new(Schema::new(vec![
            Field::new("ts", DataType::Float64, true),
            Field::new("uid", DataType::Utf8, true),
            Field::new("id_orig_h", DataType::Utf8, true),
            Field::new("id_orig_p", DataType::UInt16, true),
            Field::new("id_resp_h", DataType::Utf8, true),
            Field::new("id_resp_p", DataType::UInt16, true),
            Field::new("version", DataType::Utf8, true),
            Field::new("cipher", DataType::Utf8, true),
            Field::new("curve", DataType::Utf8, true),
            Field::new("server_name", DataType::Utf8, true),
            Field::new("validation_status", DataType::Utf8, true),
            Field::new("_extra", DataType::Utf8, false),
        ]))
    });
    S.clone()
}

/// `files.log` Arrow schema.
pub fn files_schema() -> Arc<Schema> {
    static S: LazyLock<Arc<Schema>> = LazyLock::new(|| {
        Arc::new(Schema::new(vec![
            Field::new("ts", DataType::Float64, true),
            Field::new("fuid", DataType::Utf8, true),
            Field::new("tx_hosts", DataType::Utf8, true),
            Field::new("rx_hosts", DataType::Utf8, true),
            Field::new("source", DataType::Utf8, true),
            Field::new("mime_type", DataType::Utf8, true),
            Field::new("filename", DataType::Utf8, true),
            Field::new("total_bytes", DataType::UInt64, true),
            Field::new("_extra", DataType::Utf8, false),
        ]))
    });
    S.clone()
}

/// `notice.log` Arrow schema.
pub fn notice_schema() -> Arc<Schema> {
    static S: LazyLock<Arc<Schema>> = LazyLock::new(|| {
        Arc::new(Schema::new(vec![
            Field::new("ts", DataType::Float64, true),
            Field::new("uid", DataType::Utf8, true),
            Field::new("id_orig_h", DataType::Utf8, true),
            Field::new("id_orig_p", DataType::UInt16, true),
            Field::new("id_resp_h", DataType::Utf8, true),
            Field::new("id_resp_p", DataType::UInt16, true),
            Field::new("note", DataType::Utf8, true),
            Field::new("msg", DataType::Utf8, true),
            Field::new("sub", DataType::Utf8, true),
            Field::new("actions", DataType::Utf8, true),
            Field::new("_extra", DataType::Utf8, false),
        ]))
    });
    S.clone()
}

/// Generic envelope schema for unknown/unmodelled stream types.
pub fn envelope_schema() -> Arc<Schema> {
    static S: LazyLock<Arc<Schema>> = LazyLock::new(|| {
        Arc::new(Schema::new(vec![
            Field::new("ts", DataType::Float64, true),
            Field::new("uid", DataType::Utf8, true),
            Field::new("id_orig_h", DataType::Utf8, true),
            Field::new("id_orig_p", DataType::UInt16, true),
            Field::new("id_resp_h", DataType::Utf8, true),
            Field::new("id_resp_p", DataType::UInt16, true),
            Field::new("log_path", DataType::Utf8, false),
            Field::new("ingest_time", DataType::Utf8, false),
            Field::new("payload", DataType::Utf8, false),
        ]))
    });
    S.clone()
}

// ---------------------------------------------------------------------------
// Row-mapping helpers
// ---------------------------------------------------------------------------

/// Extract a string value from JSON, returning None if absent or wrong type.
fn json_str(v: &serde_json::Value, key: &str) -> Option<String> {
    v.get(key).and_then(|f| f.as_str()).map(|s| s.to_string())
}

/// Extract a float64 value from JSON (accepts number).
fn json_f64(v: &serde_json::Value, key: &str) -> Option<f64> {
    v.get(key).and_then(|f| f.as_f64())
}

/// Extract a u64 value from JSON (accepts non-negative integer).
fn json_u64(v: &serde_json::Value, key: &str) -> Option<u64> {
    v.get(key).and_then(|f| f.as_u64())
}

/// Extract a u16 value from JSON.
fn json_u16(v: &serde_json::Value, key: &str) -> Option<u16> {
    v.get(key)
        .and_then(|f| f.as_u64())
        .and_then(|n| u16::try_from(n).ok())
}

/// Extract a u32 value from JSON.
fn json_u32(v: &serde_json::Value, key: &str) -> Option<u32> {
    v.get(key)
        .and_then(|f| f.as_u64())
        .and_then(|n| u32::try_from(n).ok())
}

/// Extract an array-valued field as a JSON string (for tx_hosts, rx_hosts, answers, actions).
fn json_array_str(v: &serde_json::Value, key: &str) -> Option<String> {
    v.get(key).and_then(|f| {
        if f.is_array() || f.is_string() {
            Some(f.to_string())
        } else {
            None
        }
    })
}

/// Build the `_extra` JSON string: all top-level keys in `value` that are NOT in `promoted`,
/// plus any keys whose values had type mismatches (passed in `mismatch_keys`).
fn build_extra(value: &serde_json::Value, promoted: &[&str], mismatch_keys: &[&str]) -> String {
    let promoted_set: std::collections::HashSet<&str> = promoted.iter().copied().collect();
    let mut extra = serde_json::Map::new();
    if let Some(obj) = value.as_object() {
        for (k, v) in obj {
            if !promoted_set.contains(k.as_str()) || mismatch_keys.contains(&k.as_str()) {
                extra.insert(k.clone(), v.clone());
            }
        }
    }
    serde_json::Value::Object(extra).to_string()
}

// ---------------------------------------------------------------------------
// Per-stream row mappers
// ---------------------------------------------------------------------------

fn map_conn(value: &serde_json::Value) -> anyhow::Result<RecordBatch> {
    let schema = conn_schema();
    // Promoted JSON keys (Zeek dot-notation for id fields)
    let promoted = &[
        "ts",
        "uid",
        "id.orig_h",
        "id.orig_p",
        "id.resp_h",
        "id.resp_p",
        "proto",
        "service",
        "duration",
        "orig_bytes",
        "resp_bytes",
        "conn_state",
        "history",
        "orig_pkts",
        "resp_pkts",
    ];

    let mut mismatches: Vec<&str> = Vec::new();

    // Extract each field; record mismatch if present but wrong type.
    let ts = json_f64(value, "ts");
    if value.get("ts").is_some() && ts.is_none() {
        mismatches.push("ts");
    }

    let uid = json_str(value, "uid");
    if value.get("uid").is_some() && uid.is_none() {
        mismatches.push("uid");
    }
    let id_orig_h = json_str(value, "id.orig_h");
    if value.get("id.orig_h").is_some() && id_orig_h.is_none() {
        mismatches.push("id.orig_h");
    }
    let id_orig_p = json_u16(value, "id.orig_p");
    if value.get("id.orig_p").is_some() && id_orig_p.is_none() {
        mismatches.push("id.orig_p");
    }
    let id_resp_h = json_str(value, "id.resp_h");
    if value.get("id.resp_h").is_some() && id_resp_h.is_none() {
        mismatches.push("id.resp_h");
    }
    let id_resp_p = json_u16(value, "id.resp_p");
    if value.get("id.resp_p").is_some() && id_resp_p.is_none() {
        mismatches.push("id.resp_p");
    }
    let proto = json_str(value, "proto");
    if value.get("proto").is_some() && proto.is_none() {
        mismatches.push("proto");
    }
    let service = json_str(value, "service");
    if value.get("service").is_some() && service.is_none() {
        mismatches.push("service");
    }
    let duration = json_f64(value, "duration");
    if value.get("duration").is_some() && duration.is_none() {
        mismatches.push("duration");
    }
    let orig_bytes = json_u64(value, "orig_bytes");
    if value.get("orig_bytes").is_some() && orig_bytes.is_none() {
        mismatches.push("orig_bytes");
    }
    let resp_bytes = json_u64(value, "resp_bytes");
    if value.get("resp_bytes").is_some() && resp_bytes.is_none() {
        mismatches.push("resp_bytes");
    }
    let conn_state = json_str(value, "conn_state");
    if value.get("conn_state").is_some() && conn_state.is_none() {
        mismatches.push("conn_state");
    }
    let history = json_str(value, "history");
    if value.get("history").is_some() && history.is_none() {
        mismatches.push("history");
    }
    let orig_pkts = json_u64(value, "orig_pkts");
    if value.get("orig_pkts").is_some() && orig_pkts.is_none() {
        mismatches.push("orig_pkts");
    }
    let resp_pkts = json_u64(value, "resp_pkts");
    if value.get("resp_pkts").is_some() && resp_pkts.is_none() {
        mismatches.push("resp_pkts");
    }

    let extra = build_extra(value, promoted, &mismatches);

    let mut b_ts = Float64Builder::new();
    let mut b_uid = StringBuilder::new();
    let mut b_id_orig_h = StringBuilder::new();
    let mut b_id_orig_p = UInt16Builder::new();
    let mut b_id_resp_h = StringBuilder::new();
    let mut b_id_resp_p = UInt16Builder::new();
    let mut b_proto = StringBuilder::new();
    let mut b_service = StringBuilder::new();
    let mut b_duration = Float64Builder::new();
    let mut b_orig_bytes = UInt64Builder::new();
    let mut b_resp_bytes = UInt64Builder::new();
    let mut b_conn_state = StringBuilder::new();
    let mut b_history = StringBuilder::new();
    let mut b_orig_pkts = UInt64Builder::new();
    let mut b_resp_pkts = UInt64Builder::new();
    let mut b_extra = StringBuilder::new();

    b_ts.append_option(ts);
    b_uid.append_option(uid.as_deref());
    b_id_orig_h.append_option(id_orig_h.as_deref());
    b_id_orig_p.append_option(id_orig_p);
    b_id_resp_h.append_option(id_resp_h.as_deref());
    b_id_resp_p.append_option(id_resp_p);
    b_proto.append_option(proto.as_deref());
    b_service.append_option(service.as_deref());
    b_duration.append_option(duration);
    b_orig_bytes.append_option(orig_bytes);
    b_resp_bytes.append_option(resp_bytes);
    b_conn_state.append_option(conn_state.as_deref());
    b_history.append_option(history.as_deref());
    b_orig_pkts.append_option(orig_pkts);
    b_resp_pkts.append_option(resp_pkts);
    b_extra.append_value(&extra);

    let columns: Vec<ArrayRef> = vec![
        Arc::new(b_ts.finish()),
        Arc::new(b_uid.finish()),
        Arc::new(b_id_orig_h.finish()),
        Arc::new(b_id_orig_p.finish()),
        Arc::new(b_id_resp_h.finish()),
        Arc::new(b_id_resp_p.finish()),
        Arc::new(b_proto.finish()),
        Arc::new(b_service.finish()),
        Arc::new(b_duration.finish()),
        Arc::new(b_orig_bytes.finish()),
        Arc::new(b_resp_bytes.finish()),
        Arc::new(b_conn_state.finish()),
        Arc::new(b_history.finish()),
        Arc::new(b_orig_pkts.finish()),
        Arc::new(b_resp_pkts.finish()),
        Arc::new(b_extra.finish()),
    ];
    Ok(RecordBatch::try_new(schema, columns)?)
}

fn map_dns(value: &serde_json::Value) -> anyhow::Result<RecordBatch> {
    let schema = dns_schema();
    let promoted = &[
        "ts",
        "uid",
        "id.orig_h",
        "id.orig_p",
        "id.resp_h",
        "id.resp_p",
        "proto",
        "trans_id",
        "query",
        "qtype_name",
        "qclass_name",
        "rcode_name",
        "answers",
    ];
    let mut mismatches: Vec<&str> = Vec::new();

    let ts = json_f64(value, "ts");
    if value.get("ts").is_some() && ts.is_none() {
        mismatches.push("ts");
    }
    let uid = json_str(value, "uid");
    if value.get("uid").is_some() && uid.is_none() {
        mismatches.push("uid");
    }
    let id_orig_h = json_str(value, "id.orig_h");
    if value.get("id.orig_h").is_some() && id_orig_h.is_none() {
        mismatches.push("id.orig_h");
    }
    let id_orig_p = json_u16(value, "id.orig_p");
    if value.get("id.orig_p").is_some() && id_orig_p.is_none() {
        mismatches.push("id.orig_p");
    }
    let id_resp_h = json_str(value, "id.resp_h");
    if value.get("id.resp_h").is_some() && id_resp_h.is_none() {
        mismatches.push("id.resp_h");
    }
    let id_resp_p = json_u16(value, "id.resp_p");
    if value.get("id.resp_p").is_some() && id_resp_p.is_none() {
        mismatches.push("id.resp_p");
    }
    let proto = json_str(value, "proto");
    if value.get("proto").is_some() && proto.is_none() {
        mismatches.push("proto");
    }
    let trans_id = json_u32(value, "trans_id");
    if value.get("trans_id").is_some() && trans_id.is_none() {
        mismatches.push("trans_id");
    }
    let query = json_str(value, "query");
    if value.get("query").is_some() && query.is_none() {
        mismatches.push("query");
    }
    let qtype_name = json_str(value, "qtype_name");
    if value.get("qtype_name").is_some() && qtype_name.is_none() {
        mismatches.push("qtype_name");
    }
    let qclass_name = json_str(value, "qclass_name");
    if value.get("qclass_name").is_some() && qclass_name.is_none() {
        mismatches.push("qclass_name");
    }
    let rcode_name = json_str(value, "rcode_name");
    if value.get("rcode_name").is_some() && rcode_name.is_none() {
        mismatches.push("rcode_name");
    }
    let answers = json_array_str(value, "answers");
    if value.get("answers").is_some() && answers.is_none() {
        mismatches.push("answers");
    }

    let extra = build_extra(value, promoted, &mismatches);

    let mut b_ts = Float64Builder::new();
    let mut b_uid = StringBuilder::new();
    let mut b_id_orig_h = StringBuilder::new();
    let mut b_id_orig_p = UInt16Builder::new();
    let mut b_id_resp_h = StringBuilder::new();
    let mut b_id_resp_p = UInt16Builder::new();
    let mut b_proto = StringBuilder::new();
    let mut b_trans_id = UInt32Builder::new();
    let mut b_query = StringBuilder::new();
    let mut b_qtype_name = StringBuilder::new();
    let mut b_qclass_name = StringBuilder::new();
    let mut b_rcode_name = StringBuilder::new();
    let mut b_answers = StringBuilder::new();
    let mut b_extra = StringBuilder::new();

    b_ts.append_option(ts);
    b_uid.append_option(uid.as_deref());
    b_id_orig_h.append_option(id_orig_h.as_deref());
    b_id_orig_p.append_option(id_orig_p);
    b_id_resp_h.append_option(id_resp_h.as_deref());
    b_id_resp_p.append_option(id_resp_p);
    b_proto.append_option(proto.as_deref());
    b_trans_id.append_option(trans_id);
    b_query.append_option(query.as_deref());
    b_qtype_name.append_option(qtype_name.as_deref());
    b_qclass_name.append_option(qclass_name.as_deref());
    b_rcode_name.append_option(rcode_name.as_deref());
    b_answers.append_option(answers.as_deref());
    b_extra.append_value(&extra);

    let columns: Vec<ArrayRef> = vec![
        Arc::new(b_ts.finish()),
        Arc::new(b_uid.finish()),
        Arc::new(b_id_orig_h.finish()),
        Arc::new(b_id_orig_p.finish()),
        Arc::new(b_id_resp_h.finish()),
        Arc::new(b_id_resp_p.finish()),
        Arc::new(b_proto.finish()),
        Arc::new(b_trans_id.finish()),
        Arc::new(b_query.finish()),
        Arc::new(b_qtype_name.finish()),
        Arc::new(b_qclass_name.finish()),
        Arc::new(b_rcode_name.finish()),
        Arc::new(b_answers.finish()),
        Arc::new(b_extra.finish()),
    ];
    Ok(RecordBatch::try_new(schema, columns)?)
}

fn map_http(value: &serde_json::Value) -> anyhow::Result<RecordBatch> {
    let schema = http_schema();
    let promoted = &[
        "ts",
        "uid",
        "id.orig_h",
        "id.orig_p",
        "id.resp_h",
        "id.resp_p",
        "method",
        "host",
        "uri",
        "status_code",
        "user_agent",
        "request_body_len",
        "response_body_len",
    ];
    let mut mismatches: Vec<&str> = Vec::new();

    let ts = json_f64(value, "ts");
    if value.get("ts").is_some() && ts.is_none() {
        mismatches.push("ts");
    }
    let uid = json_str(value, "uid");
    if value.get("uid").is_some() && uid.is_none() {
        mismatches.push("uid");
    }
    let id_orig_h = json_str(value, "id.orig_h");
    if value.get("id.orig_h").is_some() && id_orig_h.is_none() {
        mismatches.push("id.orig_h");
    }
    let id_orig_p = json_u16(value, "id.orig_p");
    if value.get("id.orig_p").is_some() && id_orig_p.is_none() {
        mismatches.push("id.orig_p");
    }
    let id_resp_h = json_str(value, "id.resp_h");
    if value.get("id.resp_h").is_some() && id_resp_h.is_none() {
        mismatches.push("id.resp_h");
    }
    let id_resp_p = json_u16(value, "id.resp_p");
    if value.get("id.resp_p").is_some() && id_resp_p.is_none() {
        mismatches.push("id.resp_p");
    }
    let method = json_str(value, "method");
    if value.get("method").is_some() && method.is_none() {
        mismatches.push("method");
    }
    let host = json_str(value, "host");
    if value.get("host").is_some() && host.is_none() {
        mismatches.push("host");
    }
    let uri = json_str(value, "uri");
    if value.get("uri").is_some() && uri.is_none() {
        mismatches.push("uri");
    }
    let status_code = json_u16(value, "status_code");
    if value.get("status_code").is_some() && status_code.is_none() {
        mismatches.push("status_code");
    }
    let user_agent = json_str(value, "user_agent");
    if value.get("user_agent").is_some() && user_agent.is_none() {
        mismatches.push("user_agent");
    }
    let request_body_len = json_u64(value, "request_body_len");
    if value.get("request_body_len").is_some() && request_body_len.is_none() {
        mismatches.push("request_body_len");
    }
    let response_body_len = json_u64(value, "response_body_len");
    if value.get("response_body_len").is_some() && response_body_len.is_none() {
        mismatches.push("response_body_len");
    }

    let extra = build_extra(value, promoted, &mismatches);

    let mut b_ts = Float64Builder::new();
    let mut b_uid = StringBuilder::new();
    let mut b_id_orig_h = StringBuilder::new();
    let mut b_id_orig_p = UInt16Builder::new();
    let mut b_id_resp_h = StringBuilder::new();
    let mut b_id_resp_p = UInt16Builder::new();
    let mut b_method = StringBuilder::new();
    let mut b_host = StringBuilder::new();
    let mut b_uri = StringBuilder::new();
    let mut b_status_code = UInt16Builder::new();
    let mut b_user_agent = StringBuilder::new();
    let mut b_request_body_len = UInt64Builder::new();
    let mut b_response_body_len = UInt64Builder::new();
    let mut b_extra = StringBuilder::new();

    b_ts.append_option(ts);
    b_uid.append_option(uid.as_deref());
    b_id_orig_h.append_option(id_orig_h.as_deref());
    b_id_orig_p.append_option(id_orig_p);
    b_id_resp_h.append_option(id_resp_h.as_deref());
    b_id_resp_p.append_option(id_resp_p);
    b_method.append_option(method.as_deref());
    b_host.append_option(host.as_deref());
    b_uri.append_option(uri.as_deref());
    b_status_code.append_option(status_code);
    b_user_agent.append_option(user_agent.as_deref());
    b_request_body_len.append_option(request_body_len);
    b_response_body_len.append_option(response_body_len);
    b_extra.append_value(&extra);

    let columns: Vec<ArrayRef> = vec![
        Arc::new(b_ts.finish()),
        Arc::new(b_uid.finish()),
        Arc::new(b_id_orig_h.finish()),
        Arc::new(b_id_orig_p.finish()),
        Arc::new(b_id_resp_h.finish()),
        Arc::new(b_id_resp_p.finish()),
        Arc::new(b_method.finish()),
        Arc::new(b_host.finish()),
        Arc::new(b_uri.finish()),
        Arc::new(b_status_code.finish()),
        Arc::new(b_user_agent.finish()),
        Arc::new(b_request_body_len.finish()),
        Arc::new(b_response_body_len.finish()),
        Arc::new(b_extra.finish()),
    ];
    Ok(RecordBatch::try_new(schema, columns)?)
}

fn map_ssl(value: &serde_json::Value) -> anyhow::Result<RecordBatch> {
    let schema = ssl_schema();
    let promoted = &[
        "ts",
        "uid",
        "id.orig_h",
        "id.orig_p",
        "id.resp_h",
        "id.resp_p",
        "version",
        "cipher",
        "curve",
        "server_name",
        "validation_status",
    ];
    let mut mismatches: Vec<&str> = Vec::new();

    let ts = json_f64(value, "ts");
    if value.get("ts").is_some() && ts.is_none() {
        mismatches.push("ts");
    }
    let uid = json_str(value, "uid");
    if value.get("uid").is_some() && uid.is_none() {
        mismatches.push("uid");
    }
    let id_orig_h = json_str(value, "id.orig_h");
    if value.get("id.orig_h").is_some() && id_orig_h.is_none() {
        mismatches.push("id.orig_h");
    }
    let id_orig_p = json_u16(value, "id.orig_p");
    if value.get("id.orig_p").is_some() && id_orig_p.is_none() {
        mismatches.push("id.orig_p");
    }
    let id_resp_h = json_str(value, "id.resp_h");
    if value.get("id.resp_h").is_some() && id_resp_h.is_none() {
        mismatches.push("id.resp_h");
    }
    let id_resp_p = json_u16(value, "id.resp_p");
    if value.get("id.resp_p").is_some() && id_resp_p.is_none() {
        mismatches.push("id.resp_p");
    }
    let version = json_str(value, "version");
    if value.get("version").is_some() && version.is_none() {
        mismatches.push("version");
    }
    let cipher = json_str(value, "cipher");
    if value.get("cipher").is_some() && cipher.is_none() {
        mismatches.push("cipher");
    }
    let curve = json_str(value, "curve");
    if value.get("curve").is_some() && curve.is_none() {
        mismatches.push("curve");
    }
    let server_name = json_str(value, "server_name");
    if value.get("server_name").is_some() && server_name.is_none() {
        mismatches.push("server_name");
    }
    let validation_status = json_str(value, "validation_status");
    if value.get("validation_status").is_some() && validation_status.is_none() {
        mismatches.push("validation_status");
    }

    let extra = build_extra(value, promoted, &mismatches);

    let mut b_ts = Float64Builder::new();
    let mut b_uid = StringBuilder::new();
    let mut b_id_orig_h = StringBuilder::new();
    let mut b_id_orig_p = UInt16Builder::new();
    let mut b_id_resp_h = StringBuilder::new();
    let mut b_id_resp_p = UInt16Builder::new();
    let mut b_version = StringBuilder::new();
    let mut b_cipher = StringBuilder::new();
    let mut b_curve = StringBuilder::new();
    let mut b_server_name = StringBuilder::new();
    let mut b_validation_status = StringBuilder::new();
    let mut b_extra = StringBuilder::new();

    b_ts.append_option(ts);
    b_uid.append_option(uid.as_deref());
    b_id_orig_h.append_option(id_orig_h.as_deref());
    b_id_orig_p.append_option(id_orig_p);
    b_id_resp_h.append_option(id_resp_h.as_deref());
    b_id_resp_p.append_option(id_resp_p);
    b_version.append_option(version.as_deref());
    b_cipher.append_option(cipher.as_deref());
    b_curve.append_option(curve.as_deref());
    b_server_name.append_option(server_name.as_deref());
    b_validation_status.append_option(validation_status.as_deref());
    b_extra.append_value(&extra);

    let columns: Vec<ArrayRef> = vec![
        Arc::new(b_ts.finish()),
        Arc::new(b_uid.finish()),
        Arc::new(b_id_orig_h.finish()),
        Arc::new(b_id_orig_p.finish()),
        Arc::new(b_id_resp_h.finish()),
        Arc::new(b_id_resp_p.finish()),
        Arc::new(b_version.finish()),
        Arc::new(b_cipher.finish()),
        Arc::new(b_curve.finish()),
        Arc::new(b_server_name.finish()),
        Arc::new(b_validation_status.finish()),
        Arc::new(b_extra.finish()),
    ];
    Ok(RecordBatch::try_new(schema, columns)?)
}

fn map_files(value: &serde_json::Value) -> anyhow::Result<RecordBatch> {
    let schema = files_schema();
    let promoted = &[
        "ts",
        "fuid",
        "tx_hosts",
        "rx_hosts",
        "source",
        "mime_type",
        "filename",
        "total_bytes",
    ];
    let mut mismatches: Vec<&str> = Vec::new();

    let ts = json_f64(value, "ts");
    if value.get("ts").is_some() && ts.is_none() {
        mismatches.push("ts");
    }
    let fuid = json_str(value, "fuid");
    if value.get("fuid").is_some() && fuid.is_none() {
        mismatches.push("fuid");
    }
    let tx_hosts = json_array_str(value, "tx_hosts");
    if value.get("tx_hosts").is_some() && tx_hosts.is_none() {
        mismatches.push("tx_hosts");
    }
    let rx_hosts = json_array_str(value, "rx_hosts");
    if value.get("rx_hosts").is_some() && rx_hosts.is_none() {
        mismatches.push("rx_hosts");
    }
    let source = json_str(value, "source");
    if value.get("source").is_some() && source.is_none() {
        mismatches.push("source");
    }
    let mime_type = json_str(value, "mime_type");
    if value.get("mime_type").is_some() && mime_type.is_none() {
        mismatches.push("mime_type");
    }
    let filename = json_str(value, "filename");
    if value.get("filename").is_some() && filename.is_none() {
        mismatches.push("filename");
    }
    let total_bytes = json_u64(value, "total_bytes");
    if value.get("total_bytes").is_some() && total_bytes.is_none() {
        mismatches.push("total_bytes");
    }

    let extra = build_extra(value, promoted, &mismatches);

    let mut b_ts = Float64Builder::new();
    let mut b_fuid = StringBuilder::new();
    let mut b_tx_hosts = StringBuilder::new();
    let mut b_rx_hosts = StringBuilder::new();
    let mut b_source = StringBuilder::new();
    let mut b_mime_type = StringBuilder::new();
    let mut b_filename = StringBuilder::new();
    let mut b_total_bytes = UInt64Builder::new();
    let mut b_extra = StringBuilder::new();

    b_ts.append_option(ts);
    b_fuid.append_option(fuid.as_deref());
    b_tx_hosts.append_option(tx_hosts.as_deref());
    b_rx_hosts.append_option(rx_hosts.as_deref());
    b_source.append_option(source.as_deref());
    b_mime_type.append_option(mime_type.as_deref());
    b_filename.append_option(filename.as_deref());
    b_total_bytes.append_option(total_bytes);
    b_extra.append_value(&extra);

    let columns: Vec<ArrayRef> = vec![
        Arc::new(b_ts.finish()),
        Arc::new(b_fuid.finish()),
        Arc::new(b_tx_hosts.finish()),
        Arc::new(b_rx_hosts.finish()),
        Arc::new(b_source.finish()),
        Arc::new(b_mime_type.finish()),
        Arc::new(b_filename.finish()),
        Arc::new(b_total_bytes.finish()),
        Arc::new(b_extra.finish()),
    ];
    Ok(RecordBatch::try_new(schema, columns)?)
}

fn map_notice(value: &serde_json::Value) -> anyhow::Result<RecordBatch> {
    let schema = notice_schema();
    let promoted = &[
        "ts",
        "uid",
        "id.orig_h",
        "id.orig_p",
        "id.resp_h",
        "id.resp_p",
        "note",
        "msg",
        "sub",
        "actions",
    ];
    let mut mismatches: Vec<&str> = Vec::new();

    let ts = json_f64(value, "ts");
    if value.get("ts").is_some() && ts.is_none() {
        mismatches.push("ts");
    }
    let uid = json_str(value, "uid");
    if value.get("uid").is_some() && uid.is_none() {
        mismatches.push("uid");
    }
    let id_orig_h = json_str(value, "id.orig_h");
    if value.get("id.orig_h").is_some() && id_orig_h.is_none() {
        mismatches.push("id.orig_h");
    }
    let id_orig_p = json_u16(value, "id.orig_p");
    if value.get("id.orig_p").is_some() && id_orig_p.is_none() {
        mismatches.push("id.orig_p");
    }
    let id_resp_h = json_str(value, "id.resp_h");
    if value.get("id.resp_h").is_some() && id_resp_h.is_none() {
        mismatches.push("id.resp_h");
    }
    let id_resp_p = json_u16(value, "id.resp_p");
    if value.get("id.resp_p").is_some() && id_resp_p.is_none() {
        mismatches.push("id.resp_p");
    }
    let note = json_str(value, "note");
    if value.get("note").is_some() && note.is_none() {
        mismatches.push("note");
    }
    let msg = json_str(value, "msg");
    if value.get("msg").is_some() && msg.is_none() {
        mismatches.push("msg");
    }
    let sub = json_str(value, "sub");
    if value.get("sub").is_some() && sub.is_none() {
        mismatches.push("sub");
    }
    let actions = json_array_str(value, "actions");
    if value.get("actions").is_some() && actions.is_none() {
        mismatches.push("actions");
    }

    let extra = build_extra(value, promoted, &mismatches);

    let mut b_ts = Float64Builder::new();
    let mut b_uid = StringBuilder::new();
    let mut b_id_orig_h = StringBuilder::new();
    let mut b_id_orig_p = UInt16Builder::new();
    let mut b_id_resp_h = StringBuilder::new();
    let mut b_id_resp_p = UInt16Builder::new();
    let mut b_note = StringBuilder::new();
    let mut b_msg = StringBuilder::new();
    let mut b_sub = StringBuilder::new();
    let mut b_actions = StringBuilder::new();
    let mut b_extra = StringBuilder::new();

    b_ts.append_option(ts);
    b_uid.append_option(uid.as_deref());
    b_id_orig_h.append_option(id_orig_h.as_deref());
    b_id_orig_p.append_option(id_orig_p);
    b_id_resp_h.append_option(id_resp_h.as_deref());
    b_id_resp_p.append_option(id_resp_p);
    b_note.append_option(note.as_deref());
    b_msg.append_option(msg.as_deref());
    b_sub.append_option(sub.as_deref());
    b_actions.append_option(actions.as_deref());
    b_extra.append_value(&extra);

    let columns: Vec<ArrayRef> = vec![
        Arc::new(b_ts.finish()),
        Arc::new(b_uid.finish()),
        Arc::new(b_id_orig_h.finish()),
        Arc::new(b_id_orig_p.finish()),
        Arc::new(b_id_resp_h.finish()),
        Arc::new(b_id_resp_p.finish()),
        Arc::new(b_note.finish()),
        Arc::new(b_msg.finish()),
        Arc::new(b_sub.finish()),
        Arc::new(b_actions.finish()),
        Arc::new(b_extra.finish()),
    ];
    Ok(RecordBatch::try_new(schema, columns)?)
}

fn map_envelope(value: &serde_json::Value, log_path: &str) -> anyhow::Result<RecordBatch> {
    let schema = envelope_schema();

    let ts = json_f64(value, "ts");
    let uid = json_str(value, "uid");
    let id_orig_h = json_str(value, "id.orig_h");
    let id_orig_p = json_u16(value, "id.orig_p");
    let id_resp_h = json_str(value, "id.resp_h");
    let id_resp_p = json_u16(value, "id.resp_p");
    let ingest_time = chrono::Utc::now().to_rfc3339();
    let payload = value.to_string();

    let mut b_ts = Float64Builder::new();
    let mut b_uid = StringBuilder::new();
    let mut b_id_orig_h = StringBuilder::new();
    let mut b_id_orig_p = UInt16Builder::new();
    let mut b_id_resp_h = StringBuilder::new();
    let mut b_id_resp_p = UInt16Builder::new();
    let mut b_log_path = StringBuilder::new();
    let mut b_ingest_time = StringBuilder::new();
    let mut b_payload = StringBuilder::new();

    b_ts.append_option(ts);
    b_uid.append_option(uid.as_deref());
    b_id_orig_h.append_option(id_orig_h.as_deref());
    b_id_orig_p.append_option(id_orig_p);
    b_id_resp_h.append_option(id_resp_h.as_deref());
    b_id_resp_p.append_option(id_resp_p);
    b_log_path.append_value(log_path);
    b_ingest_time.append_value(&ingest_time);
    b_payload.append_value(&payload);

    let columns: Vec<ArrayRef> = vec![
        Arc::new(b_ts.finish()),
        Arc::new(b_uid.finish()),
        Arc::new(b_id_orig_h.finish()),
        Arc::new(b_id_orig_p.finish()),
        Arc::new(b_id_resp_h.finish()),
        Arc::new(b_id_resp_p.finish()),
        Arc::new(b_log_path.finish()),
        Arc::new(b_ingest_time.finish()),
        Arc::new(b_payload.finish()),
    ];
    Ok(RecordBatch::try_new(schema, columns)?)
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

static REGISTRY: LazyLock<HashMap<&'static str, Arc<SchemaEntry>>> = LazyLock::new(|| {
    let mut m: HashMap<&'static str, Arc<SchemaEntry>> = HashMap::new();

    m.insert(
        "conn",
        Arc::new(SchemaEntry {
            schema: conn_schema(),
            mapper: Arc::new(map_conn),
        }),
    );
    m.insert(
        "dns",
        Arc::new(SchemaEntry {
            schema: dns_schema(),
            mapper: Arc::new(map_dns),
        }),
    );
    m.insert(
        "http",
        Arc::new(SchemaEntry {
            schema: http_schema(),
            mapper: Arc::new(map_http),
        }),
    );
    m.insert(
        "ssl",
        Arc::new(SchemaEntry {
            schema: ssl_schema(),
            mapper: Arc::new(map_ssl),
        }),
    );
    m.insert(
        "files",
        Arc::new(SchemaEntry {
            schema: files_schema(),
            mapper: Arc::new(map_files),
        }),
    );
    m.insert(
        "notice",
        Arc::new(SchemaEntry {
            schema: notice_schema(),
            mapper: Arc::new(map_notice),
        }),
    );
    m
});

/// Look up the SchemaEntry for `log_path`. Falls back to the envelope schema for unknown paths.
/// The envelope mapper always uses the actual `log_path` at call time via a wrapper.
pub fn get_schema_entry(log_path: &str) -> Arc<SchemaEntry> {
    if let Some(entry) = REGISTRY.get(log_path) {
        return entry.clone();
    }
    // For unknown paths, build a fresh SchemaEntry with the actual log_path captured.
    let path = log_path.to_string();
    Arc::new(SchemaEntry {
        schema: envelope_schema(),
        mapper: Arc::new(move |v| map_envelope(v, &path)),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use arrow::array::{Array, Float64Array, StringArray, UInt16Array, UInt64Array};

    // --- conn schema tests ---

    #[test]
    fn conn_schema_has_correct_fields() {
        let s = conn_schema();
        assert_eq!(s.fields().len(), 16);
        let f = s.field_with_name("ts").unwrap();
        assert_eq!(*f.data_type(), DataType::Float64);
        assert!(f.is_nullable());
        let f = s.field_with_name("_extra").unwrap();
        assert_eq!(*f.data_type(), DataType::Utf8);
        assert!(!f.is_nullable()); // _extra is never null
        s.field_with_name("id_orig_h")
            .expect("id_orig_h must exist");
        s.field_with_name("orig_pkts")
            .expect("orig_pkts must exist");
    }

    #[test]
    fn conn_mapper_extracts_all_typed_fields() {
        let json = serde_json::json!({
            "_path": "conn",
            "ts": 1700000000.123,
            "uid": "CTestConn1",
            "id.orig_h": "10.0.0.1",
            "id.orig_p": 54321,
            "id.resp_h": "93.184.216.34",
            "id.resp_p": 80,
            "proto": "tcp",
            "service": "http",
            "duration": 0.254,
            "orig_bytes": 512,
            "resp_bytes": 4096,
            "conn_state": "SF",
            "history": "ShADadFf",
            "orig_pkts": 10,
            "resp_pkts": 15
        });
        let batch = map_conn(&json).unwrap();
        assert_eq!(batch.num_rows(), 1);
        assert_eq!(batch.num_columns(), 16);

        let uid = batch
            .column_by_name("uid")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(uid.value(0), "CTestConn1");

        let ts = batch
            .column_by_name("ts")
            .unwrap()
            .as_any()
            .downcast_ref::<Float64Array>()
            .unwrap();
        assert!((ts.value(0) - 1700000000.123).abs() < 0.001);

        let orig_p = batch
            .column_by_name("id_orig_p")
            .unwrap()
            .as_any()
            .downcast_ref::<UInt16Array>()
            .unwrap();
        assert_eq!(orig_p.value(0), 54321u16);

        let orig_bytes = batch
            .column_by_name("orig_bytes")
            .unwrap()
            .as_any()
            .downcast_ref::<UInt64Array>()
            .unwrap();
        assert_eq!(orig_bytes.value(0), 512u64);

        // _extra should be empty object (all promoted fields consumed)
        let extra = batch
            .column_by_name("_extra")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let extra_val: serde_json::Value = serde_json::from_str(extra.value(0)).unwrap();
        // _path is not promoted so it appears in _extra
        assert!(
            extra_val.get("_path").is_some(),
            "_path should go to _extra"
        );
    }

    #[test]
    fn conn_mapper_null_for_absent_fields() {
        let json = serde_json::json!({"_path": "conn", "uid": "CMinimal"});
        let batch = map_conn(&json).unwrap();
        let ts = batch
            .column_by_name("ts")
            .unwrap()
            .as_any()
            .downcast_ref::<Float64Array>()
            .unwrap();
        assert!(ts.is_null(0), "absent ts should be null");
        let orig_bytes = batch
            .column_by_name("orig_bytes")
            .unwrap()
            .as_any()
            .downcast_ref::<UInt64Array>()
            .unwrap();
        assert!(orig_bytes.is_null(0), "absent orig_bytes should be null");
    }

    #[test]
    fn conn_mapper_type_mismatch_goes_to_extra() {
        // orig_bytes is a string instead of number — should go to _extra, column null
        let json = serde_json::json!({
            "_path": "conn",
            "uid": "CMismatch",
            "ts": 1700000000.0,
            "orig_bytes": "not-a-number"
        });
        let batch = map_conn(&json).unwrap();
        let orig_bytes = batch
            .column_by_name("orig_bytes")
            .unwrap()
            .as_any()
            .downcast_ref::<UInt64Array>()
            .unwrap();
        assert!(
            orig_bytes.is_null(0),
            "type-mismatched orig_bytes must be null in typed column"
        );
        let extra = batch
            .column_by_name("_extra")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let extra_val: serde_json::Value = serde_json::from_str(extra.value(0)).unwrap();
        assert!(
            extra_val.get("orig_bytes").is_some(),
            "type-mismatched orig_bytes must appear in _extra"
        );
    }

    // --- dns schema tests ---

    #[test]
    fn dns_schema_has_correct_fields() {
        let s = dns_schema();
        assert_eq!(s.fields().len(), 14);
        s.field_with_name("trans_id").expect("trans_id must exist");
        s.field_with_name("answers").expect("answers must exist");
        let f = s.field_with_name("trans_id").unwrap();
        assert_eq!(*f.data_type(), DataType::UInt32);
    }

    #[test]
    fn dns_mapper_extracts_typed_fields() {
        let json = serde_json::json!({
            "_path": "dns",
            "ts": 1700000100.0,
            "uid": "CDns1",
            "id.orig_h": "192.168.1.100",
            "id.orig_p": 12345,
            "id.resp_h": "8.8.8.8",
            "id.resp_p": 53,
            "proto": "udp",
            "trans_id": 12345,
            "query": "example.com",
            "qtype_name": "A",
            "qclass_name": "C_INTERNET",
            "rcode_name": "NOERROR",
            "answers": ["93.184.216.34"]
        });
        let batch = map_dns(&json).unwrap();
        assert_eq!(batch.num_rows(), 1);
        let query = batch
            .column_by_name("query")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(query.value(0), "example.com");
        let trans_id = batch
            .column_by_name("trans_id")
            .unwrap()
            .as_any()
            .downcast_ref::<arrow::array::UInt32Array>()
            .unwrap();
        assert_eq!(trans_id.value(0), 12345u32);
        // answers is an array — stored as JSON string
        let answers = batch
            .column_by_name("answers")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert!(answers.value(0).contains("93.184.216.34"));
    }

    // --- http schema tests ---

    #[test]
    fn http_mapper_extracts_status_code_and_uri() {
        let json = serde_json::json!({
            "_path": "http",
            "ts": 1700000200.0,
            "uid": "CHttpTest",
            "id.orig_h": "10.0.0.5",
            "id.orig_p": 49123,
            "id.resp_h": "1.2.3.4",
            "id.resp_p": 80,
            "method": "GET",
            "host": "example.com",
            "uri": "/index.html",
            "status_code": 200,
            "user_agent": "curl/7.68.0",
            "request_body_len": 0,
            "response_body_len": 4096
        });
        let batch = map_http(&json).unwrap();
        let status = batch
            .column_by_name("status_code")
            .unwrap()
            .as_any()
            .downcast_ref::<UInt16Array>()
            .unwrap();
        assert_eq!(status.value(0), 200u16);
        let uri = batch
            .column_by_name("uri")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(uri.value(0), "/index.html");
    }

    // --- ssl schema tests ---

    #[test]
    fn ssl_mapper_extracts_server_name_and_cipher() {
        let json = serde_json::json!({
            "_path": "ssl",
            "ts": 1700000300.0,
            "uid": "CSslTest",
            "id.orig_h": "10.0.0.6",
            "id.orig_p": 55001,
            "id.resp_h": "1.2.3.5",
            "id.resp_p": 443,
            "version": "TLSv13",
            "cipher": "TLS_AES_128_GCM_SHA256",
            "curve": "x25519",
            "server_name": "secure.example.com",
            "validation_status": "ok"
        });
        let batch = map_ssl(&json).unwrap();
        let sn = batch
            .column_by_name("server_name")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(sn.value(0), "secure.example.com");
        let cipher = batch
            .column_by_name("cipher")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(cipher.value(0), "TLS_AES_128_GCM_SHA256");
    }

    // --- files schema tests ---

    #[test]
    fn files_mapper_extracts_mime_type_and_total_bytes() {
        let json = serde_json::json!({
            "_path": "files",
            "ts": 1700000400.0,
            "fuid": "FTest001",
            "tx_hosts": ["10.0.0.7"],
            "rx_hosts": ["192.168.0.1"],
            "source": "HTTP",
            "mime_type": "application/pdf",
            "filename": "report.pdf",
            "total_bytes": 102400
        });
        let batch = map_files(&json).unwrap();
        let mime = batch
            .column_by_name("mime_type")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(mime.value(0), "application/pdf");
        let total = batch
            .column_by_name("total_bytes")
            .unwrap()
            .as_any()
            .downcast_ref::<UInt64Array>()
            .unwrap();
        assert_eq!(total.value(0), 102400u64);
    }

    // --- notice schema tests ---

    #[test]
    fn notice_mapper_extracts_note_and_msg() {
        let json = serde_json::json!({
            "_path": "notice",
            "ts": 1700000500.0,
            "uid": "CNotice1",
            "id.orig_h": "10.0.0.9",
            "id.orig_p": 11111,
            "id.resp_h": "10.0.0.10",
            "id.resp_p": 22,
            "note": "SSH::Password_Guessing",
            "msg": "172.16.0.1 appears to be guessing SSH passwords",
            "sub": "Sampled 1 of 30 attempts",
            "actions": ["Notice::ACTION_LOG"]
        });
        let batch = map_notice(&json).unwrap();
        let note = batch
            .column_by_name("note")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(note.value(0), "SSH::Password_Guessing");
        let actions = batch
            .column_by_name("actions")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert!(actions.value(0).contains("Notice::ACTION_LOG"));
    }

    // --- envelope fallback ---

    #[test]
    fn unknown_log_path_uses_envelope_schema() {
        let entry = get_schema_entry("weird");
        let json = serde_json::json!({
            "_path": "weird",
            "ts": 1700000600.0,
            "uid": "CWeird1",
            "name": "data_before_established",
            "addl": "extra data"
        });
        let batch = (entry.mapper)(&json).unwrap();
        assert_eq!(batch.num_rows(), 1);
        let payload = batch
            .column_by_name("payload")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(payload.value(0)).unwrap();
        assert_eq!(parsed["uid"], "CWeird1");
        let log_path_col = batch
            .column_by_name("log_path")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(log_path_col.value(0), "weird");
    }

    #[test]
    fn get_schema_entry_returns_typed_for_known_paths() {
        for path in &["conn", "dns", "http", "ssl", "files", "notice"] {
            let entry = get_schema_entry(path);
            // Typed schemas have _extra; envelope schema has payload
            assert!(
                entry.schema.field_with_name("_extra").is_ok()
                    || entry.schema.field_with_name("payload").is_ok(),
                "schema for {} must have _extra or payload",
                path
            );
            let has_extra = entry.schema.field_with_name("_extra").is_ok();
            assert!(
                has_extra,
                "typed schema for {} must have _extra column",
                path
            );
        }
    }

    // --- Parquet round-trip ---

    #[test]
    fn conn_parquet_round_trip() {
        use bytes::Bytes;
        use parquet::arrow::ArrowWriter;
        use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
        use parquet::basic::{Compression, ZstdLevel};
        use parquet::file::properties::WriterProperties;

        let json = serde_json::json!({
            "_path": "conn",
            "ts": 1700000000.0,
            "uid": "CRoundTrip",
            "id.orig_h": "10.0.0.1",
            "id.orig_p": 12345,
            "id.resp_h": "10.0.0.2",
            "id.resp_p": 443,
            "proto": "tcp",
            "conn_state": "SF",
            "orig_bytes": 1024,
            "resp_bytes": 8192,
        });
        let batch = map_conn(&json).unwrap();
        let schema = conn_schema();

        let props = WriterProperties::builder()
            .set_compression(Compression::ZSTD(ZstdLevel::try_new(3).unwrap()))
            .build();
        let mut buf = Vec::new();
        let mut writer = ArrowWriter::try_new(&mut buf, schema, Some(props)).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();
        assert!(!buf.is_empty());

        let bytes = Bytes::from(buf);
        let mut reader = ParquetRecordBatchReaderBuilder::try_new(bytes)
            .unwrap()
            .build()
            .unwrap();
        let rb = reader.next().unwrap().unwrap();
        assert_eq!(rb.num_rows(), 1);
        let uid = rb
            .column_by_name("uid")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(uid.value(0), "CRoundTrip");
    }

    #[test]
    fn conn_mapper_string_type_mismatch_goes_to_extra() {
        // uid is a number instead of string — typed column null, value in _extra
        let json = serde_json::json!({
            "_path": "conn",
            "ts": 1700000000.0,
            "uid": 42,  // number, not string
            "orig_bytes": 512
        });
        let batch = map_conn(&json).unwrap();
        let uid_col = batch
            .column_by_name("uid")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert!(
            uid_col.is_null(0),
            "type-mismatched uid must be null in typed column"
        );
        let extra = batch
            .column_by_name("_extra")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let extra_val: serde_json::Value = serde_json::from_str(extra.value(0)).unwrap();
        assert!(
            extra_val.get("uid").is_some(),
            "type-mismatched uid must appear in _extra"
        );
        assert_eq!(extra_val["uid"], 42, "uid value preserved in _extra");
    }

    #[test]
    fn envelope_parquet_round_trip() {
        use bytes::Bytes;
        use parquet::arrow::ArrowWriter;
        use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

        let json = serde_json::json!({
            "_path": "weird",
            "ts": 1700000700.0,
            "uid": "CEnvRT",
            "weird_field": "some_value"
        });
        let batch = map_envelope(&json, "weird").unwrap();
        let schema = envelope_schema();

        let mut buf = Vec::new();
        let mut writer = ArrowWriter::try_new(&mut buf, schema, None).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();
        assert!(!buf.is_empty());

        let bytes = Bytes::from(buf);
        let mut reader = ParquetRecordBatchReaderBuilder::try_new(bytes)
            .unwrap()
            .build()
            .unwrap();
        let rb = reader.next().unwrap().unwrap();
        assert_eq!(rb.num_rows(), 1);
        let log_path = rb
            .column_by_name("log_path")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(log_path.value(0), "weird");
    }
}
