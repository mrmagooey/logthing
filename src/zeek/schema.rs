//! Zeek stream schema registry — typed Arrow schemas for the six curated streams
//! plus a generic envelope fallback for unmodelled stream types.

use arrow::array::{
    ArrayRef, Float64Builder, StringBuilder, TimestampMicrosecondBuilder, UInt16Builder,
    UInt32Builder, UInt64Builder,
};
use arrow::datatypes::{DataType, Field, Schema, TimeUnit};
use arrow::record_batch::RecordBatch;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

use crate::forwarding::buffered_writer::sanitize_log_path;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A function that maps one JSON record (plus the record's `received_at`
/// receipt instant, needed to derive `partition_time`) to a one-row
/// RecordBatch.
pub type RowMapper = Arc<
    dyn Fn(&serde_json::Value, chrono::DateTime<chrono::Utc>) -> anyhow::Result<RecordBatch>
        + Send
        + Sync,
>;

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
            Field::new(
                "ts",
                DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
                true,
            ),
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
            Field::new(
                "partition_time",
                DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
                false,
            ),
        ]))
    });
    S.clone()
}

/// `dns.log` Arrow schema.
pub fn dns_schema() -> Arc<Schema> {
    static S: LazyLock<Arc<Schema>> = LazyLock::new(|| {
        Arc::new(Schema::new(vec![
            Field::new(
                "ts",
                DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
                true,
            ),
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
            Field::new(
                "partition_time",
                DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
                false,
            ),
        ]))
    });
    S.clone()
}

/// `http.log` Arrow schema.
pub fn http_schema() -> Arc<Schema> {
    static S: LazyLock<Arc<Schema>> = LazyLock::new(|| {
        Arc::new(Schema::new(vec![
            Field::new(
                "ts",
                DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
                true,
            ),
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
            Field::new(
                "partition_time",
                DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
                false,
            ),
        ]))
    });
    S.clone()
}

/// `ssl.log` Arrow schema.
pub fn ssl_schema() -> Arc<Schema> {
    static S: LazyLock<Arc<Schema>> = LazyLock::new(|| {
        Arc::new(Schema::new(vec![
            Field::new(
                "ts",
                DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
                true,
            ),
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
            Field::new(
                "partition_time",
                DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
                false,
            ),
        ]))
    });
    S.clone()
}

/// `files.log` Arrow schema.
pub fn files_schema() -> Arc<Schema> {
    static S: LazyLock<Arc<Schema>> = LazyLock::new(|| {
        Arc::new(Schema::new(vec![
            Field::new(
                "ts",
                DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
                true,
            ),
            Field::new("fuid", DataType::Utf8, true),
            Field::new("tx_hosts", DataType::Utf8, true),
            Field::new("rx_hosts", DataType::Utf8, true),
            Field::new("source", DataType::Utf8, true),
            Field::new("mime_type", DataType::Utf8, true),
            Field::new("filename", DataType::Utf8, true),
            Field::new("total_bytes", DataType::UInt64, true),
            Field::new("_extra", DataType::Utf8, false),
            Field::new(
                "partition_time",
                DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
                false,
            ),
        ]))
    });
    S.clone()
}

/// `notice.log` Arrow schema.
pub fn notice_schema() -> Arc<Schema> {
    static S: LazyLock<Arc<Schema>> = LazyLock::new(|| {
        Arc::new(Schema::new(vec![
            Field::new(
                "ts",
                DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
                true,
            ),
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
            Field::new(
                "partition_time",
                DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
                false,
            ),
        ]))
    });
    S.clone()
}

/// Generic envelope schema for unknown/unmodelled stream types.
pub fn envelope_schema() -> Arc<Schema> {
    static S: LazyLock<Arc<Schema>> = LazyLock::new(|| {
        Arc::new(Schema::new(vec![
            Field::new(
                "ts",
                DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
                true,
            ),
            Field::new("uid", DataType::Utf8, true),
            Field::new("id_orig_h", DataType::Utf8, true),
            Field::new("id_orig_p", DataType::UInt16, true),
            Field::new("id_resp_h", DataType::Utf8, true),
            Field::new("id_resp_p", DataType::UInt16, true),
            Field::new("log_path", DataType::Utf8, false),
            Field::new(
                "ingest_time",
                DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
                false,
            ),
            Field::new("payload", DataType::Utf8, false),
            Field::new(
                "partition_time",
                DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
                false,
            ),
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

/// Extract an epoch-seconds float and convert it to microseconds.
///
/// Returns `None` if the key is absent, is not a number, or is outside the
/// range representable as `i64` microseconds. JSON is a trust boundary: a
/// legal-but-absurd value like `1e300` would saturate a bare `as i64` cast
/// to `i64::MAX`, presenting a nonsense timestamp as real data. Callers
/// treat `None` exactly as they already treat a type mismatch.
fn json_ts_micros(v: &serde_json::Value, key: &str) -> Option<i64> {
    let secs = v.get(key).and_then(|f| f.as_f64())?;
    let micros = (secs * 1e6).round();
    // NaN/Infinity cannot arrive from JSON, but the range check below also
    // rejects them, so the guard holds regardless of the source.
    //
    // Upper bound is a strict `<`, not `<=`: i64::MAX (2^63 - 1) is not
    // exactly representable as f64 (ULP is 1024 at that magnitude), so
    // `i64::MAX as f64` rounds up to 2^63. A `micros` value of exactly
    // 2^63 would pass `<=` but is already out of i64 range, so `as i64`
    // would saturate it to i64::MAX instead of being rejected here.
    if micros >= (i64::MIN as f64) && micros < (i64::MAX as f64) {
        Some(micros as i64)
    } else {
        None
    }
}

/// Derive the instant a Zeek record's `partition_time` column (and hence its
/// day-clean buffer bucket) is computed from.
///
/// `ts` is nullable in all 7 Zeek schemas -- a log path that sometimes omits
/// it would otherwise mix null and non-null `ts` values in one Parquet file,
/// which yields two `day(ts)` partition values for a single file and
/// Iceberg rejects the write. Materialising a non-null `partition_time`
/// column, always derived from this one clock-free function, closes that
/// gap: every row in a file agrees on the same instant.
///
/// Reads the raw JSON `ts` via `json_ts_micros` -- the same parser
/// `append_conn_value` (and every other row mapper) calls a moment later --
/// so the bucketed day and the persisted `ts` column (when present) can
/// never disagree about what the record's own timestamp was. The resulting
/// `Option<DateTime<Utc>>` is handed to `partition_time`, which applies the
/// shared backfill/skew clamp and falls back to `received_at` for a missing,
/// malformed, or out-of-window `ts` -- exactly the fallback the 6 typed
/// schemas need since none of them expose a `received_at`-equivalent column
/// of their own (only the envelope schema's `ingest_time` plays that role,
/// for unmodelled log paths).
///
/// Pure and clock-free: no `Utc::now()` read anywhere in this call chain, so
/// calling it twice on the same `(fields, received_at)` pair -- once from
/// `ZeekSink::day_and_batch` to pick the buffer, once from a row mapper to
/// stamp the column -- always agrees.
pub(crate) fn zeek_partition_time(
    fields: &serde_json::Value,
    received_at: chrono::DateTime<chrono::Utc>,
) -> chrono::DateTime<chrono::Utc> {
    let event = json_ts_micros(fields, "ts").and_then(chrono::DateTime::from_timestamp_micros);
    crate::forwarding::buffered_writer::partition_time(event, received_at)
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
    let mut extra = serde_json::Map::new();
    if let Some(obj) = value.as_object() {
        for (k, v) in obj {
            if !promoted.contains(&k.as_str()) || mismatch_keys.contains(&k.as_str()) {
                extra.insert(k.clone(), v.clone());
            }
        }
    }
    serde_json::Value::Object(extra).to_string()
}

// ---------------------------------------------------------------------------
// Per-stream row mappers
// ---------------------------------------------------------------------------

/// Amortized builder set for the "conn" schema. Holds the same 16 Arrow
/// builders `map_conn` used to create fresh on every call, as persistent
/// fields, so they can be reused across many records via `finish(&mut
/// self)` instead of reallocated per record or per batch.
pub(crate) struct ConnAccumulator {
    b_ts: TimestampMicrosecondBuilder,
    b_uid: StringBuilder,
    b_id_orig_h: StringBuilder,
    b_id_orig_p: UInt16Builder,
    b_id_resp_h: StringBuilder,
    b_id_resp_p: UInt16Builder,
    b_proto: StringBuilder,
    b_service: StringBuilder,
    b_duration: Float64Builder,
    b_orig_bytes: UInt64Builder,
    b_resp_bytes: UInt64Builder,
    b_conn_state: StringBuilder,
    b_history: StringBuilder,
    b_orig_pkts: UInt64Builder,
    b_resp_pkts: UInt64Builder,
    b_extra: StringBuilder,
    b_partition_time: TimestampMicrosecondBuilder,
    rows: usize,
}

impl ConnAccumulator {
    pub(crate) fn new() -> Self {
        Self {
            b_ts: TimestampMicrosecondBuilder::new().with_data_type(DataType::Timestamp(
                TimeUnit::Microsecond,
                Some("UTC".into()),
            )),
            b_uid: StringBuilder::new(),
            b_id_orig_h: StringBuilder::new(),
            b_id_orig_p: UInt16Builder::new(),
            b_id_resp_h: StringBuilder::new(),
            b_id_resp_p: UInt16Builder::new(),
            b_proto: StringBuilder::new(),
            b_service: StringBuilder::new(),
            b_duration: Float64Builder::new(),
            b_orig_bytes: UInt64Builder::new(),
            b_resp_bytes: UInt64Builder::new(),
            b_conn_state: StringBuilder::new(),
            b_history: StringBuilder::new(),
            b_orig_pkts: UInt64Builder::new(),
            b_resp_pkts: UInt64Builder::new(),
            b_extra: StringBuilder::new(),
            b_partition_time: TimestampMicrosecondBuilder::new().with_data_type(
                DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            ),
            rows: 0,
        }
    }

    /// Append one already-parsed JSON `value` (the `conn` fields object) plus
    /// the record's `received_at`, needed to derive `partition_time`.
    /// Shared by both the amortized path (`RecordBatchAccumulator::try_append`)
    /// and `map_conn`'s single-record fallback wrapper below -- identical
    /// extraction/mismatch-detection/`_extra`-building logic either way.
    fn append_conn_value(
        &mut self,
        value: &serde_json::Value,
        received_at: chrono::DateTime<chrono::Utc>,
    ) {
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

        let ts = json_ts_micros(value, "ts");
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
        let partition_time = zeek_partition_time(value, received_at);

        self.b_ts.append_option(ts);
        self.b_uid.append_option(uid.as_deref());
        self.b_id_orig_h.append_option(id_orig_h.as_deref());
        self.b_id_orig_p.append_option(id_orig_p);
        self.b_id_resp_h.append_option(id_resp_h.as_deref());
        self.b_id_resp_p.append_option(id_resp_p);
        self.b_proto.append_option(proto.as_deref());
        self.b_service.append_option(service.as_deref());
        self.b_duration.append_option(duration);
        self.b_orig_bytes.append_option(orig_bytes);
        self.b_resp_bytes.append_option(resp_bytes);
        self.b_conn_state.append_option(conn_state.as_deref());
        self.b_history.append_option(history.as_deref());
        self.b_orig_pkts.append_option(orig_pkts);
        self.b_resp_pkts.append_option(resp_pkts);
        self.b_extra.append_value(&extra);
        self.b_partition_time
            .append_value(partition_time.timestamp_micros());
        self.rows += 1;
    }

    /// Test-only helper: append a raw JSON value directly (bypassing the
    /// `ZeekRecord`-level schema-match check `try_append` performs), for
    /// unit tests that construct raw JSON fixtures.
    #[cfg(test)]
    fn try_append_value(
        &mut self,
        value: &serde_json::Value,
        received_at: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<bool> {
        self.append_conn_value(value, received_at);
        Ok(true)
    }

    fn finish_batch(&mut self) -> anyhow::Result<RecordBatch> {
        let columns: Vec<ArrayRef> = vec![
            Arc::new(self.b_ts.finish()),
            Arc::new(self.b_uid.finish()),
            Arc::new(self.b_id_orig_h.finish()),
            Arc::new(self.b_id_orig_p.finish()),
            Arc::new(self.b_id_resp_h.finish()),
            Arc::new(self.b_id_resp_p.finish()),
            Arc::new(self.b_proto.finish()),
            Arc::new(self.b_service.finish()),
            Arc::new(self.b_duration.finish()),
            Arc::new(self.b_orig_bytes.finish()),
            Arc::new(self.b_resp_bytes.finish()),
            Arc::new(self.b_conn_state.finish()),
            Arc::new(self.b_history.finish()),
            Arc::new(self.b_orig_pkts.finish()),
            Arc::new(self.b_resp_pkts.finish()),
            Arc::new(self.b_extra.finish()),
            Arc::new(self.b_partition_time.finish()),
        ];
        self.rows = 0;
        Ok(RecordBatch::try_new(conn_schema(), columns)?)
    }
}

impl crate::forwarding::buffered_writer::RecordBatchAccumulator<crate::zeek::ZeekRecord>
    for ConnAccumulator
{
    fn try_append(
        &mut self,
        record: &crate::zeek::ZeekRecord,
        // Zeek's own `received_at` (stamped on the record at ingest, see
        // `ZeekRecord`) is what `zeek_partition_time` already derives from --
        // the shared per-push clock read has nothing to add here. See the
        // trait doc comment for why the parameter exists at all.
        _now: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<bool> {
        // Mirror to_record_batch's existing per-record fallback check: only
        // accept a record whose RAW log_path resolves (via the registry) to
        // exactly the conn schema. A mismatch (e.g. raw "Conn" vs the
        // sanitized "conn" partition) must fall back to to_record_batch for
        // just this one record, exactly as today.
        let entry = get_schema_entry(&record.log_path);
        if !Arc::ptr_eq(&entry.schema, &conn_schema()) {
            return Ok(false);
        }
        self.append_conn_value(&record.fields, record.received_at);
        Ok(true)
    }

    fn len(&self) -> usize {
        self.rows
    }

    fn finish(&mut self) -> anyhow::Result<RecordBatch> {
        self.finish_batch()
    }
}

fn map_conn(
    value: &serde_json::Value,
    received_at: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<RecordBatch> {
    let mut acc = ConnAccumulator::new();
    acc.append_conn_value(value, received_at);
    acc.finish_batch()
}

/// Amortized builder set for the `dns.log` schema.
///
/// Holds the 15 columns `map_dns` used to allocate fresh on every record as
/// persistent builders. The field extraction lives exactly once, in
/// `append_dns_row`; `map_dns` is a `new -> append -> finish` wrapper over it,
/// so the amortized path and the single-record fallback cannot drift apart.
pub(crate) struct DnsAccumulator {
    b_ts: TimestampMicrosecondBuilder,
    b_uid: StringBuilder,
    b_id_orig_h: StringBuilder,
    b_id_orig_p: UInt16Builder,
    b_id_resp_h: StringBuilder,
    b_id_resp_p: UInt16Builder,
    b_proto: StringBuilder,
    b_trans_id: UInt32Builder,
    b_query: StringBuilder,
    b_qtype_name: StringBuilder,
    b_qclass_name: StringBuilder,
    b_rcode_name: StringBuilder,
    b_answers: StringBuilder,
    b_extra: StringBuilder,
    b_partition_time: TimestampMicrosecondBuilder,
    rows: usize,
}

impl DnsAccumulator {
    pub(crate) fn new() -> Self {
        let ts = || {
            TimestampMicrosecondBuilder::new().with_data_type(DataType::Timestamp(
                TimeUnit::Microsecond,
                Some("UTC".into()),
            ))
        };
        Self {
            b_ts: ts(),
            b_uid: StringBuilder::new(),
            b_id_orig_h: StringBuilder::new(),
            b_id_orig_p: UInt16Builder::new(),
            b_id_resp_h: StringBuilder::new(),
            b_id_resp_p: UInt16Builder::new(),
            b_proto: StringBuilder::new(),
            b_trans_id: UInt32Builder::new(),
            b_query: StringBuilder::new(),
            b_qtype_name: StringBuilder::new(),
            b_qclass_name: StringBuilder::new(),
            b_rcode_name: StringBuilder::new(),
            b_answers: StringBuilder::new(),
            b_extra: StringBuilder::new(),
            b_partition_time: ts(),
            rows: 0,
        }
    }

    fn finish_batch(&mut self) -> anyhow::Result<RecordBatch> {
        let columns: Vec<ArrayRef> = vec![
            Arc::new(self.b_ts.finish()),
            Arc::new(self.b_uid.finish()),
            Arc::new(self.b_id_orig_h.finish()),
            Arc::new(self.b_id_orig_p.finish()),
            Arc::new(self.b_id_resp_h.finish()),
            Arc::new(self.b_id_resp_p.finish()),
            Arc::new(self.b_proto.finish()),
            Arc::new(self.b_trans_id.finish()),
            Arc::new(self.b_query.finish()),
            Arc::new(self.b_qtype_name.finish()),
            Arc::new(self.b_qclass_name.finish()),
            Arc::new(self.b_rcode_name.finish()),
            Arc::new(self.b_answers.finish()),
            Arc::new(self.b_extra.finish()),
            Arc::new(self.b_partition_time.finish()),
        ];
        self.rows = 0;
        Ok(RecordBatch::try_new(dns_schema(), columns)?)
    }
}

/// Extract one `dns.log` record from raw Zeek JSON and append it to `acc`.
/// This is the single implementation of the dns row mapping.
fn append_dns_row(
    acc: &mut DnsAccumulator,
    value: &serde_json::Value,
    received_at: chrono::DateTime<chrono::Utc>,
) {
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

    let ts = json_ts_micros(value, "ts");
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
    let partition_time = zeek_partition_time(value, received_at);

    acc.b_ts.append_option(ts);
    acc.b_uid.append_option(uid.as_deref());
    acc.b_id_orig_h.append_option(id_orig_h.as_deref());
    acc.b_id_orig_p.append_option(id_orig_p);
    acc.b_id_resp_h.append_option(id_resp_h.as_deref());
    acc.b_id_resp_p.append_option(id_resp_p);
    acc.b_proto.append_option(proto.as_deref());
    acc.b_trans_id.append_option(trans_id);
    acc.b_query.append_option(query.as_deref());
    acc.b_qtype_name.append_option(qtype_name.as_deref());
    acc.b_qclass_name.append_option(qclass_name.as_deref());
    acc.b_rcode_name.append_option(rcode_name.as_deref());
    acc.b_answers.append_option(answers.as_deref());
    acc.b_extra.append_value(&extra);
    acc.b_partition_time
        .append_value(partition_time.timestamp_micros());
    acc.rows += 1;
}

impl crate::forwarding::buffered_writer::RecordBatchAccumulator<crate::zeek::ZeekRecord>
    for DnsAccumulator
{
    /// `_now` is unused: `ZeekRecord` carries its own `received_at`.
    fn try_append(
        &mut self,
        record: &crate::zeek::ZeekRecord,
        _now: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<bool> {
        // Mirror map_conn/ConnAccumulator's gate: only accept a record whose
        // RAW log_path resolves to exactly the dns schema. A mismatch falls
        // back to to_record_batch for that one record.
        let entry = get_schema_entry(&record.log_path);
        if !Arc::ptr_eq(&entry.schema, &dns_schema()) {
            return Ok(false);
        }
        append_dns_row(self, &record.fields, record.received_at);
        Ok(true)
    }

    fn len(&self) -> usize {
        self.rows
    }

    fn finish(&mut self) -> anyhow::Result<RecordBatch> {
        self.finish_batch()
    }
}

/// Map one `dns.log` record to a single-row `RecordBatch`.
///
/// Thin wrapper over `DnsAccumulator` so the mapping has one implementation.
fn map_dns(
    value: &serde_json::Value,
    received_at: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<RecordBatch> {
    let mut acc = DnsAccumulator::new();
    append_dns_row(&mut acc, value, received_at);
    acc.finish_batch()
}

/// Amortized builder set for the `http.log` schema.
///
/// Holds the columns `map_http` used to allocate fresh on every record as
/// persistent builders. The field extraction lives exactly once, in
/// `append_http_row`; `map_http` is a `new -> append -> finish` wrapper,
/// so the amortized path and the single-record fallback cannot drift apart.
pub(crate) struct HttpAccumulator {
    b_ts: TimestampMicrosecondBuilder,
    b_uid: StringBuilder,
    b_id_orig_h: StringBuilder,
    b_id_orig_p: UInt16Builder,
    b_id_resp_h: StringBuilder,
    b_id_resp_p: UInt16Builder,
    b_method: StringBuilder,
    b_host: StringBuilder,
    b_uri: StringBuilder,
    b_status_code: UInt16Builder,
    b_user_agent: StringBuilder,
    b_request_body_len: UInt64Builder,
    b_response_body_len: UInt64Builder,
    b_extra: StringBuilder,
    b_partition_time: TimestampMicrosecondBuilder,
    rows: usize,
}

impl HttpAccumulator {
    pub(crate) fn new() -> Self {
        Self {
            b_ts: TimestampMicrosecondBuilder::new().with_data_type(DataType::Timestamp(
                TimeUnit::Microsecond,
                Some("UTC".into()),
            )),
            b_uid: StringBuilder::new(),
            b_id_orig_h: StringBuilder::new(),
            b_id_orig_p: UInt16Builder::new(),
            b_id_resp_h: StringBuilder::new(),
            b_id_resp_p: UInt16Builder::new(),
            b_method: StringBuilder::new(),
            b_host: StringBuilder::new(),
            b_uri: StringBuilder::new(),
            b_status_code: UInt16Builder::new(),
            b_user_agent: StringBuilder::new(),
            b_request_body_len: UInt64Builder::new(),
            b_response_body_len: UInt64Builder::new(),
            b_extra: StringBuilder::new(),
            b_partition_time: TimestampMicrosecondBuilder::new().with_data_type(
                DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            ),
            rows: 0,
        }
    }

    fn finish_batch(&mut self) -> anyhow::Result<RecordBatch> {
        let columns: Vec<ArrayRef> = vec![
            Arc::new(self.b_ts.finish()),
            Arc::new(self.b_uid.finish()),
            Arc::new(self.b_id_orig_h.finish()),
            Arc::new(self.b_id_orig_p.finish()),
            Arc::new(self.b_id_resp_h.finish()),
            Arc::new(self.b_id_resp_p.finish()),
            Arc::new(self.b_method.finish()),
            Arc::new(self.b_host.finish()),
            Arc::new(self.b_uri.finish()),
            Arc::new(self.b_status_code.finish()),
            Arc::new(self.b_user_agent.finish()),
            Arc::new(self.b_request_body_len.finish()),
            Arc::new(self.b_response_body_len.finish()),
            Arc::new(self.b_extra.finish()),
            Arc::new(self.b_partition_time.finish()),
        ];
        self.rows = 0;
        Ok(RecordBatch::try_new(http_schema(), columns)?)
    }
}

/// Extract one `http.log` record from raw Zeek JSON and append it to `acc`.
/// Single implementation of the http row mapping.
fn append_http_row(
    acc: &mut HttpAccumulator,
    value: &serde_json::Value,
    received_at: chrono::DateTime<chrono::Utc>,
) {
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

    let ts = json_ts_micros(value, "ts");
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
    let partition_time = zeek_partition_time(value, received_at);

    acc.b_ts.append_option(ts);
    acc.b_uid.append_option(uid.as_deref());
    acc.b_id_orig_h.append_option(id_orig_h.as_deref());
    acc.b_id_orig_p.append_option(id_orig_p);
    acc.b_id_resp_h.append_option(id_resp_h.as_deref());
    acc.b_id_resp_p.append_option(id_resp_p);
    acc.b_method.append_option(method.as_deref());
    acc.b_host.append_option(host.as_deref());
    acc.b_uri.append_option(uri.as_deref());
    acc.b_status_code.append_option(status_code);
    acc.b_user_agent.append_option(user_agent.as_deref());
    acc.b_request_body_len.append_option(request_body_len);
    acc.b_response_body_len.append_option(response_body_len);
    acc.b_extra.append_value(&extra);
    acc.b_partition_time
        .append_value(partition_time.timestamp_micros());
    acc.rows += 1;
}

impl crate::forwarding::buffered_writer::RecordBatchAccumulator<crate::zeek::ZeekRecord>
    for HttpAccumulator
{
    /// `_now` is unused: `ZeekRecord` carries its own `received_at`.
    fn try_append(
        &mut self,
        record: &crate::zeek::ZeekRecord,
        _now: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<bool> {
        let entry = get_schema_entry(&record.log_path);
        if !Arc::ptr_eq(&entry.schema, &http_schema()) {
            return Ok(false);
        }
        append_http_row(self, &record.fields, record.received_at);
        Ok(true)
    }

    fn len(&self) -> usize {
        self.rows
    }

    fn finish(&mut self) -> anyhow::Result<RecordBatch> {
        self.finish_batch()
    }
}

/// Map one `http.log` record to a single-row `RecordBatch`.
fn map_http(
    value: &serde_json::Value,
    received_at: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<RecordBatch> {
    let mut acc = HttpAccumulator::new();
    append_http_row(&mut acc, value, received_at);
    acc.finish_batch()
}
/// Amortized builder set for the `ssl.log` schema.
///
/// Holds the columns `map_ssl` used to allocate fresh on every record as
/// persistent builders. The field extraction lives exactly once, in
/// `append_ssl_row`; `map_ssl` is a `new -> append -> finish` wrapper,
/// so the amortized path and the single-record fallback cannot drift apart.
pub(crate) struct SslAccumulator {
    b_ts: TimestampMicrosecondBuilder,
    b_uid: StringBuilder,
    b_id_orig_h: StringBuilder,
    b_id_orig_p: UInt16Builder,
    b_id_resp_h: StringBuilder,
    b_id_resp_p: UInt16Builder,
    b_version: StringBuilder,
    b_cipher: StringBuilder,
    b_curve: StringBuilder,
    b_server_name: StringBuilder,
    b_validation_status: StringBuilder,
    b_extra: StringBuilder,
    b_partition_time: TimestampMicrosecondBuilder,
    rows: usize,
}

impl SslAccumulator {
    pub(crate) fn new() -> Self {
        Self {
            b_ts: TimestampMicrosecondBuilder::new().with_data_type(DataType::Timestamp(
                TimeUnit::Microsecond,
                Some("UTC".into()),
            )),
            b_uid: StringBuilder::new(),
            b_id_orig_h: StringBuilder::new(),
            b_id_orig_p: UInt16Builder::new(),
            b_id_resp_h: StringBuilder::new(),
            b_id_resp_p: UInt16Builder::new(),
            b_version: StringBuilder::new(),
            b_cipher: StringBuilder::new(),
            b_curve: StringBuilder::new(),
            b_server_name: StringBuilder::new(),
            b_validation_status: StringBuilder::new(),
            b_extra: StringBuilder::new(),
            b_partition_time: TimestampMicrosecondBuilder::new().with_data_type(
                DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            ),
            rows: 0,
        }
    }

    fn finish_batch(&mut self) -> anyhow::Result<RecordBatch> {
        let columns: Vec<ArrayRef> = vec![
            Arc::new(self.b_ts.finish()),
            Arc::new(self.b_uid.finish()),
            Arc::new(self.b_id_orig_h.finish()),
            Arc::new(self.b_id_orig_p.finish()),
            Arc::new(self.b_id_resp_h.finish()),
            Arc::new(self.b_id_resp_p.finish()),
            Arc::new(self.b_version.finish()),
            Arc::new(self.b_cipher.finish()),
            Arc::new(self.b_curve.finish()),
            Arc::new(self.b_server_name.finish()),
            Arc::new(self.b_validation_status.finish()),
            Arc::new(self.b_extra.finish()),
            Arc::new(self.b_partition_time.finish()),
        ];
        self.rows = 0;
        Ok(RecordBatch::try_new(ssl_schema(), columns)?)
    }
}

/// Extract one `ssl.log` record from raw Zeek JSON and append it to `acc`.
/// Single implementation of the ssl row mapping.
fn append_ssl_row(
    acc: &mut SslAccumulator,
    value: &serde_json::Value,
    received_at: chrono::DateTime<chrono::Utc>,
) {
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

    let ts = json_ts_micros(value, "ts");
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
    let partition_time = zeek_partition_time(value, received_at);

    acc.b_ts.append_option(ts);
    acc.b_uid.append_option(uid.as_deref());
    acc.b_id_orig_h.append_option(id_orig_h.as_deref());
    acc.b_id_orig_p.append_option(id_orig_p);
    acc.b_id_resp_h.append_option(id_resp_h.as_deref());
    acc.b_id_resp_p.append_option(id_resp_p);
    acc.b_version.append_option(version.as_deref());
    acc.b_cipher.append_option(cipher.as_deref());
    acc.b_curve.append_option(curve.as_deref());
    acc.b_server_name.append_option(server_name.as_deref());
    acc.b_validation_status
        .append_option(validation_status.as_deref());
    acc.b_extra.append_value(&extra);
    acc.b_partition_time
        .append_value(partition_time.timestamp_micros());
    acc.rows += 1;
}

impl crate::forwarding::buffered_writer::RecordBatchAccumulator<crate::zeek::ZeekRecord>
    for SslAccumulator
{
    /// `_now` is unused: `ZeekRecord` carries its own `received_at`.
    fn try_append(
        &mut self,
        record: &crate::zeek::ZeekRecord,
        _now: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<bool> {
        let entry = get_schema_entry(&record.log_path);
        if !Arc::ptr_eq(&entry.schema, &ssl_schema()) {
            return Ok(false);
        }
        append_ssl_row(self, &record.fields, record.received_at);
        Ok(true)
    }

    fn len(&self) -> usize {
        self.rows
    }

    fn finish(&mut self) -> anyhow::Result<RecordBatch> {
        self.finish_batch()
    }
}

/// Map one `ssl.log` record to a single-row `RecordBatch`.
fn map_ssl(
    value: &serde_json::Value,
    received_at: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<RecordBatch> {
    let mut acc = SslAccumulator::new();
    append_ssl_row(&mut acc, value, received_at);
    acc.finish_batch()
}
/// Amortized builder set for the `files.log` schema.
///
/// Holds the columns `map_files` used to allocate fresh on every record as
/// persistent builders. The field extraction lives exactly once, in
/// `append_files_row`; `map_files` is a `new -> append -> finish` wrapper,
/// so the amortized path and the single-record fallback cannot drift apart.
pub(crate) struct FilesAccumulator {
    b_ts: TimestampMicrosecondBuilder,
    b_fuid: StringBuilder,
    b_tx_hosts: StringBuilder,
    b_rx_hosts: StringBuilder,
    b_source: StringBuilder,
    b_mime_type: StringBuilder,
    b_filename: StringBuilder,
    b_total_bytes: UInt64Builder,
    b_extra: StringBuilder,
    b_partition_time: TimestampMicrosecondBuilder,
    rows: usize,
}

impl FilesAccumulator {
    pub(crate) fn new() -> Self {
        Self {
            b_ts: TimestampMicrosecondBuilder::new().with_data_type(DataType::Timestamp(
                TimeUnit::Microsecond,
                Some("UTC".into()),
            )),
            b_fuid: StringBuilder::new(),
            b_tx_hosts: StringBuilder::new(),
            b_rx_hosts: StringBuilder::new(),
            b_source: StringBuilder::new(),
            b_mime_type: StringBuilder::new(),
            b_filename: StringBuilder::new(),
            b_total_bytes: UInt64Builder::new(),
            b_extra: StringBuilder::new(),
            b_partition_time: TimestampMicrosecondBuilder::new().with_data_type(
                DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            ),
            rows: 0,
        }
    }

    fn finish_batch(&mut self) -> anyhow::Result<RecordBatch> {
        let columns: Vec<ArrayRef> = vec![
            Arc::new(self.b_ts.finish()),
            Arc::new(self.b_fuid.finish()),
            Arc::new(self.b_tx_hosts.finish()),
            Arc::new(self.b_rx_hosts.finish()),
            Arc::new(self.b_source.finish()),
            Arc::new(self.b_mime_type.finish()),
            Arc::new(self.b_filename.finish()),
            Arc::new(self.b_total_bytes.finish()),
            Arc::new(self.b_extra.finish()),
            Arc::new(self.b_partition_time.finish()),
        ];
        self.rows = 0;
        Ok(RecordBatch::try_new(files_schema(), columns)?)
    }
}

/// Extract one `files.log` record from raw Zeek JSON and append it to `acc`.
/// Single implementation of the files row mapping.
fn append_files_row(
    acc: &mut FilesAccumulator,
    value: &serde_json::Value,
    received_at: chrono::DateTime<chrono::Utc>,
) {
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

    let ts = json_ts_micros(value, "ts");
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
    let partition_time = zeek_partition_time(value, received_at);

    acc.b_ts.append_option(ts);
    acc.b_fuid.append_option(fuid.as_deref());
    acc.b_tx_hosts.append_option(tx_hosts.as_deref());
    acc.b_rx_hosts.append_option(rx_hosts.as_deref());
    acc.b_source.append_option(source.as_deref());
    acc.b_mime_type.append_option(mime_type.as_deref());
    acc.b_filename.append_option(filename.as_deref());
    acc.b_total_bytes.append_option(total_bytes);
    acc.b_extra.append_value(&extra);
    acc.b_partition_time
        .append_value(partition_time.timestamp_micros());
    acc.rows += 1;
}

impl crate::forwarding::buffered_writer::RecordBatchAccumulator<crate::zeek::ZeekRecord>
    for FilesAccumulator
{
    /// `_now` is unused: `ZeekRecord` carries its own `received_at`.
    fn try_append(
        &mut self,
        record: &crate::zeek::ZeekRecord,
        _now: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<bool> {
        let entry = get_schema_entry(&record.log_path);
        if !Arc::ptr_eq(&entry.schema, &files_schema()) {
            return Ok(false);
        }
        append_files_row(self, &record.fields, record.received_at);
        Ok(true)
    }

    fn len(&self) -> usize {
        self.rows
    }

    fn finish(&mut self) -> anyhow::Result<RecordBatch> {
        self.finish_batch()
    }
}

/// Map one `files.log` record to a single-row `RecordBatch`.
fn map_files(
    value: &serde_json::Value,
    received_at: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<RecordBatch> {
    let mut acc = FilesAccumulator::new();
    append_files_row(&mut acc, value, received_at);
    acc.finish_batch()
}
/// Amortized builder set for the `notice.log` schema.
///
/// Holds the columns `map_notice` used to allocate fresh on every record as
/// persistent builders. The field extraction lives exactly once, in
/// `append_notice_row`; `map_notice` is a `new -> append -> finish` wrapper,
/// so the amortized path and the single-record fallback cannot drift apart.
pub(crate) struct NoticeAccumulator {
    b_ts: TimestampMicrosecondBuilder,
    b_uid: StringBuilder,
    b_id_orig_h: StringBuilder,
    b_id_orig_p: UInt16Builder,
    b_id_resp_h: StringBuilder,
    b_id_resp_p: UInt16Builder,
    b_note: StringBuilder,
    b_msg: StringBuilder,
    b_sub: StringBuilder,
    b_actions: StringBuilder,
    b_extra: StringBuilder,
    b_partition_time: TimestampMicrosecondBuilder,
    rows: usize,
}

impl NoticeAccumulator {
    pub(crate) fn new() -> Self {
        Self {
            b_ts: TimestampMicrosecondBuilder::new().with_data_type(DataType::Timestamp(
                TimeUnit::Microsecond,
                Some("UTC".into()),
            )),
            b_uid: StringBuilder::new(),
            b_id_orig_h: StringBuilder::new(),
            b_id_orig_p: UInt16Builder::new(),
            b_id_resp_h: StringBuilder::new(),
            b_id_resp_p: UInt16Builder::new(),
            b_note: StringBuilder::new(),
            b_msg: StringBuilder::new(),
            b_sub: StringBuilder::new(),
            b_actions: StringBuilder::new(),
            b_extra: StringBuilder::new(),
            b_partition_time: TimestampMicrosecondBuilder::new().with_data_type(
                DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            ),
            rows: 0,
        }
    }

    fn finish_batch(&mut self) -> anyhow::Result<RecordBatch> {
        let columns: Vec<ArrayRef> = vec![
            Arc::new(self.b_ts.finish()),
            Arc::new(self.b_uid.finish()),
            Arc::new(self.b_id_orig_h.finish()),
            Arc::new(self.b_id_orig_p.finish()),
            Arc::new(self.b_id_resp_h.finish()),
            Arc::new(self.b_id_resp_p.finish()),
            Arc::new(self.b_note.finish()),
            Arc::new(self.b_msg.finish()),
            Arc::new(self.b_sub.finish()),
            Arc::new(self.b_actions.finish()),
            Arc::new(self.b_extra.finish()),
            Arc::new(self.b_partition_time.finish()),
        ];
        self.rows = 0;
        Ok(RecordBatch::try_new(notice_schema(), columns)?)
    }
}

/// Extract one `notice.log` record from raw Zeek JSON and append it to `acc`.
/// Single implementation of the notice row mapping.
fn append_notice_row(
    acc: &mut NoticeAccumulator,
    value: &serde_json::Value,
    received_at: chrono::DateTime<chrono::Utc>,
) {
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

    let ts = json_ts_micros(value, "ts");
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
    let partition_time = zeek_partition_time(value, received_at);

    acc.b_ts.append_option(ts);
    acc.b_uid.append_option(uid.as_deref());
    acc.b_id_orig_h.append_option(id_orig_h.as_deref());
    acc.b_id_orig_p.append_option(id_orig_p);
    acc.b_id_resp_h.append_option(id_resp_h.as_deref());
    acc.b_id_resp_p.append_option(id_resp_p);
    acc.b_note.append_option(note.as_deref());
    acc.b_msg.append_option(msg.as_deref());
    acc.b_sub.append_option(sub.as_deref());
    acc.b_actions.append_option(actions.as_deref());
    acc.b_extra.append_value(&extra);
    acc.b_partition_time
        .append_value(partition_time.timestamp_micros());
    acc.rows += 1;
}

impl crate::forwarding::buffered_writer::RecordBatchAccumulator<crate::zeek::ZeekRecord>
    for NoticeAccumulator
{
    /// `_now` is unused: `ZeekRecord` carries its own `received_at`.
    fn try_append(
        &mut self,
        record: &crate::zeek::ZeekRecord,
        _now: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<bool> {
        let entry = get_schema_entry(&record.log_path);
        if !Arc::ptr_eq(&entry.schema, &notice_schema()) {
            return Ok(false);
        }
        append_notice_row(self, &record.fields, record.received_at);
        Ok(true)
    }

    fn len(&self) -> usize {
        self.rows
    }

    fn finish(&mut self) -> anyhow::Result<RecordBatch> {
        self.finish_batch()
    }
}

/// Map one `notice.log` record to a single-row `RecordBatch`.
fn map_notice(
    value: &serde_json::Value,
    received_at: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<RecordBatch> {
    let mut acc = NoticeAccumulator::new();
    append_notice_row(&mut acc, value, received_at);
    acc.finish_batch()
}
/// Amortized builder set for the envelope schema -- the fallback every
/// unmodelled Zeek stream takes.
///
/// The field extraction lives exactly once, in `append_envelope_row`;
/// `map_envelope` is a `new -> append -> finish` wrapper over it.
pub(crate) struct EnvelopeAccumulator {
    b_ts: TimestampMicrosecondBuilder,
    b_uid: StringBuilder,
    b_id_orig_h: StringBuilder,
    b_id_orig_p: UInt16Builder,
    b_id_resp_h: StringBuilder,
    b_id_resp_p: UInt16Builder,
    b_log_path: StringBuilder,
    b_ingest_time: TimestampMicrosecondBuilder,
    b_payload: StringBuilder,
    b_partition_time: TimestampMicrosecondBuilder,
    rows: usize,
}

impl EnvelopeAccumulator {
    pub(crate) fn new() -> Self {
        let ts = || {
            TimestampMicrosecondBuilder::new().with_data_type(DataType::Timestamp(
                TimeUnit::Microsecond,
                Some("UTC".into()),
            ))
        };
        Self {
            b_ts: ts(),
            b_uid: StringBuilder::new(),
            b_id_orig_h: StringBuilder::new(),
            b_id_orig_p: UInt16Builder::new(),
            b_id_resp_h: StringBuilder::new(),
            b_id_resp_p: UInt16Builder::new(),
            b_log_path: StringBuilder::new(),
            b_ingest_time: ts(),
            b_payload: StringBuilder::new(),
            b_partition_time: ts(),
            rows: 0,
        }
    }

    fn finish_batch(&mut self) -> anyhow::Result<RecordBatch> {
        let columns: Vec<ArrayRef> = vec![
            Arc::new(self.b_ts.finish()),
            Arc::new(self.b_uid.finish()),
            Arc::new(self.b_id_orig_h.finish()),
            Arc::new(self.b_id_orig_p.finish()),
            Arc::new(self.b_id_resp_h.finish()),
            Arc::new(self.b_id_resp_p.finish()),
            Arc::new(self.b_log_path.finish()),
            Arc::new(self.b_ingest_time.finish()),
            Arc::new(self.b_payload.finish()),
            Arc::new(self.b_partition_time.finish()),
        ];
        self.rows = 0;
        Ok(RecordBatch::try_new(envelope_schema(), columns)?)
    }
}

/// Extract one envelope row and append it to `acc`. Single implementation of
/// the envelope row mapping.
fn append_envelope_row(
    acc: &mut EnvelopeAccumulator,
    value: &serde_json::Value,
    log_path: &str,
    received_at: chrono::DateTime<chrono::Utc>,
) {
    let ts = json_ts_micros(value, "ts");
    let uid = json_str(value, "uid");
    let id_orig_h = json_str(value, "id.orig_h");
    let id_orig_p = json_u16(value, "id.orig_p");
    let id_resp_h = json_str(value, "id.resp_h");
    let id_resp_p = json_u16(value, "id.resp_p");
    // Read per row, NOT from the writer's threaded `now`: `ingest_time` is
    // this row's own receipt-into-storage instant, and every row of an
    // accumulated batch is appended at a different moment. Unlike
    // `partition_time` this is not a buffer key, so a per-row read cannot
    // produce a non-day-clean file -- the race `push()`'s single clock read
    // exists to prevent does not apply here.
    let ingest_time = chrono::Utc::now().timestamp_micros();
    let payload = value.to_string();
    let partition_time = zeek_partition_time(value, received_at);

    acc.b_ts.append_option(ts);
    acc.b_uid.append_option(uid.as_deref());
    acc.b_id_orig_h.append_option(id_orig_h.as_deref());
    acc.b_id_orig_p.append_option(id_orig_p);
    acc.b_id_resp_h.append_option(id_resp_h.as_deref());
    acc.b_id_resp_p.append_option(id_resp_p);
    acc.b_log_path.append_value(log_path);
    acc.b_ingest_time.append_value(ingest_time);
    acc.b_payload.append_value(&payload);
    acc.b_partition_time
        .append_value(partition_time.timestamp_micros());
    acc.rows += 1;
}

impl crate::forwarding::buffered_writer::RecordBatchAccumulator<crate::zeek::ZeekRecord>
    for EnvelopeAccumulator
{
    /// `_now` is unused: `ZeekRecord` carries its own `received_at`, and
    /// `ingest_time` is deliberately read per row (see `append_envelope_row`).
    fn try_append(
        &mut self,
        record: &crate::zeek::ZeekRecord,
        _now: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<bool> {
        let entry = get_schema_entry(&record.log_path);
        if !Arc::ptr_eq(&entry.schema, &envelope_schema()) {
            return Ok(false);
        }
        append_envelope_row(self, &record.fields, &record.log_path, record.received_at);
        Ok(true)
    }

    fn len(&self) -> usize {
        self.rows
    }

    fn finish(&mut self) -> anyhow::Result<RecordBatch> {
        self.finish_batch()
    }
}

/// Map one unmodelled Zeek record to a single-row envelope `RecordBatch`.
fn map_envelope(
    value: &serde_json::Value,
    log_path: &str,
    received_at: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<RecordBatch> {
    let mut acc = EnvelopeAccumulator::new();
    append_envelope_row(&mut acc, value, log_path, received_at);
    acc.finish_batch()
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

/// Bound a `_path` value to the set of modelled zeek streams, for use as a
/// metric label. `_path` comes straight off the wire and is unbounded in both
/// length and charset, so labelling a Prometheus counter with it raw lets any
/// client that can reach the listener mint a permanent series per record.
/// Returning the registry's own `&'static str` keys caps the label set at the
/// modelled streams plus `"other"` — and drops the per-record string clone
/// the label used to cost (the `counter!` macro's own one-element label Vec
/// is unchanged).
pub fn metric_log_path(log_path: &str) -> &'static str {
    REGISTRY
        .get_key_value(log_path)
        .map(|(name, _)| *name)
        .unwrap_or("other")
}

/// Look up the SchemaEntry for `log_path`. Falls back to the envelope schema for unknown paths.
/// The envelope mapper always uses the actual `log_path` at call time via a wrapper.
///
/// Tries an exact match first, then the `sanitize_log_path`-normalized key:
/// `ZeekSink::partition()`/`schema()` key buffers by `sanitize_log_path` (which
/// lowercases), so `"Conn"` must resolve to the same typed conn schema its
/// buffer holds -- a case-sensitive-only lookup would fall through to the
/// envelope schema here while the buffer stays typed conn, and every later
/// flush of that buffer would fail in `concat_batches` forever.
pub fn get_schema_entry(log_path: &str) -> Arc<SchemaEntry> {
    if let Some(entry) = REGISTRY.get(log_path) {
        return entry.clone();
    }
    if let Some(entry) = REGISTRY.get(sanitize_log_path(log_path).as_str()) {
        return entry.clone();
    }
    // For unknown paths, build a fresh SchemaEntry with the actual log_path captured.
    let path = log_path.to_string();
    Arc::new(SchemaEntry {
        schema: envelope_schema(),
        mapper: Arc::new(move |v, received_at| map_envelope(v, &path, received_at)),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forwarding::buffered_writer::RecordBatchAccumulator;
    use arrow::array::{Array, StringArray, TimestampMicrosecondArray, UInt16Array, UInt64Array};
    use chrono::TimeZone;

    /// `_path` is attacker-controlled, so the metric label must be drawn from
    /// the fixed registry, never from the wire value.
    #[test]
    fn metric_log_path_bounds_the_label_to_modelled_streams() {
        for known in ["conn", "dns", "http", "ssl", "files", "notice"] {
            assert_eq!(
                metric_log_path(known),
                known,
                "modelled streams keep their own series"
            );
        }
        for hostile in [
            "unknown",
            "weird",
            &"A".repeat(16_384),
            "conn\u{0}injected",
            "",
        ] {
            assert_eq!(
                metric_log_path(hostile),
                "other",
                "an unmodelled _path must collapse to a single series, not mint a new one"
            );
        }
    }

    /// A fixed, distinctive `received_at` for tests that don't care about its
    /// exact value -- deliberately far from any epoch-second `ts` fixture
    /// used elsewhere in this module (e.g. `1700000000.0` -> 2023-11-14), so
    /// a test that silently started asserting against the fallback instead
    /// of the real one would visibly fail rather than passing by accident.
    fn rx() -> chrono::DateTime<chrono::Utc> {
        chrono::Utc.with_ymd_and_hms(2024, 3, 15, 12, 0, 0).unwrap()
    }

    // --- amortized accumulator tests (all six non-conn schemas) ---

    /// For each schema: N records through one accumulator must equal N
    /// single-row batches concatenated. This is the test that would catch the
    /// extraction logic having been altered rather than moved during the
    /// hoist into `append_*_row`.
    macro_rules! accumulator_parity_test {
        ($test:ident, $acc:ident, $append:ident, $schema:ident, $json:expr) => {
            #[test]
            fn $test() {
                use crate::forwarding::buffered_writer::RecordBatchAccumulator;
                let records: Vec<serde_json::Value> = (0..4).map($json).collect();

                let singles: Vec<RecordBatch> = records
                    .iter()
                    .map(|v| {
                        let mut a = $acc::new();
                        $append(&mut a, v, rx());
                        a.finish_batch().unwrap()
                    })
                    .collect();
                let expected = arrow::compute::concat_batches(&$schema(), &singles).unwrap();

                let mut acc = $acc::new();
                assert!(acc.is_empty());
                for (i, v) in records.iter().enumerate() {
                    $append(&mut acc, v, rx());
                    assert_eq!(acc.len(), i + 1, "len must advance one row per record");
                }
                let actual = acc.finish().unwrap();

                assert_eq!(actual.num_rows(), expected.num_rows());
                assert_eq!(actual.schema(), expected.schema());
                for c in 0..expected.num_columns() {
                    assert_eq!(
                        format!("{:?}", actual.column(c)),
                        format!("{:?}", expected.column(c)),
                        "column {} ({}) differs between amortized and per-record paths",
                        c,
                        expected.schema().field(c).name()
                    );
                }

                // finish() must reset: a builder retaining rows would
                // silently duplicate data into the next flush.
                assert_eq!(acc.len(), 0);
                $append(&mut acc, &records[0], rx());
                assert_eq!(acc.finish().unwrap().num_rows(), 1);
            }
        };
    }

    accumulator_parity_test!(
        dns_accumulator_matches_per_record_path,
        DnsAccumulator,
        append_dns_row,
        dns_schema,
        |i: i32| serde_json::json!({
            "ts": 1700000000.0 + i as f64, "uid": format!("C{i}"),
            "id.orig_h": "10.0.0.1", "id.orig_p": 1234u16 + i as u16,
            "id.resp_h": "10.0.0.2", "id.resp_p": 53u16, "proto": "udp",
            "trans_id": 42u32 + i as u32, "query": format!("h{i}.example.com"),
            "qtype_name": "A", "qclass_name": "C_INTERNET", "rcode_name": "NOERROR",
            "answers": ["1.2.3.4"], "unmodelled": i,
        })
    );

    accumulator_parity_test!(
        http_accumulator_matches_per_record_path,
        HttpAccumulator,
        append_http_row,
        http_schema,
        |i: i32| serde_json::json!({
            "ts": 1700000000.0 + i as f64, "uid": format!("C{i}"),
            "id.orig_h": "10.0.0.1", "id.orig_p": 1234u16 + i as u16,
            "id.resp_h": "10.0.0.2", "id.resp_p": 80u16,
            "method": "GET", "host": "example.com", "uri": format!("/p/{i}"),
            "status_code": 200u16, "user_agent": "curl/8", "unmodelled": i,
        })
    );

    accumulator_parity_test!(
        ssl_accumulator_matches_per_record_path,
        SslAccumulator,
        append_ssl_row,
        ssl_schema,
        |i: i32| serde_json::json!({
            "ts": 1700000000.0 + i as f64, "uid": format!("C{i}"),
            "id.orig_h": "10.0.0.1", "id.orig_p": 1234u16 + i as u16,
            "id.resp_h": "10.0.0.2", "id.resp_p": 443u16,
            "version": "TLSv13", "server_name": format!("h{i}.example.com"),
            "established": true, "unmodelled": i,
        })
    );

    accumulator_parity_test!(
        files_accumulator_matches_per_record_path,
        FilesAccumulator,
        append_files_row,
        files_schema,
        |i: i32| serde_json::json!({
            "ts": 1700000000.0 + i as f64, "fuid": format!("F{i}"),
            "source": "HTTP", "mime_type": "text/plain",
            "filename": format!("f{i}.txt"), "seen_bytes": 100u64 + i as u64,
            "unmodelled": i,
        })
    );

    accumulator_parity_test!(
        notice_accumulator_matches_per_record_path,
        NoticeAccumulator,
        append_notice_row,
        notice_schema,
        |i: i32| serde_json::json!({
            "ts": 1700000000.0 + i as f64, "uid": format!("C{i}"),
            "note": "Scan::Port_Scan", "msg": format!("m{i}"),
            "src": "10.0.0.1", "dst": "10.0.0.2", "unmodelled": i,
        })
    );

    /// Envelope takes an extra `log_path` argument, so it does not fit the
    /// macro above.
    #[test]
    fn envelope_accumulator_matches_per_record_path() {
        use crate::forwarding::buffered_writer::RecordBatchAccumulator;
        let records: Vec<serde_json::Value> = (0..4)
            .map(|i| serde_json::json!({ "ts": 1700000000.0 + i as f64, "uid": format!("C{i}"), "x": i }))
            .collect();

        let mut acc = EnvelopeAccumulator::new();
        for v in &records {
            append_envelope_row(&mut acc, v, "weird_stream", rx());
        }
        let actual = acc.finish().unwrap();
        assert_eq!(actual.num_rows(), records.len());

        // ingest_time is read per row and so legitimately differs between the
        // amortized and per-record paths; every OTHER column must match.
        let singles: Vec<RecordBatch> = records
            .iter()
            .map(|v| map_envelope(v, "weird_stream", rx()).unwrap())
            .collect();
        let expected = arrow::compute::concat_batches(&envelope_schema(), &singles).unwrap();
        for c in 0..expected.num_columns() {
            if expected.schema().field(c).name() == "ingest_time" {
                continue;
            }
            assert_eq!(
                format!("{:?}", actual.column(c)),
                format!("{:?}", expected.column(c)),
                "column {} differs",
                expected.schema().field(c).name()
            );
        }
    }

    /// An accumulator handed a record belonging to a DIFFERENT schema must
    /// return Ok(false) and append nothing, so push() falls back to
    /// to_record_batch for that record instead of writing it through the
    /// wrong builder set -- silent cross-schema data corruption.
    #[test]
    fn accumulators_reject_records_from_another_schema() {
        use crate::forwarding::buffered_writer::RecordBatchAccumulator;
        let http_rec = crate::zeek::ZeekRecord {
            log_path: "http".to_string(),
            fields: serde_json::json!({ "ts": 1700000000.0, "method": "GET" }),
            received_at: rx(),
        };
        let mut dns = DnsAccumulator::new();
        assert!(
            !dns.try_append(&http_rec, rx()).unwrap(),
            "dns accumulator must reject an http record"
        );
        assert_eq!(dns.len(), 0, "a rejected record must not add a row");

        let dns_rec = crate::zeek::ZeekRecord {
            log_path: "dns".to_string(),
            fields: serde_json::json!({ "ts": 1700000000.0, "query": "a.example.com" }),
            received_at: rx(),
        };
        let mut http = HttpAccumulator::new();
        assert!(!http.try_append(&dns_rec, rx()).unwrap());
        assert_eq!(http.len(), 0);
    }

    // --- conn schema tests ---

    #[test]
    fn conn_accumulator_matches_map_conn_output_row_for_row() {
        let records: Vec<serde_json::Value> = (0..5)
            .map(|i| {
                serde_json::json!({
                    "ts": 1700000000.0 + i as f64,
                    "uid": format!("C{i}"),
                    "id.orig_h": "10.0.0.1",
                    "id.orig_p": 12345u16 + i as u16,
                    "id.resp_h": "10.0.0.2",
                    "id.resp_p": 443u16,
                    "proto": "tcp",
                    "duration": 1.5,
                    "orig_bytes": 100u64 + i as u64,
                    "resp_bytes": 200u64,
                    "conn_state": "SF",
                    "orig_pkts": 3u64,
                    "resp_pkts": 4u64,
                })
            })
            .collect();

        // Baseline: today's exact per-record path, N single-row batches concatenated.
        let single_row_batches: Vec<RecordBatch> =
            records.iter().map(|v| map_conn(v, rx()).unwrap()).collect();
        let expected = arrow::compute::concat_batches(&conn_schema(), &single_row_batches).unwrap();

        // Amortized path: one accumulator, N appends, one finish.
        let mut acc = ConnAccumulator::new();
        for v in &records {
            assert!(acc.try_append_value(v, rx()).unwrap());
        }
        let actual = acc.finish().unwrap();

        assert_eq!(actual.num_rows(), expected.num_rows());
        assert_eq!(actual.schema(), expected.schema());
        for col_idx in 0..expected.num_columns() {
            assert_eq!(
                format!("{:?}", actual.column(col_idx)),
                format!("{:?}", expected.column(col_idx)),
                "column {col_idx} differs between amortized and per-record paths"
            );
        }
    }

    #[test]
    fn map_conn_still_produces_a_single_row_batch() {
        let v = serde_json::json!({"ts": 1700000000.0, "uid": "C1", "proto": "tcp"});
        let batch = map_conn(&v, rx()).unwrap();
        assert_eq!(batch.num_rows(), 1);
        assert_eq!(batch.schema(), conn_schema());
    }

    #[test]
    fn conn_schema_has_correct_fields() {
        let s = conn_schema();
        assert_eq!(s.fields().len(), 17);
        let f = s.field_with_name("ts").unwrap();
        assert_eq!(
            *f.data_type(),
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()))
        );
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
        let batch = map_conn(&json, rx()).unwrap();
        assert_eq!(batch.num_rows(), 1);
        assert_eq!(batch.num_columns(), 17);

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
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert_eq!(ts.value(0), 1_700_000_000_123_000);

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
        let batch = map_conn(&json, rx()).unwrap();
        let ts = batch
            .column_by_name("ts")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
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
    fn conn_ts_is_written_as_microseconds() {
        let v = serde_json::json!({ "ts": 1700000000.0, "uid": "C1" });
        let batch = map_conn(&v, rx()).unwrap();
        let col = batch
            .column_by_name("ts")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .expect("ts column should be TimestampMicrosecondArray");
        assert_eq!(col.value(0), 1_700_000_000_000_000);
    }

    #[test]
    fn conn_out_of_range_ts_is_null_and_preserved_in_extra() {
        let v = serde_json::json!({ "ts": 1e300, "uid": "C1" });
        let batch = map_conn(&v, rx()).unwrap();
        // The record is still written...
        assert_eq!(batch.num_rows(), 1);
        // ...the ts column is null...
        let col = batch
            .column_by_name("ts")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert!(col.is_null(0));
        // ...and the raw value survives in _extra via the existing
        // mismatches/build_extra path.
        let extra = batch
            .column_by_name("_extra")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let extra_json: serde_json::Value = serde_json::from_str(extra.value(0)).unwrap();
        assert!(
            extra_json.get("ts").is_some(),
            "the rejected raw ts value must be preserved in _extra, got: {}",
            extra.value(0)
        );
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
        let batch = map_conn(&json, rx()).unwrap();
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
        assert_eq!(s.fields().len(), 15);
        s.field_with_name("trans_id").expect("trans_id must exist");
        s.field_with_name("answers").expect("answers must exist");
        let f = s.field_with_name("trans_id").unwrap();
        assert_eq!(*f.data_type(), DataType::UInt32);
        let f = s.field_with_name("ts").unwrap();
        assert_eq!(
            *f.data_type(),
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()))
        );
        assert!(f.is_nullable());
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
        let batch = map_dns(&json, rx()).unwrap();
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
    fn http_schema_ts_is_nullable_microsecond_timestamp() {
        let s = http_schema();
        let f = s.field_with_name("ts").unwrap();
        assert_eq!(
            *f.data_type(),
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()))
        );
        assert!(f.is_nullable());
    }

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
        let batch = map_http(&json, rx()).unwrap();
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
    fn ssl_schema_ts_is_nullable_microsecond_timestamp() {
        let s = ssl_schema();
        let f = s.field_with_name("ts").unwrap();
        assert_eq!(
            *f.data_type(),
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()))
        );
        assert!(f.is_nullable());
    }

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
        let batch = map_ssl(&json, rx()).unwrap();
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
    fn files_schema_ts_is_nullable_microsecond_timestamp() {
        let s = files_schema();
        let f = s.field_with_name("ts").unwrap();
        assert_eq!(
            *f.data_type(),
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()))
        );
        assert!(f.is_nullable());
    }

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
        let batch = map_files(&json, rx()).unwrap();
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
    fn notice_schema_ts_is_nullable_microsecond_timestamp() {
        let s = notice_schema();
        let f = s.field_with_name("ts").unwrap();
        assert_eq!(
            *f.data_type(),
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()))
        );
        assert!(f.is_nullable());
    }

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
        let batch = map_notice(&json, rx()).unwrap();
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
        let batch = (entry.mapper)(&json, rx()).unwrap();
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

    #[test]
    fn get_schema_entry_resolves_case_and_rotation_variants() {
        let conn = get_schema_entry("conn");
        for raw in ["Conn", "CONN", "cOnN"] {
            assert!(
                Arc::ptr_eq(&get_schema_entry(raw).schema, &conn.schema),
                "{raw} must resolve to the typed conn schema"
            );
        }
        // The listener runs normalize_log_path first; the pair must compose.
        let rotated = crate::zeek::normalize_log_path("CONN.2026-08-14-16-08-44");
        assert!(Arc::ptr_eq(&get_schema_entry(rotated).schema, &conn.schema));
        // Hostile / non-ASCII inputs: no panic, envelope unless the sanitized key is real.
        for raw in ["Ｃonn", "../Conn", "", "weird"] {
            let e = get_schema_entry(raw);
            assert!(
                e.schema.field_with_name("payload").is_ok(),
                "{raw:?} must be envelope"
            );
        }
    }

    #[test]
    fn all_seven_schemas_have_a_non_nullable_microsecond_partition_time_column() {
        // All 7 Zeek schemas (6 typed + envelope) must carry a non-null
        // `partition_time` column of the same type, as the LAST field --
        // this is what lets every Zeek Parquet file stay day-clean even
        // though `ts` is nullable in every typed schema and 6 of the 7
        // schemas have no other non-null receipt column of their own.
        let expected_type = DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()));
        let schemas: Vec<(&str, Arc<Schema>)> = vec![
            ("conn", conn_schema()),
            ("dns", dns_schema()),
            ("http", http_schema()),
            ("ssl", ssl_schema()),
            ("files", files_schema()),
            ("notice", notice_schema()),
            ("envelope", envelope_schema()),
        ];
        for (name, schema) in &schemas {
            let f = schema
                .field_with_name("partition_time")
                .unwrap_or_else(|_| panic!("{name} schema must have a partition_time column"));
            assert_eq!(
                *f.data_type(),
                expected_type,
                "{name} schema's partition_time must be Timestamp(Microsecond, Some(UTC))"
            );
            assert!(
                !f.is_nullable(),
                "{name} schema's partition_time must be non-nullable"
            );
            assert_eq!(
                schema.fields().last().unwrap().name(),
                "partition_time",
                "{name} schema's partition_time must be the last field"
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
        let batch = map_conn(&json, rx()).unwrap();
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
        let batch = map_conn(&json, rx()).unwrap();
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

    // --- json_ts_micros helper ---

    #[test]
    fn json_ts_micros_converts_epoch_seconds() {
        let v = serde_json::json!({ "ts": 1700000000.0 });
        assert_eq!(json_ts_micros(&v, "ts"), Some(1_700_000_000_000_000));
    }

    #[test]
    fn json_ts_micros_preserves_sub_second_precision() {
        let v = serde_json::json!({ "ts": 1717171717.123456 });
        // f64 resolves to ~0.21us at this magnitude, so rounding to whole
        // microseconds is lossless relative to what the source can represent.
        assert_eq!(json_ts_micros(&v, "ts"), Some(1_717_171_717_123_456));
    }

    #[test]
    fn json_ts_micros_returns_none_for_absent_key() {
        let v = serde_json::json!({ "uid": "C1" });
        assert_eq!(json_ts_micros(&v, "ts"), None);
    }

    #[test]
    fn json_ts_micros_returns_none_for_non_numeric() {
        let v = serde_json::json!({ "ts": "not a number" });
        assert_eq!(json_ts_micros(&v, "ts"), None);
    }

    #[test]
    fn json_ts_micros_rejects_out_of_range() {
        // 1e300 is legal JSON. A bare `as i64` cast would saturate to
        // i64::MAX and present a nonsense timestamp as real data.
        let v = serde_json::json!({ "ts": 1e300 });
        assert_eq!(json_ts_micros(&v, "ts"), None);

        let v = serde_json::json!({ "ts": -1e300 });
        assert_eq!(json_ts_micros(&v, "ts"), None);
    }

    #[test]
    fn json_ts_micros_rejects_value_at_i64_max_boundary() {
        // i64::MAX (2^63 - 1) is not exactly representable as f64 -- the
        // ULP at that magnitude is 1024, so `i64::MAX as f64` rounds up to
        // 2^63. A ts of 9223372036854.775 seconds rounds to exactly
        // 2^63 microseconds, which is one past the largest valid i64 and
        // must be rejected, not saturated to i64::MAX by `as i64`.
        let v = serde_json::json!({ "ts": 9223372036854.775 });
        assert_eq!(json_ts_micros(&v, "ts"), None);

        // A large but genuinely representable value just under the
        // boundary must still convert -- the fix must not over-reject.
        let v = serde_json::json!({ "ts": 9223372036.854773 });
        assert_eq!(json_ts_micros(&v, "ts"), Some(9_223_372_036_854_772));
    }

    // --- zeek_partition_time helper ---

    #[test]
    fn zeek_partition_time_uses_ts_when_present_and_within_window() {
        // ts is a valid, in-window event timestamp on a distinctly different
        // day from received_at -- a test that accidentally asserted the
        // received_at fallback instead would fail loudly rather than
        // passing by coincidence.
        let fields = serde_json::json!({"ts": 1700000000.0}); // 2023-11-14T22:13:20Z
        let received_at = chrono::Utc.with_ymd_and_hms(2023, 11, 20, 8, 0, 0).unwrap();
        let expected = chrono::DateTime::from_timestamp_micros(1_700_000_000_000_000).unwrap();
        assert_eq!(zeek_partition_time(&fields, received_at), expected);
    }

    #[test]
    fn zeek_partition_time_falls_back_to_received_at_when_ts_missing() {
        let fields = serde_json::json!({"uid": "C1"});
        let received_at = chrono::Utc.with_ymd_and_hms(2030, 6, 15, 0, 0, 0).unwrap();
        assert_eq!(zeek_partition_time(&fields, received_at), received_at);
    }

    #[test]
    fn zeek_partition_time_falls_back_to_received_at_when_ts_malformed() {
        let fields = serde_json::json!({"ts": "not-a-number"});
        let received_at = chrono::Utc.with_ymd_and_hms(2030, 6, 15, 0, 0, 0).unwrap();
        assert_eq!(zeek_partition_time(&fields, received_at), received_at);
    }

    #[test]
    fn zeek_partition_time_falls_back_to_received_at_when_ts_far_outside_clamp_window() {
        // ts claims an event 90 days before received_at -- well past the
        // shared 30-day backfill clamp `partition_time` applies -- so this
        // must collapse onto received_at rather than mint a distant buffer.
        let received_at = chrono::Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let far_past = received_at - chrono::TimeDelta::days(90);
        let fields = serde_json::json!({"ts": far_past.timestamp() as f64});
        assert_eq!(zeek_partition_time(&fields, received_at), received_at);
    }

    #[test]
    fn zeek_partition_time_agrees_for_missing_and_present_ts_received_same_day() {
        // Regression test for the day-clean-partitions addendum: `ts` is
        // nullable in every typed Zeek schema, so a log path that sometimes
        // omits it could previously mix a real event instant and a
        // `now()`-derived fallback within one buffered file, yielding two
        // `day(ts)` partition values for a single Parquet file -- which
        // Iceberg rejects. Both records below are received on the same UTC
        // day; one carries a valid `ts`, the other omits it entirely. Both
        // must resolve to `partition_time` values on that same day, so a
        // file built from both rows stays day-clean.
        let received_at_1 = chrono::Utc.with_ymd_and_hms(2026, 4, 2, 1, 0, 0).unwrap();
        let received_at_2 = chrono::Utc.with_ymd_and_hms(2026, 4, 2, 23, 0, 0).unwrap();

        // Within the backfill window of both received_at values, same day.
        let ts_same_day = chrono::Utc.with_ymd_and_hms(2026, 4, 2, 0, 30, 0).unwrap();
        let with_ts = serde_json::json!({"ts": ts_same_day.timestamp() as f64});
        let without_ts = serde_json::json!({"uid": "no-ts-here"});

        let pt_1 = zeek_partition_time(&with_ts, received_at_1);
        let pt_2 = zeek_partition_time(&without_ts, received_at_2);

        assert_eq!(
            pt_1.date_naive(),
            pt_2.date_naive(),
            "a record with ts and one without, received the same day, must \
             partition onto the same day"
        );
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
        let batch = map_envelope(&json, "weird", rx()).unwrap();
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

    #[test]
    fn envelope_schema_ts_and_ingest_time_are_microsecond_timestamps() {
        let s = envelope_schema();
        let expected = DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()));

        let f = s.field_with_name("ts").unwrap();
        assert_eq!(*f.data_type(), expected);
        assert!(f.is_nullable());

        let f = s.field_with_name("ingest_time").unwrap();
        assert_eq!(*f.data_type(), expected);
        assert!(!f.is_nullable()); // ingest_time is server-generated, never null
    }

    #[test]
    fn envelope_out_of_range_ts_is_null_and_preserved_in_payload() {
        let v = serde_json::json!({ "ts": 1e300, "uid": "C1" });
        let batch = map_envelope(&v, "weird", rx()).unwrap();
        assert_eq!(batch.num_rows(), 1);

        let ts = batch
            .column_by_name("ts")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert!(ts.is_null(0));

        // map_envelope has no `mismatches` mechanism; it stores the entire raw
        // record in `payload` unconditionally, which preserves the value.
        let payload = batch
            .column_by_name("payload")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        // serde_json renders 1e300 as "1e+300", so parse and compare the
        // value rather than substring-matching the literal "1e300".
        let payload_json: serde_json::Value = serde_json::from_str(payload.value(0)).unwrap();
        assert_eq!(
            payload_json.get("ts"),
            Some(&serde_json::json!(1e300)),
            "the raw ts value must be preserved in payload, got: {}",
            payload.value(0)
        );
    }
}
