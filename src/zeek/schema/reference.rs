//! Frozen copy of the pre-fix-4 Zeek row-mapping code (`json_*`, `build_extra`, every
//! `*Accumulator`, `append_*`), taken verbatim from master ac4d97d. Test-only: it is the
//! byte-parity oracle for the single-pass rewrite in the parent module. Do not "fix" or tidy
//! anything below the `use` line; if the real behaviour is meant to change, change the oracle
//! deliberately in its own commit.
#![allow(dead_code, unused_imports, clippy::all)]

use super::*;

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
pub(crate) fn map_envelope(
    value: &serde_json::Value,
    log_path: &str,
    received_at: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<RecordBatch> {
    let mut acc = EnvelopeAccumulator::new();
    append_envelope_row(&mut acc, value, log_path, received_at);
    acc.finish_batch()
}
// ---------------------------------------------------------------------------

mod parity;
