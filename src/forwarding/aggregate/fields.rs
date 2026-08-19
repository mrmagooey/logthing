//! Field access for aggregation: one small adapter per source record type.
//!
//! Group-by columns and numeric aggregates both go through `AggFields::field`,
//! so a rule can name any field of any source without the aggregator knowing
//! which source it came from.

use std::borrow::Cow;

/// A single scalar field value read off a record.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldValue<'a> {
    Str(Cow<'a, str>),
    Num(f64),
    Bool(bool),
}

/// The per-source adapter contract.
pub trait AggFields {
    /// Stream name a rule's optional `stream` filter matches against.
    fn stream(&self) -> &str;
    /// Look up one field by the name a rule configured.
    fn field(&self, name: &str) -> Option<FieldValue<'_>>;
}

/// Cap on a single group value. Bounds worst-case aggregator memory to
/// `max_groups * group_by.len() * MAX_GROUP_VALUE_BYTES` per rule.
//
// ponytail: fixed 256-byte cap, so two keys sharing a 256-byte prefix merge
// into one group. Raise the constant if that ever matters.
pub const MAX_GROUP_VALUE_BYTES: usize = 256;

/// Truncate to at most `max` bytes, walking back to the nearest char boundary
/// so the result is always valid UTF-8.
pub fn truncate_to_bytes(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Render a field value as a group-key component.
pub fn group_value_string(v: FieldValue<'_>) -> String {
    let s = match v {
        FieldValue::Str(s) => return truncate_to_bytes(&s, MAX_GROUP_VALUE_BYTES).to_string(),
        // Whole numbers render as integers: a port grouped as "443", not "443.0".
        FieldValue::Num(n)
            if n.is_finite() && n.fract() == 0.0 && n.abs() < 9.007_199_254_740_992e15 =>
        {
            (n as i64).to_string()
        }
        // `{n:?}` (not `to_string`): Display drops the decimal point for whole
        // floats beyond the i64-shortcut range (e.g. "9007199254740994"),
        // while Debug always keeps it ("...994.0"), which is what a value
        // that hit this fallback needs to still look like a float.
        FieldValue::Num(n) => format!("{n:?}"),
        FieldValue::Bool(b) => b.to_string(),
    };
    // Numeric and boolean renderings are always short, but truncate uniformly
    // so the memory bound holds for every branch.
    truncate_to_bytes(&s, MAX_GROUP_VALUE_BYTES).to_string()
}

/// Numeric contribution of a field value to a sum/min/max accumulator.
///
/// SQL semantics: a value that isn't a usable number contributes nothing (the
/// record is still counted). Numeric strings parse — Zeek and Suricata JSON
/// carry numbers as strings in places, and treating those as absent would
/// produce surprising all-null columns.
pub fn numeric_value(v: &FieldValue<'_>) -> Option<f64> {
    let n = match v {
        FieldValue::Num(n) => *n,
        FieldValue::Str(s) => s.parse::<f64>().ok()?,
        FieldValue::Bool(_) => return None,
    };
    n.is_finite().then_some(n)
}

/// JSON field lookup: literal key first, then a dotted path.
///
/// Zeek NDJSON carries `"id.orig_h"` as one flat key; Suricata EVE nests
/// `dns.rrname`. Trying the literal key first means a flat key always wins,
/// which is what the source that produced it intended.
pub fn json_field<'a>(root: &'a serde_json::Value, name: &str) -> Option<FieldValue<'a>> {
    if let Some(v) = root.get(name) {
        return scalar(v);
    }
    if !name.contains('.') {
        return None;
    }
    let mut cur = root;
    for seg in name.split('.') {
        cur = cur.get(seg)?;
    }
    scalar(cur)
}

/// Map a JSON scalar to a `FieldValue`. Objects, arrays, and null are misses —
/// they are not group-able scalars.
fn scalar(v: &serde_json::Value) -> Option<FieldValue<'_>> {
    match v {
        serde_json::Value::String(s) => Some(FieldValue::Str(Cow::Borrowed(s.as_str()))),
        serde_json::Value::Number(n) => n.as_f64().map(FieldValue::Num),
        serde_json::Value::Bool(b) => Some(FieldValue::Bool(*b)),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Per-source impls: JSON-backed records
// ---------------------------------------------------------------------------

impl AggFields for crate::zeek::ZeekRecord {
    fn stream(&self) -> &str {
        &self.log_path
    }
    fn field(&self, name: &str) -> Option<FieldValue<'_>> {
        json_field(&self.fields, name)
    }
}

impl AggFields for crate::suricata::SuricataRecord {
    fn stream(&self) -> &str {
        &self.event_type
    }
    fn field(&self, name: &str) -> Option<FieldValue<'_>> {
        json_field(&self.fields, name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;

    // -- group_value_string --

    #[test]
    fn integral_numbers_stringify_without_a_decimal_point() {
        assert_eq!(group_value_string(FieldValue::Num(443.0)), "443");
        assert_eq!(group_value_string(FieldValue::Num(-1.0)), "-1");
        assert_eq!(group_value_string(FieldValue::Num(0.0)), "0");
    }

    #[test]
    fn fractional_and_huge_numbers_keep_float_formatting() {
        assert_eq!(group_value_string(FieldValue::Num(1.5)), "1.5");
        // Beyond 2^53 the i64 shortcut is not safe; fall back to float form.
        let big = 9.007199254740994e15_f64;
        assert!(
            group_value_string(FieldValue::Num(big)).contains('e')
                || group_value_string(FieldValue::Num(big)).contains('.')
        );
    }

    #[test]
    fn booleans_stringify_as_true_false() {
        assert_eq!(group_value_string(FieldValue::Bool(true)), "true");
        assert_eq!(group_value_string(FieldValue::Bool(false)), "false");
    }

    #[test]
    fn strings_longer_than_the_cap_are_truncated() {
        let long = "a".repeat(MAX_GROUP_VALUE_BYTES + 50);
        let out = group_value_string(FieldValue::Str(Cow::Owned(long)));
        assert_eq!(out.len(), MAX_GROUP_VALUE_BYTES);
    }

    // -- truncate_to_bytes --

    #[test]
    fn truncation_never_splits_a_multibyte_char() {
        // 'é' is 2 bytes; a cap landing mid-char must walk back.
        let s = "é".repeat(200); // 400 bytes
        let out = truncate_to_bytes(&s, 255);
        assert!(out.len() <= 255);
        assert_eq!(out.len() % 2, 0, "must not split a 2-byte char");
        assert!(s.starts_with(out));
    }

    #[test]
    fn truncation_leaves_short_strings_alone() {
        assert_eq!(truncate_to_bytes("short", 256), "short");
    }

    // -- numeric_value --

    #[test]
    fn numeric_value_accepts_numbers_and_numeric_strings() {
        assert_eq!(numeric_value(&FieldValue::Num(7.0)), Some(7.0));
        assert_eq!(
            numeric_value(&FieldValue::Str(Cow::Borrowed("42"))),
            Some(42.0)
        );
        assert_eq!(
            numeric_value(&FieldValue::Str(Cow::Borrowed("1.5"))),
            Some(1.5)
        );
    }

    #[test]
    fn numeric_value_rejects_non_numeric_bool_and_non_finite() {
        assert_eq!(numeric_value(&FieldValue::Str(Cow::Borrowed("abc"))), None);
        assert_eq!(numeric_value(&FieldValue::Bool(true)), None);
        assert_eq!(numeric_value(&FieldValue::Num(f64::NAN)), None);
        assert_eq!(numeric_value(&FieldValue::Num(f64::INFINITY)), None);
    }

    // -- json_field --

    #[test]
    fn json_lookup_prefers_a_literal_dotted_key() {
        // Zeek NDJSON carries "id.orig_h" as ONE flat key.
        let v = serde_json::json!({"id.orig_h": "10.0.0.1", "id": {"orig_h": "WRONG"}});
        match json_field(&v, "id.orig_h") {
            Some(FieldValue::Str(s)) => assert_eq!(s, "10.0.0.1"),
            other => panic!("expected the flat key, got {other:?}"),
        }
    }

    #[test]
    fn json_lookup_falls_back_to_a_dotted_path() {
        // Suricata EVE nests: {"dns": {"rrname": "example.com"}}
        let v = serde_json::json!({"dns": {"rrname": "example.com"}});
        match json_field(&v, "dns.rrname") {
            Some(FieldValue::Str(s)) => assert_eq!(s, "example.com"),
            other => panic!("expected nested lookup, got {other:?}"),
        }
    }

    #[test]
    fn json_lookup_maps_scalar_types_and_misses() {
        let v = serde_json::json!({"n": 5, "f": 1.5, "b": true, "nil": null});
        assert!(matches!(json_field(&v, "n"), Some(FieldValue::Num(n)) if n == 5.0));
        assert!(matches!(json_field(&v, "f"), Some(FieldValue::Num(n)) if n == 1.5));
        assert!(matches!(json_field(&v, "b"), Some(FieldValue::Bool(true))));
        assert!(json_field(&v, "nil").is_none(), "null is a miss");
        assert!(json_field(&v, "absent").is_none());
        // Objects and arrays are not group-able scalars.
        let nested = serde_json::json!({"o": {"a": 1}, "arr": [1, 2]});
        assert!(json_field(&nested, "o").is_none());
        assert!(json_field(&nested, "arr").is_none());
    }

    // -- AggFields impls --

    #[test]
    fn zeek_record_exposes_stream_and_fields() {
        let rec = crate::zeek::ZeekRecord {
            log_path: "dns".to_string(),
            fields: serde_json::json!({"_path": "dns", "query": "example.com", "AA": false}),
            received_at: chrono::Utc::now(),
        };
        assert_eq!(rec.stream(), "dns");
        assert!(matches!(rec.field("query"), Some(FieldValue::Str(s)) if s == "example.com"));
        assert!(matches!(rec.field("AA"), Some(FieldValue::Bool(false))));
        assert!(rec.field("nope").is_none());
    }

    #[test]
    fn suricata_record_exposes_event_type_as_stream() {
        let rec = crate::suricata::SuricataRecord {
            event_type: "dns".to_string(),
            fields: serde_json::json!({"event_type": "dns", "dns": {"rrname": "a.example"}}),
            received_at: chrono::Utc::now(),
        };
        assert_eq!(rec.stream(), "dns");
        assert!(matches!(rec.field("dns.rrname"), Some(FieldValue::Str(s)) if s == "a.example"));
    }
}
