//! PII redaction for the HEC and OTLP ingest paths.
//!
//! A [`Redactor`] is compiled once at startup from a [`RedactionConfig`] and shared as an
//! `Arc`. Handlers call it immediately after parse/map and BEFORE
//! `crate::ingest::assign_event_uuids` and enqueue, so unredacted values never reach the
//! channel, the spool, or disk. Semantics are documented in `docs/redaction.md`.
//!
//! Fail closed: an `@body.<path>` drop/hash rule cannot be applied to an OTLP body that starts
//! with `{`/`[` but does not parse as JSON (too deeply nested, trailing comma, NaN, ...). Rather
//! than let the value through unredacted, the WHOLE body is replaced by `[REDACTED]` and
//! `redactions_applied{rule="body_unparseable"}` is incremented. Plain-text bodies (not
//! JSON-looking) are left alone by `@body.<path>` rules.

use std::sync::Arc;

use anyhow::{Context, bail};
use hmac::{Hmac, Mac};
use regex::{NoExpand, Regex, RegexBuilder};
use serde_json::Value;
use sha2::Sha256;

use crate::config::RedactionConfig;
use crate::forwarding::otlp_s3::OtlpRecord;
use crate::ingest::GenericRecord;

type HmacSha256 = Hmac<Sha256>;

/// Replacement text for regex matches.
pub const MASK_REPLACEMENT: &str = "[REDACTED]";
/// Shortest accepted HMAC key (bytes).
const MIN_HASH_KEY_BYTES: usize = 16;
/// Compiled-regex size cap so a pathological pattern fails at startup.
const REGEX_SIZE_LIMIT: usize = 1 << 20;

/// Which ingest surface a [`Redactor`] serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactorKind {
    /// HEC / NDJSON (`[hec.redaction]`).
    Hec,
    /// OTLP logs (`[otlp.redaction]`).
    Otlp,
}

impl RedactorKind {
    /// Bounded metric/log label.
    pub fn label(self) -> &'static str {
        match self {
            RedactorKind::Hec => "hec",
            RedactorKind::Otlp => "otlp",
        }
    }
}

/// Number of values changed by each rule type for one record.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct RedactionCounts {
    /// Values removed (or typed columns set to NULL).
    pub dropped: u64,
    /// Values replaced by their HMAC.
    pub hashed: u64,
    /// Regex matches replaced by `[REDACTED]`.
    pub masked: u64,
    /// JSON-looking OTLP bodies that failed to parse while an `@body.<path>` drop/hash rule was
    /// configured; the whole body was replaced by `[REDACTED]` (fail closed).
    pub body_unparseable: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Column {
    Body,
    HostName,
    PeerAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    /// Dotted path into JSON values.
    Json(String),
    /// OTLP typed column, optionally with a path inside a JSON body.
    Column(Column, Option<String>),
}

/// Compiled redaction rules. Cheap to share (`Arc`), immutable after construction.
pub struct Redactor {
    kind: RedactorKind,
    drops: Vec<Target>,
    hashes: Vec<Target>,
    masks: Vec<Regex>,
    key: Option<Vec<u8>>,
}

impl std::fmt::Debug for Redactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Redactor")
            .field("kind", &self.kind)
            .field("drops", &self.drops)
            .field("hashes", &self.hashes)
            .field("masks", &self.masks.len())
            .field("key", &self.key.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

fn is_env_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn validate_path(section: &str, rule: &str, path: &str) -> anyhow::Result<()> {
    if path.is_empty() || path.split('.').any(str::is_empty) {
        bail!("{section}.{rule}: invalid path {path:?} (empty path or empty segment)");
    }
    Ok(())
}

fn parse_target(
    kind: RedactorKind,
    section: &str,
    rule: &str,
    raw: &str,
) -> anyhow::Result<Target> {
    let Some(rest) = raw.strip_prefix('@') else {
        validate_path(section, rule, raw)?;
        return Ok(Target::Json(raw.to_string()));
    };
    if kind != RedactorKind::Otlp {
        bail!(
            "{section}.{rule}: {raw:?}: '@' typed-column paths are only valid for [otlp.redaction]"
        );
    }
    let (name, sub) = match rest.split_once('.') {
        Some((n, s)) => (n, Some(s)),
        None => (rest, None),
    };
    let column = match name {
        "body" => Column::Body,
        "host_name" => Column::HostName,
        "peer_addr" => Column::PeerAddr,
        other => bail!(
            "{section}.{rule}: @{other} is not redactable (allowed: @body, @host_name, \
             @peer_addr; service_name is the partition key and ids are join keys)"
        ),
    };
    if let Some(s) = sub {
        if column != Column::Body {
            bail!("{section}.{rule}: {raw:?}: only @body accepts a sub-path");
        }
        validate_path(section, rule, s)?;
    }
    Ok(Target::Column(column, sub.map(str::to_string)))
}

impl Redactor {
    /// Compile `cfg`, reading the HMAC key from the process environment.
    pub fn compile(cfg: &RedactionConfig, kind: RedactorKind) -> anyhow::Result<Redactor> {
        Self::compile_with_env(cfg, kind, &|n| std::env::var(n).ok())
    }

    /// Like [`Redactor::compile`] with an injectable environment (tests avoid `set_var`).
    pub fn compile_with_env(
        cfg: &RedactionConfig,
        kind: RedactorKind,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> anyhow::Result<Redactor> {
        let section = format!("[{}.redaction]", kind.label());
        let drops = cfg
            .drop_fields
            .iter()
            .map(|p| parse_target(kind, &section, "drop_fields", p))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let mut seen = std::collections::HashSet::new();
        if let Some(dup) = cfg.hash_fields.iter().find(|p| !seen.insert(p.as_str())) {
            bail!("{section}.hash_fields: duplicate path {dup:?} (a value would be hashed twice)");
        }
        let hashes = cfg
            .hash_fields
            .iter()
            .map(|p| parse_target(kind, &section, "hash_fields", p))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let masks = cfg
            .mask_patterns
            .iter()
            .map(|p| {
                if p.is_empty() {
                    bail!("{section} mask_patterns: empty pattern would match everywhere");
                }
                let re = RegexBuilder::new(p)
                    .size_limit(REGEX_SIZE_LIMIT)
                    .build()
                    .with_context(|| format!("{section} mask_patterns: invalid regex {p:?}"))?;
                // `x*`, `^`, `\b` ... match the empty string at every position and would
                // splice "[REDACTED]" between every character; reject them at startup.
                let min_len = regex_syntax::parse(p)
                    .with_context(|| format!("{section} mask_patterns: invalid regex {p:?}"))?
                    .properties()
                    .minimum_len();
                if min_len == Some(0) {
                    bail!(
                        "{section} mask_patterns: pattern {p:?} can match the empty string \
                         (it would redact everywhere); require at least one character"
                    );
                }
                Ok(re)
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let key = if hashes.is_empty() {
            None
        } else {
            let name = cfg
                .hash_key_env
                .as_deref()
                .filter(|n| !n.is_empty())
                .with_context(|| format!("{section}: hash_fields requires hash_key_env"))?;
            // Never echo the value: an operator may have pasted the key itself here.
            if !is_env_identifier(name) {
                bail!(
                    "{section}: hash_key_env is not a valid environment variable name \
                     (expected letters, digits and underscores, not starting with a digit); \
                     it must be the NAME of the variable, not the key"
                );
            }
            let value = env(name).with_context(|| {
                format!("{section}: hash_key_env names {name}, which is not set in the environment")
            })?;
            if value.len() < MIN_HASH_KEY_BYTES {
                bail!("{section}: the key in ${name} is shorter than {MIN_HASH_KEY_BYTES} bytes");
            }
            Some(value.into_bytes())
        };
        Ok(Redactor {
            kind,
            drops,
            hashes,
            masks,
            key,
        })
    }

    /// `Ok(None)` for an empty config (no rules -> no per-record work at all).
    pub fn compile_optional(
        cfg: &RedactionConfig,
        kind: RedactorKind,
    ) -> anyhow::Result<Option<Arc<Redactor>>> {
        if cfg.is_empty() {
            return Ok(None);
        }
        Self::compile(cfg, kind).map(|r| Some(Arc::new(r)))
    }

    fn hmac_hex(&self, input: &[u8]) -> String {
        let key = self.key.as_deref().expect("hash rule implies key");
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(input);
        hex::encode(mac.finalize().into_bytes())
    }

    fn hash_value(&self, v: &Value) -> Option<String> {
        match v {
            Value::Null => None,
            Value::String(s) => Some(self.hmac_hex(s.as_bytes())),
            other => {
                let mut text = String::new();
                canonical_json(other, &mut text);
                Some(self.hmac_hex(text.as_bytes()))
            }
        }
    }

    fn emit(&self, c: RedactionCounts) -> RedactionCounts {
        let source = self.kind.label();
        for (rule, n) in [
            ("drop", c.dropped),
            ("hash", c.hashed),
            ("mask", c.masked),
            ("body_unparseable", c.body_unparseable),
        ] {
            if n > 0 {
                metrics::counter!("redactions_applied", "source" => source, "rule" => rule)
                    .increment(n);
            }
        }
        c
    }

    /// Redact a parsed HEC/NDJSON record in place (`fields` and `indexed_fields`).
    pub fn redact_generic(&self, rec: &mut GenericRecord) -> RedactionCounts {
        let mut c = RedactionCounts::default();
        for t in &self.drops {
            if let Target::Json(p) = t {
                c.dropped += apply_path(&mut rec.fields, p, &PathOp::Drop);
                if let Some(v) = rec.indexed_fields.as_mut() {
                    c.dropped += apply_path(v, p, &PathOp::Drop);
                }
            }
        }
        for t in &self.hashes {
            if let Target::Json(p) = t {
                c.hashed += apply_path(&mut rec.fields, p, &PathOp::Hash(self));
                if let Some(v) = rec.indexed_fields.as_mut() {
                    c.hashed += apply_path(v, p, &PathOp::Hash(self));
                }
            }
        }
        for re in &self.masks {
            c.masked += mask_value(&mut rec.fields, re);
            if let Some(v) = rec.indexed_fields.as_mut() {
                c.masked += mask_value(v, re);
            }
        }
        self.emit(c)
    }

    /// Redact a mapped OTLP record in place.
    pub fn redact_otlp(&self, rec: &mut OtlpRecord) -> RedactionCounts {
        let mut c = RedactionCounts::default();
        for t in &self.drops {
            match t {
                Target::Json(p) => {
                    c.dropped += apply_path(&mut rec.attributes, p, &PathOp::Drop);
                    c.dropped += apply_path(&mut rec.resource_attributes, p, &PathOp::Drop);
                }
                Target::Column(col, None) => {
                    let slot = column_slot(rec, *col);
                    if slot.take().is_some() {
                        c.dropped += 1;
                    }
                }
                Target::Column(_, Some(sub)) => {
                    match edit_json_body(&mut rec.body, |v| apply_path(v, sub, &PathOp::Drop)) {
                        Some(n) => c.dropped += n,
                        None => c.body_unparseable += fail_closed_body(&mut rec.body),
                    }
                }
            }
        }
        for t in &self.hashes {
            match t {
                Target::Json(p) => {
                    c.hashed += apply_path(&mut rec.attributes, p, &PathOp::Hash(self));
                    c.hashed += apply_path(&mut rec.resource_attributes, p, &PathOp::Hash(self));
                }
                Target::Column(col, None) => {
                    let slot = column_slot(rec, *col);
                    if let Some(s) = slot.as_deref() {
                        let h = self.hmac_hex(s.as_bytes());
                        *slot = Some(h);
                        c.hashed += 1;
                    }
                }
                Target::Column(_, Some(sub)) => {
                    match edit_json_body(&mut rec.body, |v| apply_path(v, sub, &PathOp::Hash(self)))
                    {
                        Some(n) => c.hashed += n,
                        None => c.body_unparseable += fail_closed_body(&mut rec.body),
                    }
                }
            }
        }
        for re in &self.masks {
            c.masked += mask_value(&mut rec.attributes, re);
            c.masked += mask_value(&mut rec.resource_attributes, re);
            c.masked += mask_body(&mut rec.body, re);
        }
        self.emit(c)
    }
}

fn column_slot(rec: &mut OtlpRecord, col: Column) -> &mut Option<String> {
    match col {
        Column::Body => &mut rec.body,
        Column::HostName => &mut rec.host_name,
        Column::PeerAddr => &mut rec.peer_addr,
    }
}

enum PathOp<'a> {
    Drop,
    Hash(&'a Redactor),
}

/// Apply `op` at every location matching `path` below `v`; returns locations changed.
fn apply_path(v: &mut Value, path: &str, op: &PathOp<'_>) -> u64 {
    match v {
        Value::Array(items) => items.iter_mut().map(|i| apply_path(i, path, op)).sum(),
        Value::Object(map) => {
            let mut n = 0;
            // The whole remaining path as one literal key (OTLP keys contain dots).
            match op {
                PathOp::Drop => {
                    if map.remove(path).is_some() {
                        n += 1;
                    }
                }
                PathOp::Hash(r) => {
                    if let Some(slot) = map.get_mut(path)
                        && let Some(h) = r.hash_value(slot)
                    {
                        *slot = Value::String(h);
                        n += 1;
                    }
                }
            }
            // Every '.'-prefix that is itself a key: descend with the remainder.
            for (i, _) in path.match_indices('.') {
                let (prefix, rest) = (&path[..i], &path[i + 1..]);
                if let Some(child) = map.get_mut(prefix) {
                    n += apply_path(child, rest, op);
                }
            }
            n
        }
        _ => 0,
    }
}

/// Recursive, sorted-key, whitespace-free JSON text used as the hash input for non-strings.
fn canonical_json(v: &Value, out: &mut String) {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(k.clone()).to_string());
                out.push(':');
                canonical_json(&m[k], out);
            }
            out.push('}');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, e) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical_json(e, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

/// Replace regex matches in every string leaf; returns number of matches replaced.
fn mask_value(v: &mut Value, re: &Regex) -> u64 {
    match v {
        Value::String(s) => mask_str(s, re, MASK_REPLACEMENT),
        Value::Array(a) => a.iter_mut().map(|e| mask_value(e, re)).sum(),
        Value::Object(m) => m.values_mut().map(|e| mask_value(e, re)).sum(),
        _ => 0,
    }
}

fn mask_str(s: &mut String, re: &Regex, replacement: &str) -> u64 {
    let n = re.find_iter(s).count() as u64;
    if n > 0 {
        *s = re.replace_all(s, NoExpand(replacement)).into_owned();
    }
    n
}

/// Parse `body` as JSON when it looks like an object/array, run `f`, and re-serialize only
/// when `f` reported a change (so an unchanged body stays byte-identical). Returns `Some(0)`
/// for an absent or plain-text body and `None` when the body looks like JSON but does not
/// parse (the caller must fail closed).
fn edit_json_body(body: &mut Option<String>, f: impl FnOnce(&mut Value) -> u64) -> Option<u64> {
    let Some(text) = body.as_deref() else {
        return Some(0);
    };
    if !matches!(text.trim_start().as_bytes().first(), Some(b'{' | b'[')) {
        return Some(0);
    }
    let mut v = serde_json::from_str::<Value>(text).ok()?;
    let n = f(&mut v);
    if n > 0 {
        *body = Some(v.to_string());
    }
    Some(n)
}

/// Replace an unredactable body wholesale; returns the count to add.
fn fail_closed_body(body: &mut Option<String>) -> u64 {
    *body = Some(MASK_REPLACEMENT.to_string());
    1
}

/// Mask a body: JSON bodies are masked leaf-wise, plain-text bodies as a whole string.
fn mask_body(body: &mut Option<String>, re: &Regex) -> u64 {
    let is_json = body.as_deref().is_some_and(|t| {
        matches!(t.trim_start().as_bytes().first(), Some(b'{' | b'['))
            && serde_json::from_str::<Value>(t).is_ok()
    });
    if is_json {
        edit_json_body(body, |v| mask_value(v, re)).unwrap_or(0)
    } else if let Some(s) = body.as_mut() {
        mask_str(s, re, MASK_REPLACEMENT)
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RedactionConfig;
    use crate::forwarding::otlp_s3::OtlpRecord;
    use crate::ingest::GenericRecord;
    use serde_json::json;

    const KEY: &str = "0123456789abcdef";

    fn env(name: &str) -> Option<String> {
        (name == "TEST_KEY").then(|| KEY.to_string())
    }

    fn cfg(drop: &[&str], hash: &[&str], mask: &[&str]) -> RedactionConfig {
        RedactionConfig {
            drop_fields: drop.iter().map(|s| s.to_string()).collect(),
            hash_fields: hash.iter().map(|s| s.to_string()).collect(),
            hash_key_env: (!hash.is_empty()).then(|| "TEST_KEY".to_string()),
            mask_patterns: mask.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn hec(drop: &[&str], hash: &[&str], mask: &[&str]) -> Redactor {
        Redactor::compile_with_env(&cfg(drop, hash, mask), RedactorKind::Hec, &env).unwrap()
    }

    fn otlp(drop: &[&str], hash: &[&str], mask: &[&str]) -> Redactor {
        Redactor::compile_with_env(&cfg(drop, hash, mask), RedactorKind::Otlp, &env).unwrap()
    }

    fn generic(fields: serde_json::Value) -> GenericRecord {
        GenericRecord {
            sourcetype: "t".into(),
            host: None,
            time: None,
            fields,
            received_at: chrono::Utc::now(),
            event_uuid: None,
            source: None,
            index: None,
            indexed_fields: None,
        }
    }

    fn otlp_rec() -> OtlpRecord {
        OtlpRecord {
            event_uuid: None,
            time: None,
            observed_time: None,
            received_at: chrono::Utc::now(),
            severity_number: None,
            severity_text: None,
            body: None,
            service_name: Some("checkout".into()),
            service_namespace: None,
            service_instance_id: None,
            host_name: Some("host-1".into()),
            peer_addr: Some("10.0.0.9".into()),
            trace_id: None,
            span_id: None,
            flags: None,
            event_name: None,
            scope_name: None,
            scope_version: None,
            resource_attributes: json!({}),
            attributes: json!({}),
        }
    }

    #[test]
    fn test_drop_removes_top_level_nested_and_array_element_paths() {
        let r = hec(&["password", "user.ssn", "items.secret"], &[], &[]);
        let mut rec = generic(json!({
            "password": "p", "keep": 1,
            "user": {"ssn": "123", "name": "bob"},
            "items": [{"secret": "a", "id": 1}, {"secret": "b", "id": 2}, 7]
        }));
        let c = r.redact_generic(&mut rec);
        assert_eq!(
            rec.fields,
            json!({"keep": 1, "user": {"name": "bob"}, "items": [{"id": 1}, {"id": 2}, 7]})
        );
        assert_eq!(c.dropped, 4);
    }

    #[test]
    fn test_drop_literal_dotted_key_and_nested_key_both_match() {
        let r = otlp(&["user.email"], &[], &[]);
        let mut rec = otlp_rec();
        rec.attributes = json!({"user.email": "a@b.co", "user": {"email": "c@d.co", "id": 1}});
        rec.resource_attributes = json!({"user.email": "r@r.co"});
        let c = r.redact_otlp(&mut rec);
        assert_eq!(rec.attributes, json!({"user": {"id": 1}}));
        assert_eq!(rec.resource_attributes, json!({}));
        assert_eq!(c.dropped, 3);
    }

    #[test]
    fn test_drop_missing_path_is_a_noop() {
        let r = hec(&["nope.deeper"], &[], &[]);
        let mut rec = generic(json!({"a": 1}));
        assert_eq!(r.redact_generic(&mut rec), RedactionCounts::default());
        assert_eq!(rec.fields, json!({"a": 1}));
    }

    #[test]
    fn test_hash_known_answer_and_hex_shape() {
        let r = hec(&[], &["email"], &[]);
        let mut rec = generic(json!({"email": "alice@example.com", "n": 42}));
        let c = r.redact_generic(&mut rec);
        assert_eq!(
            rec.fields["email"],
            json!("f3d6ddc7dbf9be2eb667360a5a9a43434c54e345f522bbb433afeba094d74aa2")
        );
        assert_eq!(rec.fields["n"], json!(42));
        assert_eq!(c.hashed, 1);
    }

    #[test]
    fn test_hash_non_string_uses_canonical_json_text() {
        let r = hec(&[], &["n", "obj"], &[]);
        let mut a = generic(json!({"n": 42, "obj": {"b": 1, "a": [true, null]}}));
        let mut b = generic(json!({"n": 42, "obj": {"a": [true, null], "b": 1}}));
        r.redact_generic(&mut a);
        r.redact_generic(&mut b);
        // number hashes its JSON text "42"
        assert_eq!(
            a.fields["n"],
            json!("8d24a2a526d5f556469db8b6280e3a7b877a41155ca536be3a1f2a9d2be0eacd")
        );
        // key order does not change the object hash
        assert_eq!(a.fields["obj"], b.fields["obj"]);
        assert_eq!(a.fields["obj"].as_str().unwrap().len(), 64);
    }

    #[test]
    fn test_hash_null_is_left_null_and_array_elements_are_each_hashed() {
        let r = hec(&[], &["x", "tags.id"], &[]);
        let mut rec = generic(json!({"x": null, "tags": [{"id": "a"}, {"id": "b"}]}));
        let c = r.redact_generic(&mut rec);
        assert_eq!(rec.fields["x"], json!(null));
        assert_ne!(rec.fields["tags"][0]["id"], rec.fields["tags"][1]["id"]);
        assert_eq!(c.hashed, 2);
    }

    #[test]
    fn test_hash_differs_by_key() {
        let other = |n: &str| (n == "TEST_KEY").then(|| "fedcba9876543210".to_string());
        let r1 = hec(&[], &["e"], &[]);
        let r2 =
            Redactor::compile_with_env(&cfg(&[], &["e"], &[]), RedactorKind::Hec, &other).unwrap();
        let (mut a, mut b) = (generic(json!({"e": "x"})), generic(json!({"e": "x"})));
        r1.redact_generic(&mut a);
        r2.redact_generic(&mut b);
        assert_ne!(a.fields, b.fields);
    }

    #[test]
    fn test_mask_reaches_nested_arrays_and_skips_non_strings_and_keys() {
        let r = hec(&[], &[], &[r"\d{3}-\d{2}-\d{4}"]);
        let mut rec = generic(json!({
            "note": "ssn 123-45-6789 ok", "123-45-6789": "key stays",
            "list": ["a", {"deep": ["999-88-7777 and 111-22-3333"]}],
            "num": 123456789, "flag": true, "nil": null
        }));
        let c = r.redact_generic(&mut rec);
        assert_eq!(rec.fields["note"], json!("ssn [REDACTED] ok"));
        assert_eq!(rec.fields["123-45-6789"], json!("key stays"));
        assert_eq!(
            rec.fields["list"][1]["deep"][0],
            json!("[REDACTED] and [REDACTED]")
        );
        assert_eq!(rec.fields["num"], json!(123456789));
        assert_eq!(c.masked, 3);
    }

    #[test]
    fn test_mask_on_bare_string_fields_root_as_in_hec_raw() {
        let r = hec(&[], &[], &["secret=\\w+"]);
        let mut rec = generic(json!("login secret=abc123 done"));
        r.redact_generic(&mut rec);
        assert_eq!(rec.fields, json!("login [REDACTED] done"));
    }

    #[test]
    fn test_mask_replacement_text_is_literal_not_expanded() {
        // With expansion, "$1-$1" would yield "xa-ay"; NoExpand keeps it literal.
        let re = Regex::new("(a)").unwrap();
        let mut s = String::from("xay");
        assert_eq!(mask_str(&mut s, &re, "$1-$1"), 1);
        assert_eq!(s, "x$1-$1y");
        // And the production path uses the fixed literal.
        let r = hec(&[], &[], &["(a)"]);
        let mut rec = generic(json!({"v": "xay"}));
        r.redact_generic(&mut rec);
        assert_eq!(rec.fields["v"], json!("x[REDACTED]y"));
    }

    #[test]
    fn test_hash_output_survives_an_email_mask_pattern() {
        let r = hec(&[], &["email"], &[r"[\w.]+@[\w.]+", r"\d{9,}"]);
        let mut rec = generic(json!({"email": "alice@example.com"}));
        r.redact_generic(&mut rec);
        let h = rec.fields["email"].as_str().unwrap();
        assert_eq!(h.len(), 64);
        assert!(
            h.chars().all(|c| c.is_ascii_hexdigit()),
            "hash was mangled: {h}"
        );
    }

    #[test]
    fn test_drop_runs_before_hash_before_mask() {
        let r = hec(&["a"], &["a", "b"], &["[0-9a-f]{64}"]);
        let mut rec = generic(json!({"a": "x", "b": "y"}));
        let c = r.redact_generic(&mut rec);
        assert!(rec.fields.get("a").is_none());
        // b was hashed (64 hex) and then the (deliberately aggressive) mask consumed it
        assert_eq!(rec.fields["b"], json!("[REDACTED]"));
        assert_eq!((c.dropped, c.hashed, c.masked), (1, 1, 1));
    }

    #[test]
    fn test_hec_rules_apply_to_indexed_fields_too() {
        let r = hec(&["secret"], &[], &[]);
        let mut rec = generic(json!({"secret": 1}));
        rec.indexed_fields = Some(json!({"secret": "s", "keep": "k"}));
        r.redact_generic(&mut rec);
        assert_eq!(rec.indexed_fields, Some(json!({"keep": "k"})));
    }

    #[test]
    fn test_otlp_typed_columns_drop_hash_and_json_body_paths() {
        let r = otlp(&["@host_name", "@body.card"], &["@peer_addr"], &[]);
        let mut rec = otlp_rec();
        rec.body = Some(r#"{"card": "4111", "msg": "hi"}"#.into());
        let c = r.redact_otlp(&mut rec);
        assert_eq!(rec.host_name, None);
        assert_eq!(rec.peer_addr.as_deref().map(str::len), Some(64));
        assert_eq!(rec.body.as_deref(), Some(r#"{"msg":"hi"}"#));
        assert_eq!((c.dropped, c.hashed), (2, 1));
        // untouched typed columns
        assert_eq!(rec.service_name.as_deref(), Some("checkout"));
    }

    #[test]
    fn test_otlp_body_path_on_plain_text_body_is_noop() {
        let r = otlp(&["@body.card"], &[], &[]);
        let mut rec = otlp_rec();
        rec.body = Some("card=4111".into());
        assert_eq!(r.redact_otlp(&mut rec), RedactionCounts::default());
        assert_eq!(rec.body.as_deref(), Some("card=4111"));
    }

    #[test]
    fn test_otlp_drop_whole_body_sets_null() {
        let r = otlp(&["@body"], &[], &[]);
        let mut rec = otlp_rec();
        rec.body = Some("x".into());
        r.redact_otlp(&mut rec);
        assert_eq!(rec.body, None);
    }

    #[test]
    fn test_otlp_mask_covers_attributes_resource_and_both_body_shapes_but_not_typed_ids() {
        let r = otlp(&[], &[], &[r"checkout|\d{4}-\d{4}"]);
        let mut rec = otlp_rec();
        rec.attributes = json!({"card": "1234-5678", "n": [1, "9999-0000"]});
        rec.resource_attributes = json!({"service.name": "checkout"});
        rec.body = Some("paid 1111-2222".into());
        let c = r.redact_otlp(&mut rec);
        assert_eq!(
            rec.attributes,
            json!({"card": "[REDACTED]", "n": [1, "[REDACTED]"]})
        );
        assert_eq!(
            rec.resource_attributes,
            json!({"service.name": "[REDACTED]"})
        );
        assert_eq!(rec.body.as_deref(), Some("paid [REDACTED]"));
        // service_name (the partition key) is never masked
        assert_eq!(rec.service_name.as_deref(), Some("checkout"));
        assert_eq!(c.masked, 4);
    }

    #[test]
    fn test_otlp_json_body_without_match_is_byte_identical() {
        let r = otlp(&[], &[], &["zzz"]);
        let mut rec = otlp_rec();
        let original = "{ \"a\" :  1,\n \"b\": \"x\" }";
        rec.body = Some(original.into());
        r.redact_otlp(&mut rec);
        assert_eq!(rec.body.as_deref(), Some(original));
    }

    #[test]
    fn test_otlp_json_body_masks_string_leaves_only() {
        let r = otlp(&[], &[], &["secret"]);
        let mut rec = otlp_rec();
        rec.body = Some(r#"{"secret": "my secret", "n": 1}"#.into());
        r.redact_otlp(&mut rec);
        assert_eq!(
            rec.body.as_deref(),
            Some(r#"{"n":1,"secret":"my [REDACTED]"}"#)
        );
    }

    #[test]
    fn test_compile_rejects_bad_regex_empty_pattern_and_oversized_pattern() {
        for bad in ["(", "", "a{1000}{1000}{1000}"] {
            let e = Redactor::compile_with_env(&cfg(&[], &[], &[bad]), RedactorKind::Hec, &env)
                .unwrap_err()
                .to_string();
            assert!(e.contains("mask_patterns"), "{bad:?} -> {e}");
        }
    }

    #[test]
    fn test_compile_rejects_missing_short_or_unnamed_hash_key() {
        let c = cfg(&[], &["e"], &[]);
        let missing = Redactor::compile_with_env(&c, RedactorKind::Hec, &|_| None).unwrap_err();
        assert!(missing.to_string().contains("TEST_KEY"), "{missing}");
        let short = Redactor::compile_with_env(&c, RedactorKind::Hec, &|_| Some("short".into()))
            .unwrap_err();
        assert!(short.to_string().contains("16"), "{short}");
        assert!(
            !short.to_string().contains("short\""),
            "key value leaked: {short}"
        );
        let mut unnamed = c.clone();
        unnamed.hash_key_env = None;
        let e = Redactor::compile_with_env(&unnamed, RedactorKind::Hec, &env).unwrap_err();
        assert!(e.to_string().contains("hash_key_env"), "{e}");
    }

    #[test]
    fn test_compile_rejects_bad_paths_and_wrong_kind_columns() {
        for (kind, p) in [
            (RedactorKind::Hec, "a..b"),
            (RedactorKind::Hec, ".a"),
            (RedactorKind::Hec, ""),
            (RedactorKind::Hec, "@body"),
            (RedactorKind::Otlp, "@service_name"),
            (RedactorKind::Otlp, "@trace_id"),
            (RedactorKind::Otlp, "@host_name.x"),
        ] {
            assert!(
                Redactor::compile_with_env(&cfg(&[p], &[], &[]), kind, &env).is_err(),
                "{kind:?} {p:?} must be rejected"
            );
        }
    }

    #[test]
    fn test_compile_optional_is_none_for_empty_config() {
        let r = Redactor::compile_optional(&RedactionConfig::default(), RedactorKind::Hec);
        assert!(r.unwrap().is_none());
    }

    #[test]
    fn test_debug_output_never_contains_the_key() {
        let r = hec(&[], &["e"], &[]);
        assert!(!format!("{r:?}").contains(KEY));
    }

    #[test]
    fn test_compile_rejects_mask_patterns_that_can_match_the_empty_string() {
        for bad in ["x*", r"\b", "^", "$", "(?:)", "a|", "(a)?", r"\B"] {
            let e = Redactor::compile_with_env(&cfg(&[], &[], &[bad]), RedactorKind::Hec, &env)
                .unwrap_err()
                .to_string();
            assert!(
                e.contains("mask_patterns") && e.contains("empty"),
                "{bad:?} -> {e}"
            );
        }
        // A pattern that needs at least one character is fine.
        assert!(
            Redactor::compile_with_env(&cfg(&[], &[], &["x+"]), RedactorKind::Hec, &env).is_ok()
        );
    }

    #[test]
    fn test_hash_of_typed_column_equals_hash_of_same_text_attribute() {
        let r = otlp(&["@host_name"], &["@peer_addr", "who"], &[]);
        let mut rec = otlp_rec();
        rec.peer_addr = Some("alice@x.com".into());
        rec.attributes = json!({"who": "alice@x.com"});
        r.redact_otlp(&mut rec);
        assert_eq!(rec.peer_addr.as_deref(), rec.attributes["who"].as_str());
    }

    #[test]
    fn test_otlp_hash_inside_json_body_path() {
        let r = otlp(&[], &["@body.user"], &[]);
        let mut rec = otlp_rec();
        rec.body = Some(r#"{"user":"bob","n":1}"#.into());
        let c = r.redact_otlp(&mut rec);
        let v: serde_json::Value = serde_json::from_str(rec.body.as_deref().unwrap()).unwrap();
        assert_eq!(v["user"].as_str().map(str::len), Some(64));
        assert_eq!(v["n"], json!(1));
        assert_eq!(c.hashed, 1);
    }

    #[test]
    fn test_otlp_unprefixed_drop_applies_to_attributes_and_resource_attributes() {
        let r = otlp(&["token"], &[], &[]);
        let mut rec = otlp_rec();
        rec.attributes = json!({"token": "a", "k": 1});
        rec.resource_attributes = json!({"token": "b"});
        let c = r.redact_otlp(&mut rec);
        assert_eq!(rec.attributes, json!({"k": 1}));
        assert_eq!(rec.resource_attributes, json!({}));
        assert_eq!(c.dropped, 2);
    }

    #[test]
    fn test_redactions_applied_counter_emitted_per_rule_only_when_nonzero() {
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = metrics::set_default_local_recorder(&recorder);
        let r = hec(&["a"], &[], &["zzz", "b+"]);
        let mut rec = generic(json!({"a": 1, "s": "abbc"}));
        r.redact_generic(&mut rec);
        let mut seen: Vec<(String, String, u64)> = snapshotter
            .snapshot()
            .into_vec()
            .into_iter()
            .filter(|(k, ..)| k.key().name() == "redactions_applied")
            .map(|(k, _, _, v)| {
                let label = |n: &str| {
                    k.key()
                        .labels()
                        .find(|l| l.key() == n)
                        .map(|l| l.value().to_string())
                        .unwrap()
                };
                let DebugValue::Counter(n) = v else {
                    panic!("not a counter")
                };
                (label("source"), label("rule"), n)
            })
            .collect();
        seen.sort();
        // no "hash" series: zero counts emit nothing
        assert_eq!(
            seen,
            vec![
                ("hec".to_string(), "drop".to_string(), 1),
                ("hec".to_string(), "mask".to_string(), 1),
            ]
        );
    }

    #[test]
    fn test_redactor_kind_labels() {
        assert_eq!(RedactorKind::Hec.label(), "hec");
        assert_eq!(RedactorKind::Otlp.label(), "otlp");
    }

    fn body_rule_redactor() -> Redactor {
        otlp(&["@body.card"], &[], &[])
    }

    #[test]
    fn test_otlp_body_path_fails_closed_on_too_deep_json() {
        let r = body_rule_redactor();
        let mut rec = otlp_rec();
        let deep = format!("{}1{}", "[".repeat(200), "]".repeat(200));
        rec.body = Some(deep);
        let c = r.redact_otlp(&mut rec);
        assert_eq!(rec.body.as_deref(), Some("[REDACTED]"));
        assert_eq!(c.body_unparseable, 1);
        assert_eq!(c.dropped, 0);
    }

    #[test]
    fn test_otlp_body_path_fails_closed_on_trailing_comma_for_drop_and_hash() {
        for r in [body_rule_redactor(), otlp(&[], &["@body.card"], &[])] {
            let mut rec = otlp_rec();
            rec.body = Some(r#"  {"card": "4111", "msg": "hi",}"#.into());
            let c = r.redact_otlp(&mut rec);
            assert_eq!(rec.body.as_deref(), Some("[REDACTED]"));
            assert_eq!(c.body_unparseable, 1);
        }
    }

    #[test]
    fn test_otlp_body_path_only_rules_leave_plain_text_body_unchanged() {
        let r = body_rule_redactor();
        let mut rec = otlp_rec();
        rec.body = Some("not json {card: 4111".into());
        let c = r.redact_otlp(&mut rec);
        assert_eq!(rec.body.as_deref(), Some("not json {card: 4111"));
        assert_eq!(c, RedactionCounts::default());
    }

    #[test]
    fn test_compile_rejects_non_identifier_hash_key_env_without_echoing_it() {
        let secret = "0123456789abcdef-pasted key!";
        let mut c = cfg(&[], &["e"], &[]);
        c.hash_key_env = Some(secret.to_string());
        let e = Redactor::compile_with_env(&c, RedactorKind::Hec, &|_| Some(KEY.into()))
            .unwrap_err()
            .to_string();
        assert!(e.contains("hash_key_env"), "{e}");
        assert!(
            !e.contains(secret) && !e.contains("pasted"),
            "value echoed: {e}"
        );
        c.hash_key_env = Some("1BAD".to_string());
        assert!(Redactor::compile_with_env(&c, RedactorKind::Hec, &|_| Some(KEY.into())).is_err());
    }

    #[test]
    fn test_compile_rejects_duplicate_hash_fields_naming_the_path() {
        let e = Redactor::compile_with_env(
            &cfg(&[], &["email", "ip", "email"], &[]),
            RedactorKind::Hec,
            &env,
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("duplicate") && e.contains("\"email\""), "{e}");
    }
}
