# Log Aggregation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Count log records as they arrive, grouped by configured columns, and write the resulting table to Parquet instead of the raw rows — the output of an SQL `GROUP BY`.

**Architecture:** A decorator handler wraps each source's existing handler chain. Records matching an aggregation rule are counted in an in-memory map and **not** forwarded downstream (suppression); everything else passes through untouched. A background task drains the map on an interval into `AggregateRow`s, which flow through the existing `PartitionedParquetWriter` machinery via a new `AggregateSink` adapter.

**Tech Stack:** Rust 2024, tokio, arrow/parquet, serde, `metrics`. No new dependencies.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-08-18-log-aggregation-design.md`. Read it before starting.
- Branch: `feat/log-aggregation`. Never commit to `master`.
- **No new dependencies.** Everything needed is already in `Cargo.toml`.
- Sources in scope: zeek, suricata, syslog, ipfix, sflow. **Not** wef/hec/otlp.
- All new modules live under `src/forwarding/aggregate/`.
- Deliberate simplifications get a `// ponytail:` comment naming the ceiling and the upgrade path.
- Every task ends with `cargo test` passing and `cargo clippy --all-targets -- -D warnings` clean.
- Run `cargo fmt` before every commit.

---

### Task 1: Aggregation config types and validation

**Files:**
- Modify: `src/config/mod.rs` (add types near the other per-source config structs; add `pub aggregate: AggregateConfig` to `struct Config`)

**Interfaces:**
- Consumes: `S3ConnectionConfig` (existing, `#[serde(flatten)]`-ed by other sources).
- Produces:
  ```rust
  pub struct AggregateConfig {
      pub enabled: bool,                       // default false
      pub flush_interval_secs: u64,            // default 900
      pub max_groups: usize,                   // default 100_000
      pub channel_capacity: usize,             // default 4096
      pub s3: Option<AggregateS3Config>,
      pub local: Option<AggregateLocalConfig>,
      pub rules: Vec<AggregateRule>,           // default empty
  }
  pub struct AggregateS3Config { pub connection: S3ConnectionConfig, pub prefix: String }
  pub struct AggregateLocalConfig { pub directory: PathBuf, pub prefix: String }
  pub struct AggregateRule {
      pub name: String,
      pub source: String,
      pub stream: Option<String>,
      pub group_by: Vec<String>,
      pub sum: Vec<String>,
      pub min: Vec<String>,
      pub max: Vec<String>,
  }
  ```

- [ ] **Step 1: Write the failing tests**

Add to the `#[cfg(test)] mod tests` block in `src/config/mod.rs`:

```rust
#[test]
fn aggregate_config_defaults_to_disabled_and_inert() {
    let cfg: AggregateConfig = toml::from_str("").expect("empty aggregate section parses");
    assert!(!cfg.enabled, "aggregation must default to off");
    assert_eq!(cfg.flush_interval_secs, 900);
    assert_eq!(cfg.max_groups, 100_000);
    assert!(cfg.rules.is_empty());
    assert!(cfg.s3.is_none());
    assert!(cfg.local.is_none());
}

#[test]
fn aggregate_rule_parses_full_toml_shape() {
    let toml_src = r#"
enabled = true
flush_interval_secs = 300
max_groups = 5000

[local]
directory = "/data/agg"
prefix = "aggregate"

[[rules]]
name = "dns_by_query"
source = "zeek"
stream = "dns"
group_by = ["query", "id.orig_h"]

[[rules]]
name = "flow_talkers"
source = "ipfix"
group_by = ["src_addr", "dst_addr"]
sum = ["octet_delta_count"]
"#;
    let cfg: AggregateConfig = toml::from_str(toml_src).expect("parses");
    assert!(cfg.enabled);
    assert_eq!(cfg.flush_interval_secs, 300);
    assert_eq!(cfg.max_groups, 5000);
    assert_eq!(cfg.rules.len(), 2);

    assert_eq!(cfg.rules[0].name, "dns_by_query");
    assert_eq!(cfg.rules[0].stream.as_deref(), Some("dns"));
    assert_eq!(cfg.rules[0].group_by, vec!["query", "id.orig_h"]);
    assert!(cfg.rules[0].sum.is_empty(), "omitted sum must default empty");

    assert_eq!(cfg.rules[1].source, "ipfix");
    assert_eq!(cfg.rules[1].stream, None, "omitted stream means all records");
    assert_eq!(cfg.rules[1].sum, vec!["octet_delta_count"]);

    let local = cfg.local.expect("local target present");
    assert_eq!(local.directory, std::path::PathBuf::from("/data/agg"));
    assert_eq!(local.prefix, "aggregate");
}

#[test]
fn aggregate_local_prefix_defaults_to_aggregate() {
    let cfg: AggregateLocalConfig =
        toml::from_str(r#"directory = "/tmp/x""#).expect("parses without prefix");
    assert_eq!(cfg.prefix, "aggregate");
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib config::tests::aggregate`
Expected: FAIL — `cannot find type AggregateConfig in this scope`.

- [ ] **Step 3: Implement the config types**

Add to `src/config/mod.rs`, following the existing per-source config style (serde defaults via named functions, `#[serde(flatten)]` for the S3 connection):

```rust
/// Optional aggregation: count records as they arrive, grouped by configured
/// columns, and write the counted table to Parquet instead of the raw rows.
/// Disabled by default — absent from TOML means nothing changes.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AggregateConfig {
    #[serde(default = "default_aggregate_enabled")]
    pub enabled: bool,
    /// Window length: drives both the emit tick and the writer's flush age.
    #[serde(default = "default_aggregate_flush_secs")]
    pub flush_interval_secs: u64,
    /// Per-rule, per-window distinct-group cap. Beyond this, new keys fold
    /// into that rule's single `_other` row.
    #[serde(default = "default_aggregate_max_groups")]
    pub max_groups: usize,
    #[serde(default = "default_aggregate_channel_capacity")]
    pub channel_capacity: usize,
    #[serde(default)]
    pub s3: Option<AggregateS3Config>,
    #[serde(default)]
    pub local: Option<AggregateLocalConfig>,
    #[serde(default)]
    pub rules: Vec<AggregateRule>,
}

impl Default for AggregateConfig {
    fn default() -> Self {
        Self {
            enabled: default_aggregate_enabled(),
            flush_interval_secs: default_aggregate_flush_secs(),
            max_groups: default_aggregate_max_groups(),
            channel_capacity: default_aggregate_channel_capacity(),
            s3: None,
            local: None,
            rules: Vec::new(),
        }
    }
}

fn default_aggregate_enabled() -> bool {
    false
}
fn default_aggregate_flush_secs() -> u64 {
    900
}
fn default_aggregate_max_groups() -> usize {
    100_000
}
fn default_aggregate_channel_capacity() -> usize {
    4096
}
fn default_aggregate_prefix() -> String {
    "aggregate".to_string()
}

/// S3 destination for aggregated tables. One writer serves every rule
/// regardless of which source the rule reads from — `AggregateRow` is
/// source-agnostic.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AggregateS3Config {
    #[serde(flatten)]
    pub connection: S3ConnectionConfig,
    #[serde(default = "default_aggregate_prefix")]
    pub prefix: String,
}

/// Local-disk destination for aggregated tables. Independent of `s3` — both
/// may be set, in which case rows are written to both.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AggregateLocalConfig {
    pub directory: PathBuf,
    #[serde(default = "default_aggregate_prefix")]
    pub prefix: String,
}

/// One `GROUP BY` rule.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AggregateRule {
    /// Unique; becomes the output partition segment.
    pub name: String,
    /// One of: zeek, suricata, syslog, ipfix, sflow.
    pub source: String,
    /// Optional stream filter — zeek `_path`, suricata `event_type`, syslog
    /// `app_name`, sflow `"flow"`/`"counter"`, ipfix `"flows"`. Omitted means
    /// every record from that source.
    #[serde(default)]
    pub stream: Option<String>,
    pub group_by: Vec<String>,
    #[serde(default)]
    pub sum: Vec<String>,
    #[serde(default)]
    pub min: Vec<String>,
    #[serde(default)]
    pub max: Vec<String>,
}
```

Add the field to `struct Config` alongside the other sections:

```rust
    #[serde(default)]
    pub aggregate: AggregateConfig,
```

`Config` has a hand-written `impl Default` (around `src/config/mod.rs:998`) — add the field there too, or the build breaks:

```rust
            aggregate: AggregateConfig::default(),
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib config::tests::aggregate`
Expected: PASS (3 tests).

- [ ] **Step 5: Verify nothing else broke, then commit**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
git add src/config/mod.rs
git commit -m "feat(aggregate): config types for group-by aggregation rules"
```

---

### Task 2: `AggFields` trait, `FieldValue`, and group-value formatting

**Files:**
- Create: `src/forwarding/aggregate/mod.rs` (module root — for this task only `pub mod fields;` plus the re-exports below)
- Create: `src/forwarding/aggregate/fields.rs`
- Modify: `src/forwarding/mod.rs` (add `pub mod aggregate;`)

**Interfaces:**
- Consumes: `crate::zeek::ZeekRecord`, `crate::suricata::SuricataRecord`.
- Produces:
  ```rust
  pub enum FieldValue<'a> { Str(Cow<'a, str>), Num(f64), Bool(bool) }
  pub trait AggFields {
      fn stream(&self) -> &str;
      fn field(&self, name: &str) -> Option<FieldValue<'_>>;
  }
  pub const MAX_GROUP_VALUE_BYTES: usize = 256;
  pub fn group_value_string(v: FieldValue<'_>) -> String;
  pub fn numeric_value(v: &FieldValue<'_>) -> Option<f64>;
  pub fn truncate_to_bytes(s: &str, max: usize) -> &str;
  pub fn json_field<'a>(root: &'a serde_json::Value, name: &str) -> Option<FieldValue<'a>>;
  ```

- [ ] **Step 1: Write the failing tests**

Create `src/forwarding/aggregate/fields.rs` containing ONLY this test module for now (implementation comes in step 3):

```rust
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
        assert!(group_value_string(FieldValue::Num(big)).contains('e')
            || group_value_string(FieldValue::Num(big)).contains('.'));
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
        assert_eq!(numeric_value(&FieldValue::Str(Cow::Borrowed("42"))), Some(42.0));
        assert_eq!(numeric_value(&FieldValue::Str(Cow::Borrowed("1.5"))), Some(1.5));
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
```

- [ ] **Step 2: Run the tests to verify they fail**

First create `src/forwarding/aggregate/mod.rs` with just `pub mod fields;` and add `pub mod aggregate;` to `src/forwarding/mod.rs`, then:

Run: `cargo test --lib aggregate::fields`
Expected: FAIL — `cannot find type FieldValue in this scope`.

- [ ] **Step 3: Implement `fields.rs`**

Prepend to `src/forwarding/aggregate/fields.rs` (above the test module):

```rust
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
        FieldValue::Num(n) if n.is_finite() && n.fract() == 0.0 && n.abs() < 9.007_199_254_740_992e15 => {
            (n as i64).to_string()
        }
        FieldValue::Num(n) => n.to_string(),
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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib aggregate::fields`
Expected: PASS (11 tests).

- [ ] **Step 5: Commit**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
git add src/forwarding/mod.rs src/forwarding/aggregate/
git commit -m "feat(aggregate): AggFields trait, FieldValue, group-value formatting"
```

---

### Task 3: `AggFields` for the typed record types (ipfix, sflow, syslog)

**Files:**
- Modify: `src/forwarding/aggregate/fields.rs`

**Interfaces:**
- Consumes: `FieldValue`, `AggFields`, `json_field` (Task 2); `crate::ipfix::FlowRecord`, `crate::sflow::{SflowRecord, SampleType}`, `crate::syslog::SyslogMessage`.
- Produces: `impl AggFields for FlowRecord | SflowRecord | SyslogMessage`.

**Notes:** These records are typed structs, not JSON. Match the configured name against the curated fields, then fall back to the record's `extra` JSON (ipfix/sflow) or `structured_data` (syslog). `IpAddr`, `DateTime`, and enum fields render via `to_string()` into `FieldValue::Str`. Numeric fields become `FieldValue::Num`.

- [ ] **Step 1: Write the failing tests**

Add to the `mod tests` block in `src/forwarding/aggregate/fields.rs`:

```rust
    #[test]
    fn flow_record_exposes_curated_fields_and_extra_fallback() {
        use std::net::{IpAddr, Ipv4Addr};
        let rec = crate::ipfix::FlowRecord {
            observation_domain_id: 1,
            template_id: 256,
            protocol_version: 10,
            exporter: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            export_time: chrono::Utc::now(),
            src_addr: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5))),
            dst_addr: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            src_port: Some(51000),
            dst_port: Some(443),
            ip_protocol: Some(6),
            octet_delta_count: Some(4096),
            packet_delta_count: Some(8),
            flow_start: None,
            flow_end: None,
            tcp_flags: None,
            input_interface: None,
            output_interface: None,
            extra: serde_json::json!({"vendorField": 12}),
        };
        assert_eq!(rec.stream(), "flows");
        assert!(matches!(rec.field("src_addr"), Some(FieldValue::Str(s)) if s == "192.168.1.5"));
        assert!(matches!(rec.field("dst_port"), Some(FieldValue::Num(n)) if n == 443.0));
        assert!(
            matches!(rec.field("octet_delta_count"), Some(FieldValue::Num(n)) if n == 4096.0)
        );
        // Absent Option field is a miss, not a zero.
        assert!(rec.field("tcp_flags").is_none());
        // Unknown name falls through to `extra`.
        assert!(matches!(rec.field("vendorField"), Some(FieldValue::Num(n)) if n == 12.0));
        assert!(rec.field("no_such_field").is_none());
    }

    #[test]
    fn sflow_record_stream_distinguishes_flow_from_counter() {
        use std::net::{IpAddr, Ipv4Addr};
        let mut rec = crate::sflow::SflowRecord {
            sample_type: crate::sflow::SampleType::Flow,
            exporter: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            received_at: chrono::Utc::now(),
            src_addr: Some(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1))),
            dst_addr: None,
            src_port: None,
            dst_port: Some(80),
            ip_protocol: Some(6),
            sampling_rate: Some(512),
            input_ifindex: None,
            output_ifindex: None,
            if_index: None,
            if_type: None,
            if_speed: None,
            if_direction: None,
            if_in_octets: None,
            if_out_octets: None,
            if_in_ucast_pkts: None,
            if_out_ucast_pkts: None,
            if_in_errors: None,
            if_out_errors: None,
            extra: serde_json::json!({}),
        };
        assert_eq!(rec.stream(), "flow");
        assert!(matches!(rec.field("src_addr"), Some(FieldValue::Str(s)) if s == "10.1.1.1"));
        assert!(matches!(rec.field("sampling_rate"), Some(FieldValue::Num(n)) if n == 512.0));

        rec.sample_type = crate::sflow::SampleType::Counter;
        assert_eq!(rec.stream(), "counter");
    }

    #[test]
    fn syslog_message_exposes_app_name_as_stream_and_curated_fields() {
        let msg = crate::syslog::SyslogMessage {
            priority: 34,
            severity: 2,
            facility: 4,
            timestamp: None,
            hostname: Some("host-a".to_string()),
            app_name: Some("sshd".to_string()),
            proc_id: None,
            msg_id: None,
            message: "Failed password".to_string(),
            structured_data: None,
            protocol: crate::syslog::SyslogProtocol::Rfc5424,
        };
        assert_eq!(msg.stream(), "sshd");
        assert!(matches!(msg.field("hostname"), Some(FieldValue::Str(s)) if s == "host-a"));
        assert!(matches!(msg.field("severity"), Some(FieldValue::Num(n)) if n == 2.0));
        assert!(matches!(msg.field("message"), Some(FieldValue::Str(s)) if s == "Failed password"));
        assert!(msg.field("proc_id").is_none());
    }

    #[test]
    fn syslog_message_without_app_name_has_an_empty_stream() {
        let msg = crate::syslog::SyslogMessage {
            priority: 13,
            severity: 5,
            facility: 1,
            timestamp: None,
            hostname: None,
            app_name: None,
            proc_id: None,
            msg_id: None,
            message: "x".to_string(),
            structured_data: None,
            protocol: crate::syslog::SyslogProtocol::Rfc3164,
        };
        assert_eq!(msg.stream(), "");
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib aggregate::fields`
Expected: FAIL — no method named `stream` found for struct `FlowRecord`.

- [ ] **Step 3: Implement the three typed impls**

Append to `src/forwarding/aggregate/fields.rs` (above `mod tests`):

```rust
// ---------------------------------------------------------------------------
// Per-source impls: typed records
// ---------------------------------------------------------------------------

/// Helper: `Option<T: Display>` → `FieldValue::Str`.
fn opt_str<T: std::fmt::Display>(v: &Option<T>) -> Option<FieldValue<'static>> {
    v.as_ref().map(|x| FieldValue::Str(Cow::Owned(x.to_string())))
}

/// Helper: `Option<T: Into<f64>>` → `FieldValue::Num`.
fn opt_num<T: Copy + Into<f64>>(v: &Option<T>) -> Option<FieldValue<'static>> {
    v.map(|x| FieldValue::Num(x.into()))
}

impl AggFields for crate::ipfix::FlowRecord {
    fn stream(&self) -> &str {
        // IPFIX has no stream concept; one bucket keeps rule matching uniform.
        "flows"
    }
    fn field(&self, name: &str) -> Option<FieldValue<'_>> {
        match name {
            "observation_domain_id" => Some(FieldValue::Num(self.observation_domain_id as f64)),
            "template_id" => Some(FieldValue::Num(self.template_id as f64)),
            "protocol_version" => Some(FieldValue::Num(self.protocol_version as f64)),
            "exporter" => Some(FieldValue::Str(Cow::Owned(self.exporter.to_string()))),
            "export_time" => Some(FieldValue::Str(Cow::Owned(self.export_time.to_rfc3339()))),
            "src_addr" => opt_str(&self.src_addr),
            "dst_addr" => opt_str(&self.dst_addr),
            "src_port" => opt_num(&self.src_port),
            "dst_port" => opt_num(&self.dst_port),
            "ip_protocol" => opt_num(&self.ip_protocol),
            "octet_delta_count" => self.octet_delta_count.map(|v| FieldValue::Num(v as f64)),
            "packet_delta_count" => self.packet_delta_count.map(|v| FieldValue::Num(v as f64)),
            "flow_start" => opt_str(&self.flow_start.map(|t| t.to_rfc3339())),
            "flow_end" => opt_str(&self.flow_end.map(|t| t.to_rfc3339())),
            "tcp_flags" => opt_num(&self.tcp_flags),
            "input_interface" => opt_num(&self.input_interface),
            "output_interface" => opt_num(&self.output_interface),
            // Non-curated IEs land in `extra` keyed by IE name.
            other => json_field(&self.extra, other),
        }
    }
}

impl AggFields for crate::sflow::SflowRecord {
    fn stream(&self) -> &str {
        match self.sample_type {
            crate::sflow::SampleType::Flow => "flow",
            crate::sflow::SampleType::Counter => "counter",
        }
    }
    fn field(&self, name: &str) -> Option<FieldValue<'_>> {
        match name {
            "exporter" => Some(FieldValue::Str(Cow::Owned(self.exporter.to_string()))),
            "received_at" => Some(FieldValue::Str(Cow::Owned(self.received_at.to_rfc3339()))),
            "src_addr" => opt_str(&self.src_addr),
            "dst_addr" => opt_str(&self.dst_addr),
            "src_port" => opt_num(&self.src_port),
            "dst_port" => opt_num(&self.dst_port),
            "ip_protocol" => opt_num(&self.ip_protocol),
            "sampling_rate" => opt_num(&self.sampling_rate),
            "input_ifindex" => opt_num(&self.input_ifindex),
            "output_ifindex" => opt_num(&self.output_ifindex),
            "if_index" => opt_num(&self.if_index),
            "if_type" => opt_num(&self.if_type),
            "if_speed" => self.if_speed.map(|v| FieldValue::Num(v as f64)),
            "if_direction" => opt_num(&self.if_direction),
            "if_in_octets" => self.if_in_octets.map(|v| FieldValue::Num(v as f64)),
            "if_out_octets" => self.if_out_octets.map(|v| FieldValue::Num(v as f64)),
            "if_in_ucast_pkts" => self.if_in_ucast_pkts.map(|v| FieldValue::Num(v as f64)),
            "if_out_ucast_pkts" => self.if_out_ucast_pkts.map(|v| FieldValue::Num(v as f64)),
            "if_in_errors" => opt_num(&self.if_in_errors),
            "if_out_errors" => opt_num(&self.if_out_errors),
            other => json_field(&self.extra, other),
        }
    }
}

impl AggFields for crate::syslog::SyslogMessage {
    fn stream(&self) -> &str {
        self.app_name.as_deref().unwrap_or("")
    }
    fn field(&self, name: &str) -> Option<FieldValue<'_>> {
        match name {
            "priority" => Some(FieldValue::Num(self.priority as f64)),
            "severity" => Some(FieldValue::Num(self.severity as f64)),
            "facility" => Some(FieldValue::Num(self.facility as f64)),
            "timestamp" => opt_str(&self.timestamp.map(|t| t.to_rfc3339())),
            "hostname" => self
                .hostname
                .as_deref()
                .map(|s| FieldValue::Str(Cow::Borrowed(s))),
            "app_name" => self
                .app_name
                .as_deref()
                .map(|s| FieldValue::Str(Cow::Borrowed(s))),
            "proc_id" => self
                .proc_id
                .as_deref()
                .map(|s| FieldValue::Str(Cow::Borrowed(s))),
            "msg_id" => self
                .msg_id
                .as_deref()
                .map(|s| FieldValue::Str(Cow::Borrowed(s))),
            "message" => Some(FieldValue::Str(Cow::Borrowed(self.message.as_str()))),
            // RFC 5424 structured data: "sdid.param" addresses one parameter.
            other => {
                let sd = self.structured_data.as_ref()?;
                let (sdid, param) = other.split_once('.')?;
                sd.get(sdid)
                    .and_then(|params| params.get(param))
                    .map(|s| FieldValue::Str(Cow::Borrowed(s.as_str())))
            }
        }
    }
}
```

If `SampleType` or `SyslogProtocol` are not already `pub` at those paths, re-export rather than changing their definitions.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib aggregate::fields`
Expected: PASS (15 tests).

- [ ] **Step 5: Commit**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
git add src/forwarding/aggregate/fields.rs
git commit -m "feat(aggregate): AggFields for ipfix, sflow, and syslog records"
```

---

### Task 4: `Aggregator` core — rules, group map, SQL aggregate semantics, cardinality cap

**Files:**
- Modify: `src/forwarding/aggregate/mod.rs`

**Interfaces:**
- Consumes: `AggFields`, `FieldValue`, `group_value_string`, `numeric_value` (Tasks 2-3); `crate::config::{Config, AggregateRule}`.
- Produces:
  ```rust
  pub enum AggKind { Sum, Min, Max }
  pub struct AggSpec { pub kind: AggKind, pub field: String, pub column: String }
  pub struct CompiledRule {
      pub name: Arc<str>,
      pub source: String,
      pub stream: Option<String>,
      pub group_by: Vec<String>,
      pub aggs: Vec<AggSpec>,
      pub schema: Arc<arrow_schema::Schema>,   // filled in Task 5; `Schema::empty()` for now
  }
  pub fn compile_rules(config: &Config) -> anyhow::Result<Vec<CompiledRule>>;
  pub struct Aggregator { /* private */ }
  impl Aggregator {
      pub fn new(rules: Vec<CompiledRule>, max_groups: usize) -> Self;
      pub fn consume<R: AggFields>(&self, source: &str, rec: &R) -> bool;
      pub fn drain(&self, window_start: DateTime<Utc>, window_end: DateTime<Utc>) -> Vec<AggregateRow>;
  }
  pub struct AggregateRow {
      pub rule: Arc<str>,
      pub keys: Vec<Option<String>>,
      pub count: u64,
      pub aggs: Vec<Option<f64>>,
      pub window_start: DateTime<Utc>,
      pub window_end: DateTime<Utc>,
  }
  pub const OTHER_LABEL: &str = "_other";
  ```

**Notes on semantics (from the spec — implement exactly):**
- A record is offered to every rule whose `source` matches and whose `stream` is `None` or equal to `rec.stream()`. **All** matching rules count it. `consume` returns `true` if ≥1 rule matched.
- A missing group-by field becomes `None` (null column); the record is still counted.
- Sum/min/max ignore missing, non-numeric, and non-finite values. A group that never saw a numeric value for a column emits `None` (SQL NULL), never `0.0`.
- At `max_groups` for a rule, a new key folds into `GroupKey::Other`, which accumulates count **and** every aggregate exactly like a normal group.

- [ ] **Step 1: Write the failing tests**

Add to `src/forwarding/aggregate/mod.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn rule(name: &str, source: &str, stream: Option<&str>, group_by: &[&str]) -> CompiledRule {
        CompiledRule {
            name: Arc::from(name),
            source: source.to_string(),
            stream: stream.map(|s| s.to_string()),
            group_by: group_by.iter().map(|s| s.to_string()).collect(),
            aggs: Vec::new(),
            schema: Arc::new(arrow_schema::Schema::empty()),
        }
    }

    fn zeek(path: &str, fields: serde_json::Value) -> crate::zeek::ZeekRecord {
        crate::zeek::ZeekRecord {
            log_path: path.to_string(),
            fields,
            received_at: Utc::now(),
        }
    }

    fn drain_sorted(agg: &Aggregator) -> Vec<AggregateRow> {
        let now = Utc::now();
        let mut rows = agg.drain(now, now);
        rows.sort_by(|a, b| (a.rule.as_ref(), &a.keys).cmp(&(b.rule.as_ref(), &b.keys)));
        rows
    }

    #[test]
    fn identical_group_values_collapse_to_one_counted_row() {
        let agg = Aggregator::new(vec![rule("r", "zeek", Some("dns"), &["query"])], 1000);
        for _ in 0..3 {
            assert!(agg.consume("zeek", &zeek("dns", serde_json::json!({"query": "a.example"}))));
        }
        assert!(agg.consume("zeek", &zeek("dns", serde_json::json!({"query": "b.example"}))));

        let rows = drain_sorted(&agg);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].keys, vec![Some("a.example".to_string())]);
        assert_eq!(rows[0].count, 3);
        assert_eq!(rows[1].count, 1);
    }

    #[test]
    fn draining_clears_state_so_windows_do_not_accumulate() {
        let agg = Aggregator::new(vec![rule("r", "zeek", Some("dns"), &["query"])], 1000);
        agg.consume("zeek", &zeek("dns", serde_json::json!({"query": "a"})));
        assert_eq!(drain_sorted(&agg).len(), 1);
        assert!(drain_sorted(&agg).is_empty(), "second drain must be empty");
    }

    #[test]
    fn non_matching_source_or_stream_is_not_consumed() {
        let agg = Aggregator::new(vec![rule("r", "zeek", Some("dns"), &["query"])], 1000);
        assert!(!agg.consume("zeek", &zeek("conn", serde_json::json!({"query": "a"}))));
        assert!(!agg.consume("suricata", &zeek("dns", serde_json::json!({"query": "a"}))));
        assert!(drain_sorted(&agg).is_empty());
    }

    #[test]
    fn a_rule_without_a_stream_filter_matches_every_record_of_its_source() {
        let agg = Aggregator::new(vec![rule("r", "zeek", None, &["query"])], 1000);
        assert!(agg.consume("zeek", &zeek("conn", serde_json::json!({"query": "a"}))));
        assert!(agg.consume("zeek", &zeek("dns", serde_json::json!({"query": "a"}))));
        assert_eq!(drain_sorted(&agg)[0].count, 2);
    }

    #[test]
    fn two_matching_rules_both_count_the_same_record() {
        let agg = Aggregator::new(
            vec![
                rule("by_query", "zeek", Some("dns"), &["query"]),
                rule("by_client", "zeek", Some("dns"), &["id.orig_h"]),
            ],
            1000,
        );
        assert!(agg.consume(
            "zeek",
            &zeek("dns", serde_json::json!({"query": "a", "id.orig_h": "10.0.0.1"}))
        ));
        let rows = drain_sorted(&agg);
        assert_eq!(rows.len(), 2, "one record must feed both rules");
        assert!(rows.iter().all(|r| r.count == 1));
    }

    #[test]
    fn a_missing_group_field_becomes_null_and_the_record_is_still_counted() {
        let agg = Aggregator::new(vec![rule("r", "zeek", Some("dns"), &["query", "absent"])], 1000);
        assert!(agg.consume("zeek", &zeek("dns", serde_json::json!({"query": "a"}))));
        let rows = drain_sorted(&agg);
        assert_eq!(rows[0].keys, vec![Some("a".to_string()), None]);
        assert_eq!(rows[0].count, 1);
    }

    #[test]
    fn sum_min_max_accumulate_over_numeric_fields() {
        let mut r = rule("r", "zeek", Some("conn"), &["proto"]);
        r.aggs = vec![
            AggSpec { kind: AggKind::Sum, field: "orig_bytes".into(), column: "sum_orig_bytes".into() },
            AggSpec { kind: AggKind::Min, field: "orig_bytes".into(), column: "min_orig_bytes".into() },
            AggSpec { kind: AggKind::Max, field: "orig_bytes".into(), column: "max_orig_bytes".into() },
        ];
        let agg = Aggregator::new(vec![r], 1000);
        for b in [10.0, 30.0, 20.0] {
            agg.consume("zeek", &zeek("conn", serde_json::json!({"proto": "tcp", "orig_bytes": b})));
        }
        let rows = drain_sorted(&agg);
        assert_eq!(rows[0].count, 3);
        assert_eq!(rows[0].aggs, vec![Some(60.0), Some(10.0), Some(30.0)]);
    }

    #[test]
    fn aggregates_ignore_missing_non_numeric_and_non_finite_values_but_still_count() {
        let mut r = rule("r", "zeek", Some("conn"), &["proto"]);
        r.aggs = vec![AggSpec {
            kind: AggKind::Sum,
            field: "orig_bytes".into(),
            column: "sum_orig_bytes".into(),
        }];
        let agg = Aggregator::new(vec![r], 1000);
        agg.consume("zeek", &zeek("conn", serde_json::json!({"proto": "tcp", "orig_bytes": 5})));
        agg.consume("zeek", &zeek("conn", serde_json::json!({"proto": "tcp"})));
        agg.consume("zeek", &zeek("conn", serde_json::json!({"proto": "tcp", "orig_bytes": "abc"})));
        // A numeric string DOES contribute.
        agg.consume("zeek", &zeek("conn", serde_json::json!({"proto": "tcp", "orig_bytes": "7"})));

        let rows = drain_sorted(&agg);
        assert_eq!(rows[0].count, 4, "every record counts regardless of aggregate usability");
        assert_eq!(rows[0].aggs, vec![Some(12.0)]);
    }

    #[test]
    fn a_group_with_no_numeric_observations_emits_null_not_zero() {
        let mut r = rule("r", "zeek", Some("conn"), &["proto"]);
        r.aggs = vec![AggSpec {
            kind: AggKind::Sum,
            field: "orig_bytes".into(),
            column: "sum_orig_bytes".into(),
        }];
        let agg = Aggregator::new(vec![r], 1000);
        agg.consume("zeek", &zeek("conn", serde_json::json!({"proto": "tcp"})));
        let rows = drain_sorted(&agg);
        assert_eq!(rows[0].count, 1);
        assert_eq!(rows[0].aggs, vec![None], "SUM over zero rows is NULL, not 0.0");
    }

    #[test]
    fn groups_past_the_cap_fold_into_other_preserving_count_and_aggregates() {
        let mut r = rule("r", "zeek", Some("dns"), &["query"]);
        r.aggs = vec![AggSpec {
            kind: AggKind::Sum,
            field: "n".into(),
            column: "sum_n".into(),
        }];
        let agg = Aggregator::new(vec![r], 2); // cap of 2 distinct groups
        for i in 0..5 {
            agg.consume("zeek", &zeek("dns", serde_json::json!({"query": format!("q{i}"), "n": 1})));
        }
        let rows = drain_sorted(&agg);
        // 2 real groups + 1 overflow row.
        assert_eq!(rows.len(), 3);
        let total: u64 = rows.iter().map(|r| r.count).sum();
        assert_eq!(total, 5, "the window total must stay exact");

        let other = rows
            .iter()
            .find(|r| r.keys.iter().all(|k| k.as_deref() == Some(OTHER_LABEL)))
            .expect("an _other row must exist");
        assert_eq!(other.count, 3);
        assert_eq!(other.aggs, vec![Some(3.0)], "aggregates accumulate into _other too");
    }

    #[test]
    fn an_all_fields_missing_record_is_not_confused_with_the_overflow_row() {
        let agg = Aggregator::new(vec![rule("r", "zeek", Some("dns"), &["absent"])], 1);
        // First key: all-None. Second distinct key would overflow, but there is
        // only one possible key here, so nothing overflows.
        agg.consume("zeek", &zeek("dns", serde_json::json!({})));
        agg.consume("zeek", &zeek("dns", serde_json::json!({})));
        let rows = drain_sorted(&agg);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].keys, vec![None], "null key, not the _other sentinel");
        assert_eq!(rows[0].count, 2);
    }

    // -- compile_rules validation --

    fn config_with(rules: Vec<crate::config::AggregateRule>) -> crate::config::Config {
        let mut c = crate::config::Config::default();
        c.zeek.enabled = true;
        c.aggregate.enabled = true;
        c.aggregate.local = Some(crate::config::AggregateLocalConfig {
            directory: std::path::PathBuf::from("/tmp/agg-test"),
            prefix: "aggregate".to_string(),
        });
        c.aggregate.rules = rules;
        c
    }

    fn raw_rule(name: &str, source: &str, group_by: &[&str]) -> crate::config::AggregateRule {
        crate::config::AggregateRule {
            name: name.to_string(),
            source: source.to_string(),
            stream: None,
            group_by: group_by.iter().map(|s| s.to_string()).collect(),
            sum: Vec::new(),
            min: Vec::new(),
            max: Vec::new(),
        }
    }

    #[test]
    fn compile_rules_accepts_a_valid_rule() {
        let cfg = config_with(vec![raw_rule("r", "zeek", &["query"])]);
        let rules = compile_rules(&cfg).expect("valid config compiles");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name.as_ref(), "r");
    }

    #[test]
    fn compile_rules_rejects_an_unknown_source() {
        let cfg = config_with(vec![raw_rule("r", "nosuch", &["query"])]);
        let err = compile_rules(&cfg).unwrap_err().to_string();
        assert!(err.contains("nosuch"), "error must name the bad source: {err}");
    }

    #[test]
    fn compile_rules_rejects_a_source_that_is_disabled() {
        let mut cfg = config_with(vec![raw_rule("r", "zeek", &["query"])]);
        cfg.zeek.enabled = false;
        let err = compile_rules(&cfg).unwrap_err().to_string();
        assert!(err.contains("zeek"), "error must name the disabled source: {err}");
    }

    #[test]
    fn compile_rules_rejects_empty_group_by() {
        let cfg = config_with(vec![raw_rule("r", "zeek", &[])]);
        assert!(compile_rules(&cfg).is_err());
    }

    #[test]
    fn compile_rules_rejects_duplicate_rule_names() {
        let cfg = config_with(vec![
            raw_rule("dupe", "zeek", &["query"]),
            raw_rule("dupe", "zeek", &["proto"]),
        ]);
        let err = compile_rules(&cfg).unwrap_err().to_string();
        assert!(err.contains("dupe"), "error must name the duplicate: {err}");
    }

    #[test]
    fn compile_rules_rejects_rules_with_no_destination() {
        let mut cfg = config_with(vec![raw_rule("r", "zeek", &["query"])]);
        cfg.aggregate.local = None;
        cfg.aggregate.s3 = None;
        assert!(compile_rules(&cfg).is_err());
    }

    #[test]
    fn compile_rules_returns_empty_when_disabled() {
        let mut cfg = config_with(vec![raw_rule("r", "zeek", &["query"])]);
        cfg.aggregate.enabled = false;
        assert!(compile_rules(&cfg).expect("disabled is not an error").is_empty());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib aggregate::tests`
Expected: FAIL — `cannot find struct Aggregator in this scope`.

- [ ] **Step 3: Implement the aggregator core**

Write `src/forwarding/aggregate/mod.rs` (keeping `pub mod fields;` and the test module):

```rust
//! Optional record aggregation: an SQL `GROUP BY` evaluated at ingest.
//!
//! A record matching a rule is counted here and NOT forwarded to the raw
//! writer (suppression) — that is the whole point, reducing noisy logging at
//! the input stage while keeping the valuable summary.

pub mod fields;
pub mod handlers;

use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::config::Config;
use fields::{AggFields, group_value_string, numeric_value};

/// Group-column value written for the cardinality-overflow row.
//
// ponytail: a real group whose every column is literally "_other" renders the
// same as the overflow row in the output. The two stay distinct internally, so
// no count is corrupted — it is an output-reading ambiguity only.
pub const OTHER_LABEL: &str = "_other";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggKind {
    Sum,
    Min,
    Max,
}

/// One configured aggregate: which function, over which source field, into
/// which output column.
#[derive(Debug, Clone)]
pub struct AggSpec {
    pub kind: AggKind,
    pub field: String,
    pub column: String,
}

/// A validated rule with its output schema resolved.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub name: Arc<str>,
    pub source: String,
    pub stream: Option<String>,
    pub group_by: Vec<String>,
    pub aggs: Vec<AggSpec>,
    pub schema: Arc<arrow_schema::Schema>,
}

/// Map key. `Other` is a distinct variant, so the overflow bucket can never
/// collide with a real key — including the all-fields-missing key, which is
/// `Keys([None, ..])`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum GroupKey {
    Keys(Box<[Option<String>]>),
    Other,
}

/// One aggregate's running state. `n == 0` means "never observed a usable
/// number" and emits SQL NULL rather than a fabricated 0.0.
#[derive(Debug, Clone)]
struct AggAcc {
    sum: f64,
    min: f64,
    max: f64,
    n: u64,
}

impl AggAcc {
    fn new() -> Self {
        Self {
            sum: 0.0,
            min: f64::INFINITY,
            max: f64::NEG_INFINITY,
            n: 0,
        }
    }

    fn observe(&mut self, v: f64) {
        self.sum += v;
        self.min = self.min.min(v);
        self.max = self.max.max(v);
        self.n += 1;
    }

    fn value(&self, kind: AggKind) -> Option<f64> {
        if self.n == 0 {
            return None;
        }
        Some(match kind {
            AggKind::Sum => self.sum,
            AggKind::Min => self.min,
            AggKind::Max => self.max,
        })
    }
}

#[derive(Debug, Clone)]
struct Acc {
    count: u64,
    aggs: Vec<AggAcc>,
}

/// One output row: one group, one window.
#[derive(Debug, Clone)]
pub struct AggregateRow {
    pub rule: Arc<str>,
    pub keys: Vec<Option<String>>,
    pub count: u64,
    pub aggs: Vec<Option<f64>>,
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
}

/// In-memory group state for every rule.
pub struct Aggregator {
    rules: Vec<CompiledRule>,
    max_groups: usize,
    // ponytail: one mutex over all rules' groups. A hashmap lookup plus a
    // counter bump is tens of nanoseconds; shard by rule if a profile ever
    // shows contention here.
    state: Mutex<HashMap<(usize, GroupKey), Acc>>,
}

impl Aggregator {
    pub fn new(rules: Vec<CompiledRule>, max_groups: usize) -> Self {
        Self {
            rules,
            max_groups,
            state: Mutex::new(HashMap::new()),
        }
    }

    pub fn rules(&self) -> &[CompiledRule] {
        &self.rules
    }

    /// Count `rec` into every rule that matches it.
    ///
    /// Returns `true` when at least one rule matched, meaning the caller must
    /// NOT forward the record downstream.
    pub fn consume<R: AggFields>(&self, source: &str, rec: &R) -> bool {
        let stream = rec.stream();
        let mut matched = false;

        for (idx, rule) in self.rules.iter().enumerate() {
            if rule.source != source {
                continue;
            }
            if let Some(want) = rule.stream.as_deref()
                && want != stream
            {
                continue;
            }
            matched = true;

            let keys: Box<[Option<String>]> = rule
                .group_by
                .iter()
                .map(|name| rec.field(name).map(group_value_string))
                .collect();

            // Read the numeric contributions before taking the lock.
            let observations: Vec<Option<f64>> = rule
                .aggs
                .iter()
                .map(|spec| rec.field(&spec.field).as_ref().and_then(numeric_value))
                .collect();

            let mut state = self.state.lock().expect("aggregator state mutex poisoned");
            let key = (idx, GroupKey::Keys(keys));
            let entry = match state.get_mut(&key) {
                Some(e) => e,
                None => {
                    // Cap counts real groups for THIS rule only.
                    let existing = state
                        .keys()
                        .filter(|(i, k)| *i == idx && matches!(k, GroupKey::Keys(_)))
                        .count();
                    let key = if existing >= self.max_groups {
                        metrics::counter!("aggregate_overflow_records", "rule" => rule.name.to_string())
                            .increment(1);
                        (idx, GroupKey::Other)
                    } else {
                        key
                    };
                    state.entry(key).or_insert_with(|| Acc {
                        count: 0,
                        aggs: rule.aggs.iter().map(|_| AggAcc::new()).collect(),
                    })
                }
            };

            entry.count += 1;
            for (acc, obs) in entry.aggs.iter_mut().zip(observations) {
                if let Some(v) = obs {
                    acc.observe(v);
                }
            }
            drop(state);

            metrics::counter!("aggregate_records_consumed", "rule" => rule.name.to_string())
                .increment(1);
        }

        matched
    }

    /// Take every group and clear the state, stamping the window bounds.
    pub fn drain(
        &self,
        window_start: DateTime<Utc>,
        window_end: DateTime<Utc>,
    ) -> Vec<AggregateRow> {
        let taken = {
            let mut state = self.state.lock().expect("aggregator state mutex poisoned");
            std::mem::take(&mut *state)
        };

        let mut rows = Vec::with_capacity(taken.len());
        for ((idx, key), acc) in taken {
            let Some(rule) = self.rules.get(idx) else {
                continue;
            };
            let keys = match key {
                GroupKey::Keys(k) => k.into_vec(),
                GroupKey::Other => rule
                    .group_by
                    .iter()
                    .map(|_| Some(OTHER_LABEL.to_string()))
                    .collect(),
            };
            rows.push(AggregateRow {
                rule: rule.name.clone(),
                keys,
                count: acc.count,
                aggs: acc
                    .aggs
                    .iter()
                    .zip(&rule.aggs)
                    .map(|(a, spec)| a.value(spec.kind))
                    .collect(),
                window_start,
                window_end,
            });
        }
        rows
    }
}

/// Sources an aggregation rule may name.
const KNOWN_SOURCES: [&str; 5] = ["zeek", "suricata", "syslog", "ipfix", "sflow"];

fn source_enabled(config: &Config, source: &str) -> bool {
    match source {
        "zeek" => config.zeek.enabled,
        "suricata" => config.suricata.enabled,
        "syslog" => config.syslog.enabled,
        "ipfix" => config.ipfix.enabled,
        "sflow" => config.sflow.enabled,
        _ => false,
    }
}

/// Validate and compile the configured rules. Returns an empty vec when
/// aggregation is disabled. Every failure is fatal at startup: a rule that
/// silently fails to match would leave the noisy stream flowing unaggregated,
/// or produce zero rows forever.
pub fn compile_rules(config: &Config) -> anyhow::Result<Vec<CompiledRule>> {
    let cfg = &config.aggregate;
    if !cfg.enabled || cfg.rules.is_empty() {
        return Ok(Vec::new());
    }
    if cfg.s3.is_none() && cfg.local.is_none() {
        anyhow::bail!(
            "[aggregate] has {} rule(s) but neither [aggregate.s3] nor [aggregate.local] is configured",
            cfg.rules.len()
        );
    }

    let mut seen: Vec<&str> = Vec::new();
    let mut compiled = Vec::with_capacity(cfg.rules.len());

    for rule in &cfg.rules {
        if rule.name.trim().is_empty() {
            anyhow::bail!("[[aggregate.rules]] has an empty `name`");
        }
        if seen.contains(&rule.name.as_str()) {
            anyhow::bail!("duplicate [[aggregate.rules]] name '{}'", rule.name);
        }
        seen.push(rule.name.as_str());

        if !KNOWN_SOURCES.contains(&rule.source.as_str()) {
            anyhow::bail!(
                "[[aggregate.rules]] '{}' names unknown source '{}' (expected one of {:?})",
                rule.name,
                rule.source,
                KNOWN_SOURCES
            );
        }
        if !source_enabled(config, &rule.source) {
            anyhow::bail!(
                "[[aggregate.rules]] '{}' targets source '{}', which is not enabled in this deployment",
                rule.name,
                rule.source
            );
        }
        if rule.group_by.is_empty() {
            anyhow::bail!("[[aggregate.rules]] '{}' has an empty `group_by`", rule.name);
        }

        let mut aggs = Vec::new();
        for (kind, list, prefix) in [
            (AggKind::Sum, &rule.sum, "sum"),
            (AggKind::Min, &rule.min, "min"),
            (AggKind::Max, &rule.max, "max"),
        ] {
            for field in list {
                aggs.push(AggSpec {
                    kind,
                    field: field.clone(),
                    column: format!("{prefix}_{field}"),
                });
            }
        }

        compiled.push(CompiledRule {
            name: Arc::from(rule.name.as_str()),
            source: rule.source.clone(),
            stream: rule.stream.clone(),
            group_by: rule.group_by.clone(),
            aggs,
            // Replaced with the real schema in Task 5.
            schema: Arc::new(arrow_schema::Schema::empty()),
        });
    }

    Ok(compiled)
}
```

Create an empty `src/forwarding/aggregate/handlers.rs` with just `//! Decorator handlers (Task 7).` so the `pub mod handlers;` line compiles.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib aggregate::tests`
Expected: PASS (18 tests).

- [ ] **Step 5: Commit**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
git add src/forwarding/aggregate/
git commit -m "feat(aggregate): group map, SQL aggregate semantics, cardinality cap"
```

---

### Task 5: `AggregateSink` — per-rule Arrow schemas and row encoding

**Files:**
- Modify: `src/forwarding/aggregate/mod.rs` (add `rule_schema`, `AggregateSink`; wire the real schema into `compile_rules`)
- Modify: `src/forwarding/drop_log.rs` (add `DropSite::Aggregate = 9`, bump `DROP_SITE_COUNT`, update the compile-time guard)

**Interfaces:**
- Consumes: `CompiledRule`, `AggregateRow`, `AggSpec` (Task 4); `crate::forwarding::buffered_writer::ParquetSink`.
- Produces:
  ```rust
  pub fn rule_schema(group_by: &[String], aggs: &[AggSpec]) -> Arc<arrow_schema::Schema>;
  pub struct AggregateSink { /* schemas: HashMap<String, Arc<Schema>> */ }
  impl AggregateSink { pub fn new(rules: &[CompiledRule]) -> Self }
  impl ParquetSink for AggregateSink { type Record = AggregateRow; }
  // drop_log.rs:
  pub enum DropSite { ..., Aggregate = 9 }
  pub const DROP_SITE_COUNT: usize = 10;
  ```

**Column order (must match `AggregateRow` field order exactly):** every `group_by` column as nullable `Utf8`, then `count` as non-null `UInt64`, then each agg column as nullable `Float64`, then `window_start` and `window_end` as non-null `Timestamp(Millisecond, Some("UTC"))`.

- [ ] **Step 1: Write the failing tests**

Add to the `mod tests` block in `src/forwarding/aggregate/mod.rs`:

```rust
    #[test]
    fn rule_schema_orders_columns_group_count_aggs_window() {
        let group_by = vec!["query".to_string(), "id.orig_h".to_string()];
        let aggs = vec![AggSpec {
            kind: AggKind::Sum,
            field: "n".into(),
            column: "sum_n".into(),
        }];
        let schema = rule_schema(&group_by, &aggs);
        let names: Vec<&str> = schema.fields().iter().map(|f| f.name().as_str()).collect();
        assert_eq!(
            names,
            vec!["query", "id.orig_h", "count", "sum_n", "window_start", "window_end"]
        );

        use arrow_schema::DataType;
        assert_eq!(schema.field(0).data_type(), &DataType::Utf8);
        assert!(schema.field(0).is_nullable(), "group columns are nullable");
        assert_eq!(schema.field(2).data_type(), &DataType::UInt64);
        assert!(!schema.field(2).is_nullable(), "count is never null");
        assert_eq!(schema.field(3).data_type(), &DataType::Float64);
        assert!(schema.field(3).is_nullable(), "aggregates may be SQL NULL");
    }

    #[test]
    fn aggregate_sink_encodes_a_row_including_nulls() {
        use crate::forwarding::buffered_writer::ParquetSink;

        let mut r = rule("dns_by_query", "zeek", Some("dns"), &["query", "client"]);
        r.aggs = vec![AggSpec {
            kind: AggKind::Sum,
            field: "n".into(),
            column: "sum_n".into(),
        }];
        r.schema = rule_schema(&r.group_by, &r.aggs);
        let schema = r.schema.clone();
        let sink = AggregateSink::new(std::slice::from_ref(&r));

        let now = Utc::now();
        let row = AggregateRow {
            rule: Arc::from("dns_by_query"),
            keys: vec![Some("a.example".to_string()), None],
            count: 7,
            aggs: vec![None],
            window_start: now,
            window_end: now,
        };

        assert_eq!(sink.partition(&row).as_deref(), Some("dns_by_query"));
        assert_eq!(sink.schema(Some("dns_by_query")), schema);

        let batch = sink.to_record_batch(&row, &schema).expect("encodes");
        assert_eq!(batch.num_rows(), 1);

        use arrow::array::{Float64Array, StringArray, UInt64Array};
        let query = batch
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(query.value(0), "a.example");
        let client = batch
            .column(1)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert!(client.is_null(0), "a missing group value must be NULL");
        let count = batch
            .column(2)
            .as_any()
            .downcast_ref::<UInt64Array>()
            .unwrap();
        assert_eq!(count.value(0), 7);
        let sum = batch
            .column(3)
            .as_any()
            .downcast_ref::<Float64Array>()
            .unwrap();
        assert!(sum.is_null(0), "an unobserved aggregate must be NULL");
    }

    #[test]
    fn compile_rules_fills_in_the_real_schema() {
        let cfg = config_with(vec![raw_rule("r", "zeek", &["query"])]);
        let rules = compile_rules(&cfg).expect("compiles");
        let names: Vec<&str> = rules[0]
            .schema
            .fields()
            .iter()
            .map(|f| f.name().as_str())
            .collect();
        assert_eq!(names, vec!["query", "count", "window_start", "window_end"]);
    }
```

Add to `src/forwarding/drop_log.rs`'s test module:

```rust
    #[test]
    fn aggregate_drop_site_has_its_own_throttle_slot() {
        let ts = DropLogThrottles::new();
        assert_eq!(ts.check_at(DropSite::Aggregate, DropKind::Full, 0), Some(1));
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib aggregate::tests && cargo test --lib drop_log`
Expected: FAIL — `cannot find function rule_schema`; `no variant Aggregate`.

- [ ] **Step 3: Implement the sink and the drop site**

In `src/forwarding/drop_log.rs`, add the variant after `StructuredSyslog = 8`, and update both constants:

```rust
    /// Aggregated group-by tables (`forwarding/aggregate`).
    Aggregate = 9,
}

pub const DROP_SITE_COUNT: usize = 10;

const _: () = assert!(DropSite::Aggregate as usize + 1 == DROP_SITE_COUNT);
```

If a test in `drop_log.rs` enumerates every site (search for `DROP_SITE_COUNT` in the test module), add `DropSite::Aggregate` to that list.

In `src/forwarding/aggregate/mod.rs`, add:

```rust
use arrow_schema::{DataType, Field, Schema, TimeUnit};

/// Arrow schema for one rule. Column order must match `AggregateRow`'s field
/// order — `to_record_batch` builds columns positionally.
pub fn rule_schema(group_by: &[String], aggs: &[AggSpec]) -> Arc<Schema> {
    let mut fields: Vec<Field> = group_by
        .iter()
        .map(|name| Field::new(name, DataType::Utf8, true))
        .collect();
    fields.push(Field::new("count", DataType::UInt64, false));
    for spec in aggs {
        // Nullable: SQL SUM/MIN/MAX over zero observations is NULL.
        fields.push(Field::new(&spec.column, DataType::Float64, true));
    }
    let ts = DataType::Timestamp(TimeUnit::Millisecond, Some("UTC".into()));
    fields.push(Field::new("window_start", ts.clone(), false));
    fields.push(Field::new("window_end", ts, false));
    Arc::new(Schema::new(fields))
}

/// `ParquetSink` adapter for aggregated rows. One writer serves every rule:
/// `AggregateRow` is source-agnostic and the partition is the rule name.
pub struct AggregateSink {
    schemas: HashMap<String, Arc<Schema>>,
}

impl AggregateSink {
    pub fn new(rules: &[CompiledRule]) -> Self {
        Self {
            schemas: rules
                .iter()
                .map(|r| (r.name.to_string(), r.schema.clone()))
                .collect(),
        }
    }
}

impl crate::forwarding::buffered_writer::ParquetSink for AggregateSink {
    type Record = AggregateRow;

    fn source(&self) -> &'static str {
        "aggregate"
    }

    fn partition(&self, record: &AggregateRow) -> Option<String> {
        Some(record.rule.to_string())
    }

    fn schema(&self, partition: Option<&str>) -> Arc<Schema> {
        partition
            .and_then(|p| self.schemas.get(p))
            .cloned()
            // Unreachable in practice: every row carries a compiled rule name.
            .unwrap_or_else(|| Arc::new(Schema::empty()))
    }

    fn to_record_batch(
        &self,
        record: &AggregateRow,
        schema: &Arc<Schema>,
    ) -> anyhow::Result<arrow_array::RecordBatch> {
        use arrow::array::{
            ArrayRef, Float64Array, StringArray, TimestampMillisecondArray, UInt64Array,
        };

        let expected = record.keys.len() + 1 + record.aggs.len() + 2;
        if schema.fields().len() != expected {
            anyhow::bail!(
                "aggregate row for rule '{}' has {} columns but its schema has {}",
                record.rule,
                expected,
                schema.fields().len()
            );
        }

        let mut columns: Vec<ArrayRef> = Vec::with_capacity(expected);
        for k in &record.keys {
            columns.push(Arc::new(StringArray::from(vec![k.as_deref()])));
        }
        columns.push(Arc::new(UInt64Array::from(vec![record.count])));
        for a in &record.aggs {
            columns.push(Arc::new(Float64Array::from(vec![*a])));
        }
        let tz: Arc<str> = Arc::from("UTC");
        for t in [record.window_start, record.window_end] {
            columns.push(Arc::new(
                TimestampMillisecondArray::from(vec![t.timestamp_millis()])
                    .with_timezone(tz.clone()),
            ));
        }

        Ok(arrow_array::RecordBatch::try_new(schema.clone(), columns)?)
    }
}
```

In `compile_rules`, replace the placeholder schema:

```rust
        let schema = rule_schema(&rule.group_by, &aggs);
        compiled.push(CompiledRule {
            name: Arc::from(rule.name.as_str()),
            source: rule.source.clone(),
            stream: rule.stream.clone(),
            group_by: rule.group_by.clone(),
            aggs,
            schema,
        });
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib aggregate && cargo test --lib drop_log`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
git add src/forwarding/aggregate/mod.rs src/forwarding/drop_log.rs
git commit -m "feat(aggregate): AggregateSink with per-rule schemas and NULL-aware encoding"
```

---

### Task 6: Emit task and writer construction

**Files:**
- Modify: `src/forwarding/aggregate/mod.rs`

**Interfaces:**
- Consumes: `Aggregator`, `AggregateSink`, `CompiledRule` (Tasks 4-5); `ParquetWriterHandle`, `BufferedWriterConfig`, `FlushPolicy`, `LiveInterval`, `UploadSink` from `buffered_writer`; `crate::stats::SourceHourlyStats`.
- Produces:
  ```rust
  pub type AggregateWriterHandle = ParquetWriterHandle<AggregateSink>;
  pub fn start_aggregate_writer(
      rules: &[CompiledRule],
      prefix: String,
      flush_interval_secs: u64,
      channel_capacity: usize,
      sink: Arc<dyn UploadSink>,
      source_stats: Arc<SourceHourlyStats>,
      descriptor_sink: Option<Arc<dyn UploadSink>>,
  ) -> (AggregateWriterHandle, tokio::task::JoinHandle<()>);
  // NOTE: no `connection` parameter. `BufferedWriterConfig.connection` is
  // vestigial for sink-based writers; fill it with
  // `buffered_writer::unused_s3_connection_placeholder()` (already
  // `pub(crate)`, exactly what `start_writer` does). Do NOT derive `Default`
  // on the secret-bearing `S3ConnectionConfig`.

  impl Aggregator {
      pub fn spawn_emit_task(
          self: Arc<Self>,
          handles: Vec<Arc<AggregateWriterHandle>>,
          interval: std::time::Duration,
          shutdown: tokio::sync::watch::Receiver<bool>,
      ) -> tokio::task::JoinHandle<()>;
  }
  ```

**Notes:**
- `AggregateSink` is not `Default`, so use `ParquetWriterHandle::start_with_stats` directly, not `start_writer::<S>()`.
- The writer's `FlushPolicy.interval` uses the same `flush_interval_secs` as the emit tick — files land window-aligned in practice, but nothing depends on it.
- `max_partitions` = `rules.len() + 1`.
- `max_buffer_rows` / `flush_threshold_bytes`: use `usize::MAX / 4` and `64 * 1024 * 1024` so the age trigger is what fires; a window's rows should land in one file when they fit.
- On shutdown, drain once more before returning so a partial window is not lost.

- [ ] **Step 1: Write the failing test**

Add to the `mod tests` block in `src/forwarding/aggregate/mod.rs`:

```rust
    #[tokio::test]
    async fn the_emit_task_drains_on_tick_and_again_on_shutdown() {
        use tokio::sync::mpsc;

        let mut r = rule("r", "zeek", Some("dns"), &["query"]);
        r.schema = rule_schema(&r.group_by, &r.aggs);
        let agg = Arc::new(Aggregator::new(vec![r], 1000));

        // A handle whose receiver we own, so we can observe what was emitted.
        let (tx, mut rx) = mpsc::channel::<AggregateRow>(64);
        let handle = Arc::new(crate::forwarding::buffered_writer::ParquetWriterHandle::<
            AggregateSink,
        >::for_test(tx, "aggregate", "local"));

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let task = agg.clone().spawn_emit_task(
            vec![handle],
            std::time::Duration::from_millis(100),
            shutdown_rx,
        );

        agg.consume("zeek", &zeek("dns", serde_json::json!({"query": "a.example"})));
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;

        let first = rx.try_recv().expect("the tick must emit the window's row");
        assert_eq!(first.count, 1);
        assert_eq!(first.keys, vec![Some("a.example".to_string())]);
        assert!(first.window_end >= first.window_start);

        // A record arriving after the tick must still be emitted on shutdown.
        agg.consume("zeek", &zeek("dns", serde_json::json!({"query": "b.example"})));
        shutdown_tx.send(true).expect("signal shutdown");
        task.await.expect("emit task joins");

        let last = rx.try_recv().expect("shutdown must drain the partial window");
        assert_eq!(last.keys, vec![Some("b.example".to_string())]);
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --lib aggregate::tests::the_emit_task`
Expected: FAIL — `no method named spawn_emit_task`.

- [ ] **Step 3: Implement the emit task and writer constructor**

Add to `src/forwarding/aggregate/mod.rs`:

```rust
use crate::forwarding::buffered_writer::{
    BufferedWriterConfig, FlushPolicy, LiveInterval, ParquetWriterHandle, UploadSink,
};

pub type AggregateWriterHandle = ParquetWriterHandle<AggregateSink>;

/// Start one writer for aggregated rows. `AggregateSink` is not `Default`
/// (schemas come from config), so this goes through `start_with_stats` rather
/// than the `start_writer::<S>()` convenience wrapper.
#[allow(clippy::too_many_arguments)]
pub fn start_aggregate_writer(
    rules: &[CompiledRule],
    prefix: String,
    flush_interval_secs: u64,
    channel_capacity: usize,
    sink: Arc<dyn UploadSink>,
    source_stats: Arc<crate::stats::SourceHourlyStats>,
    descriptor_sink: Option<Arc<dyn UploadSink>>,
) -> (AggregateWriterHandle, tokio::task::JoinHandle<()>) {
    // Rows are few (one per group per window) and large flushes are fine, so
    // the age trigger is what should fire — not rows or bytes.
    let max_buffer_rows = usize::MAX / 4;
    let flush_threshold_bytes = 64 * 1024 * 1024;

    let cfg = BufferedWriterConfig {
        // Vestigial for sink-based writers — same placeholder `start_writer` uses.
        connection: crate::forwarding::buffered_writer::unused_s3_connection_placeholder(),
        prefix,
        max_buffer_rows,
        flush_threshold_bytes,
        flush_interval_secs,
        channel_capacity,
        max_partitions: rules.len() + 1,
    };
    let policy = FlushPolicy {
        max_rows: max_buffer_rows,
        max_bytes: flush_threshold_bytes,
        interval: LiveInterval::new(std::time::Duration::from_secs(flush_interval_secs)),
    };
    ParquetWriterHandle::start_with_stats(
        AggregateSink::new(rules),
        sink,
        cfg,
        policy,
        source_stats,
        descriptor_sink,
    )
}

impl Aggregator {
    /// Drain the group map every `interval` into each writer, and once more on
    /// shutdown so a partial window is not lost.
    pub fn spawn_emit_task(
        self: Arc<Self>,
        handles: Vec<Arc<AggregateWriterHandle>>,
        interval: std::time::Duration,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            ticker.tick().await; // the first tick completes immediately
            let mut window_start = Utc::now();

            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        window_start = self.emit(window_start, &handles).await;
                    }
                    res = shutdown.changed() => {
                        if res.is_err() || *shutdown.borrow() {
                            self.emit(window_start, &handles).await;
                            return;
                        }
                    }
                }
            }
        })
    }

    /// Drain one window and push it to every destination. Returns the start of
    /// the next window.
    async fn emit(
        &self,
        window_start: DateTime<Utc>,
        handles: &[Arc<AggregateWriterHandle>],
    ) -> DateTime<Utc> {
        let window_end = Utc::now();
        let rows = self.drain(window_start, window_end);
        if rows.is_empty() {
            return window_end;
        }

        for rule in &self.rules {
            let n = rows.iter().filter(|r| r.rule == rule.name).count();
            metrics::gauge!("aggregate_groups", "rule" => rule.name.to_string()).set(n as f64);
        }

        for row in rows {
            for handle in handles {
                let rule = row.rule.clone();
                // Bounded wait, not try_send: this task is off the ingest hot
                // path, so waiting for channel capacity costs nothing that
                // matters and a whole window's counts are expensive to lose.
                match handle.send_or_drop(row.clone()).await {
                    Ok(()) => {
                        metrics::counter!("aggregate_rows_emitted", "rule" => rule.to_string())
                            .increment(1);
                    }
                    Err(e) => {
                        if let Some(dropped_total) = handle.drop_log_due(
                            crate::forwarding::drop_log::DropSite::Aggregate,
                            crate::forwarding::drop_log::DropKind::from(&e),
                        ) {
                            tracing::warn!(
                                dropped_total,
                                rule = %rule,
                                "aggregate writer channel unavailable; dropped 1 aggregated row"
                            );
                        }
                    }
                }
            }
        }
        window_end
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test --lib aggregate::tests::the_emit_task`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
git add src/forwarding/aggregate/mod.rs
git commit -m "feat(aggregate): emit task, writer construction, shutdown drain"
```

---

### Task 7: Decorator handlers for all five sources

**Files:**
- Modify: `src/forwarding/aggregate/handlers.rs`

**Interfaces:**
- Consumes: `Aggregator` (Task 4); the five handler traits.
- Produces:
  ```rust
  pub struct AggregatingZeekHandler { pub agg: Arc<Aggregator>, pub inner: Arc<dyn ZeekHandler> }
  pub struct AggregatingSuricataHandler { pub agg: Arc<Aggregator>, pub inner: Arc<dyn SuricataHandler> }
  pub struct AggregatingSyslogHandler { pub agg: Arc<Aggregator>, pub inner: Arc<dyn SyslogHandler> }
  pub struct AggregatingIpfixHandler { pub agg: Arc<Aggregator>, pub inner: Arc<dyn IpfixHandler> }
  pub struct AggregatingSflowHandler { pub agg: Arc<Aggregator>, pub inner: Arc<dyn SflowHandler> }
  ```
  Each implements its source's handler trait.

- [ ] **Step 1: Write the failing tests**

Write `src/forwarding/aggregate/handlers.rs` with only this test module for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::forwarding::aggregate::{Aggregator, CompiledRule, rule_schema};
    use crate::zeek::ZeekRecord;
    use crate::zeek::listener::ZeekHandler;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn dns_rule() -> CompiledRule {
        let group_by = vec!["query".to_string()];
        CompiledRule {
            name: std::sync::Arc::from("dns_by_query"),
            source: "zeek".to_string(),
            stream: Some("dns".to_string()),
            group_by: group_by.clone(),
            aggs: Vec::new(),
            schema: rule_schema(&group_by, &[]),
        }
    }

    struct CountingZeek(AtomicUsize);
    #[async_trait::async_trait]
    impl ZeekHandler for CountingZeek {
        async fn handle_record(&self, _r: ZeekRecord, _s: std::net::SocketAddr) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn zeek_rec(path: &str) -> ZeekRecord {
        ZeekRecord {
            log_path: path.to_string(),
            fields: serde_json::json!({"query": "a.example"}),
            received_at: chrono::Utc::now(),
        }
    }

    #[tokio::test]
    async fn a_matched_record_is_counted_and_not_forwarded() {
        let agg = Arc::new(Aggregator::new(vec![dns_rule()], 1000));
        let inner = Arc::new(CountingZeek(AtomicUsize::new(0)));
        let h = AggregatingZeekHandler {
            agg: agg.clone(),
            inner: inner.clone(),
        };
        let src: std::net::SocketAddr = "127.0.0.1:47760".parse().unwrap();

        h.handle_record(zeek_rec("dns"), src).await;

        assert_eq!(
            inner.0.load(Ordering::SeqCst),
            0,
            "an aggregated record must NOT reach the raw writer"
        );
        let now = chrono::Utc::now();
        assert_eq!(agg.drain(now, now).len(), 1, "it must have been counted");
    }

    #[tokio::test]
    async fn an_unmatched_record_passes_through_untouched() {
        let agg = Arc::new(Aggregator::new(vec![dns_rule()], 1000));
        let inner = Arc::new(CountingZeek(AtomicUsize::new(0)));
        let h = AggregatingZeekHandler {
            agg: agg.clone(),
            inner: inner.clone(),
        };
        let src: std::net::SocketAddr = "127.0.0.1:47760".parse().unwrap();

        h.handle_record(zeek_rec("conn"), src).await;

        assert_eq!(inner.0.load(Ordering::SeqCst), 1, "conn has no rule; must pass through");
        let now = chrono::Utc::now();
        assert!(agg.drain(now, now).is_empty());
    }

    #[tokio::test]
    async fn a_batch_source_forwards_only_the_unmatched_remainder() {
        use crate::ipfix::FlowRecord;
        use crate::ipfix::listener::IpfixHandler;
        use std::net::{IpAddr, Ipv4Addr};

        fn flow(dst_port: u16) -> FlowRecord {
            FlowRecord {
                observation_domain_id: 0,
                template_id: 0,
                protocol_version: 10,
                exporter: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                export_time: chrono::Utc::now(),
                src_addr: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
                dst_addr: None,
                src_port: None,
                dst_port: Some(dst_port),
                ip_protocol: None,
                octet_delta_count: None,
                packet_delta_count: None,
                flow_start: None,
                flow_end: None,
                tcp_flags: None,
                input_interface: None,
                output_interface: None,
                extra: serde_json::json!({}),
            }
        }

        struct CapturingIpfix(Mutex<Vec<FlowRecord>>);
        #[async_trait::async_trait]
        impl IpfixHandler for CapturingIpfix {
            async fn handle_flows(&self, flows: Vec<FlowRecord>, _s: std::net::SocketAddr) {
                self.0.lock().unwrap().extend(flows);
            }
        }

        // A rule with no stream filter matches EVERY ipfix record, so the
        // remainder is empty and the inner handler must not be called at all.
        let group_by = vec!["dst_port".to_string()];
        let rule = CompiledRule {
            name: std::sync::Arc::from("all_flows"),
            source: "ipfix".to_string(),
            stream: None,
            group_by: group_by.clone(),
            aggs: Vec::new(),
            schema: rule_schema(&group_by, &[]),
        };
        let agg = Arc::new(Aggregator::new(vec![rule], 1000));
        let inner = Arc::new(CapturingIpfix(Mutex::new(Vec::new())));
        let h = AggregatingIpfixHandler {
            agg: agg.clone(),
            inner: inner.clone(),
        };
        let src: std::net::SocketAddr = "127.0.0.1:4739".parse().unwrap();

        h.handle_flows(vec![flow(443), flow(443), flow(80)], src).await;

        assert!(
            inner.0.lock().unwrap().is_empty(),
            "every flow matched, so nothing may reach the raw writer"
        );
        let now = chrono::Utc::now();
        let rows = agg.drain(now, now);
        let total: u64 = rows.iter().map(|r| r.count).sum();
        assert_eq!(total, 3);
        assert_eq!(rows.len(), 2, "two distinct dst_port groups");
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib aggregate::handlers`
Expected: FAIL — `cannot find struct AggregatingZeekHandler`.

- [ ] **Step 3: Implement the five decorators**

Prepend to `src/forwarding/aggregate/handlers.rs`:

```rust
//! Decorator handlers: count a record and swallow it, or pass it through.
//!
//! These wrap each source's existing handler chain rather than sitting beside
//! it — suppression requires being upstream of the raw writer.

use std::net::SocketAddr;
use std::sync::Arc;

use super::Aggregator;

/// Zeek: single record per call.
pub struct AggregatingZeekHandler {
    pub agg: Arc<Aggregator>,
    pub inner: Arc<dyn crate::zeek::listener::ZeekHandler>,
}

#[async_trait::async_trait]
impl crate::zeek::listener::ZeekHandler for AggregatingZeekHandler {
    async fn handle_record(&self, record: crate::zeek::ZeekRecord, source: SocketAddr) {
        if self.agg.consume("zeek", &record) {
            return;
        }
        self.inner.handle_record(record, source).await;
    }
}

/// Suricata: single record per call.
pub struct AggregatingSuricataHandler {
    pub agg: Arc<Aggregator>,
    pub inner: Arc<dyn crate::suricata::listener::SuricataHandler>,
}

#[async_trait::async_trait]
impl crate::suricata::listener::SuricataHandler for AggregatingSuricataHandler {
    async fn handle_record(&self, record: crate::suricata::SuricataRecord, source: SocketAddr) {
        if self.agg.consume("suricata", &record) {
            return;
        }
        self.inner.handle_record(record, source).await;
    }
}

/// Syslog: single message per call.
pub struct AggregatingSyslogHandler {
    pub agg: Arc<Aggregator>,
    pub inner: Arc<dyn crate::syslog::listener::SyslogHandler>,
}

#[async_trait::async_trait]
impl crate::syslog::listener::SyslogHandler for AggregatingSyslogHandler {
    async fn handle_message(&self, message: crate::syslog::SyslogMessage, source: SocketAddr) {
        if self.agg.consume("syslog", &message) {
            return;
        }
        self.inner.handle_message(message, source).await;
    }
}

/// IPFIX: a batch per call — forward only the unmatched remainder.
pub struct AggregatingIpfixHandler {
    pub agg: Arc<Aggregator>,
    pub inner: Arc<dyn crate::ipfix::listener::IpfixHandler>,
}

#[async_trait::async_trait]
impl crate::ipfix::listener::IpfixHandler for AggregatingIpfixHandler {
    async fn handle_flows(&self, flows: Vec<crate::ipfix::FlowRecord>, source: SocketAddr) {
        let remainder: Vec<_> = flows
            .into_iter()
            .filter(|f| !self.agg.consume("ipfix", f))
            .collect();
        if remainder.is_empty() {
            return;
        }
        self.inner.handle_flows(remainder, source).await;
    }
}

/// sFlow: a batch per call — forward only the unmatched remainder.
pub struct AggregatingSflowHandler {
    pub agg: Arc<Aggregator>,
    pub inner: Arc<dyn crate::sflow::listener::SflowHandler>,
}

#[async_trait::async_trait]
impl crate::sflow::listener::SflowHandler for AggregatingSflowHandler {
    async fn handle_samples(&self, samples: Vec<crate::sflow::SflowRecord>, source: SocketAddr) {
        let remainder: Vec<_> = samples
            .into_iter()
            .filter(|s| !self.agg.consume("sflow", s))
            .collect();
        if remainder.is_empty() {
            return;
        }
        self.inner.handle_samples(remainder, source).await;
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib aggregate::handlers`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
git add src/forwarding/aggregate/handlers.rs
git commit -m "feat(aggregate): suppression decorators for all five sources"
```

---

### Task 8: Wire aggregation into `main.rs`

**Files:**
- Modify: `src/main.rs`

**Interfaces:**
- Consumes: `compile_rules`, `Aggregator`, `AggregateSink`, `start_aggregate_writer`, the five decorators.
- Produces: no new public API — wiring only.

**Placement rules:**
1. Build the aggregator **before** the per-source listener blocks (it must exist to wrap their handlers).
2. `compile_rules` failure is **fatal** — return the error from `main`, do not log-and-continue. A misconfigured rule means a noisy stream keeps flowing unaggregated.
3. In each source block, wrap the **final** `Arc<dyn XHandler>` (the one built from `handlers.len()`), not the individual destination handlers.
4. Register each aggregate writer with `flush_registry` under `"aggregate.s3"` / `"aggregate.local"`, and push its `JoinHandle` to `writer_handles` exactly like the per-source writers.

- [ ] **Step 1: Add the aggregator construction block**

Insert after `source_stats` / `descriptor_sink` / `flush_registry` are created and **before** the first listener block (the syslog one, around line 92):

```rust
    // -----------------------------------------------------------------------
    // Build the aggregator (optional). Rules are validated up front: a bad
    // rule means a noisy stream would keep flowing unaggregated, so a config
    // error here is fatal rather than logged-and-skipped.
    // -----------------------------------------------------------------------
    let aggregator: Option<Arc<forwarding::aggregate::Aggregator>> = {
        let rules = forwarding::aggregate::compile_rules(&config)?;
        if rules.is_empty() {
            None
        } else {
            let agg_cfg = &config.aggregate;
            let mut handles: Vec<Arc<forwarding::aggregate::AggregateWriterHandle>> = Vec::new();

            if let Some(s3_cfg) = agg_cfg.s3.as_ref() {
                match forwarding::s3_sink::S3Sink::from_connection(&s3_cfg.connection).await {
                    Ok(sink) => {
                        let (handle, writer_handle) = forwarding::aggregate::start_aggregate_writer(
                            &rules,
                            s3_cfg.prefix.clone(),
                            agg_cfg.flush_interval_secs,
                            agg_cfg.channel_capacity,
                            Arc::new(sink),
                            source_stats.clone(),
                            descriptor_sink.clone(),
                        );
                        writer_handles.push(writer_handle);
                        flush_registry.register("aggregate.s3", handle.flush_interval());
                        handles.push(Arc::new(handle));
                    }
                    Err(e) => {
                        error!("Failed to create S3Sink for aggregation, skipping S3 target: {e}");
                    }
                }
            }

            if let Some(local_cfg) = agg_cfg.local.as_ref() {
                match forwarding::local_sink::LocalDiskSink::new(local_cfg.directory.clone()).await
                {
                    Ok(sink) => {
                        let (handle, writer_handle) = forwarding::aggregate::start_aggregate_writer(
                            &rules,
                            local_cfg.prefix.clone(),
                            agg_cfg.flush_interval_secs,
                            agg_cfg.channel_capacity,
                            Arc::new(sink),
                            source_stats.clone(),
                            descriptor_sink.clone(),
                        );
                        writer_handles.push(writer_handle);
                        flush_registry.register("aggregate.local", handle.flush_interval());
                        handles.push(Arc::new(handle));
                    }
                    Err(e) => {
                        error!(
                            "Failed to create LocalDiskSink for aggregation, \
                             skipping local target: {e}"
                        );
                    }
                }
            }

            if handles.is_empty() {
                error!(
                    "Aggregation is configured with {} rule(s) but no destination could be \
                     created; aggregation is disabled and raw records will flow normally",
                    rules.len()
                );
                None
            } else {
                let agg = Arc::new(forwarding::aggregate::Aggregator::new(
                    rules,
                    agg_cfg.max_groups,
                ));
                let emit = agg.clone().spawn_emit_task(
                    handles,
                    std::time::Duration::from_secs(agg_cfg.flush_interval_secs),
                    shutdown_rx.clone(),
                );
                writer_handles.push(emit);
                info!(
                    "Aggregation enabled: {} rule(s), {}s window",
                    agg.rules().len(),
                    agg_cfg.flush_interval_secs
                );
                Some(agg)
            }
        }
    };
```

- [ ] **Step 2: Wrap each source's final handler**

In the **zeek** block, replace the `let zeek_handler: Arc<dyn ...> = match zeek_handlers.len() { ... };` binding's use with a wrapped version:

```rust
        let zeek_handler: Arc<dyn zeek::listener::ZeekHandler> = match zeek_handlers.len() {
            0 => Arc::new(zeek::listener::DefaultZeekHandler),
            1 => zeek_handlers.into_iter().next().unwrap(),
            _ => Arc::new(forwarding::zeek_s3::MultiZeekHandler(zeek_handlers)),
        };
        // Aggregation wraps the whole chain: matched records are counted here
        // and never reach the raw writer.
        let zeek_handler: Arc<dyn zeek::listener::ZeekHandler> = match aggregator.as_ref() {
            Some(agg) => Arc::new(forwarding::aggregate::handlers::AggregatingZeekHandler {
                agg: agg.clone(),
                inner: zeek_handler,
            }),
            None => zeek_handler,
        };
```

Apply the identical pattern in the suricata, syslog, ipfix, and sflow blocks, using `AggregatingSuricataHandler`, `AggregatingSyslogHandler`, `AggregatingIpfixHandler`, and `AggregatingSflowHandler` respectively, each wrapping that block's final handler binding.

- [ ] **Step 3: Verify it builds and the whole suite still passes**

Run: `cargo build && cargo test`
Expected: builds clean; all existing tests pass (aggregation is off by default, so nothing changes for existing behavior).

- [ ] **Step 4: Smoke-test that a bad rule is fatal**

```bash
cat > /tmp/bad-agg.toml <<'EOF'
[zeek]
enabled = true

[aggregate]
enabled = true
[aggregate.local]
directory = "/tmp/agg-smoke"
[[aggregate.rules]]
name = "r"
source = "nosuchsource"
group_by = ["query"]
EOF
WEF__CONFIG_FILE=/tmp/bad-agg.toml cargo run --quiet -- --config /tmp/bad-agg.toml; echo "exit=$?"
```

Expected: a non-zero exit and an error naming `nosuchsource`. If the binary takes its config path differently, use whatever flag/env `main.rs` reads — check it rather than guessing.

- [ ] **Step 5: Commit**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
git add src/main.rs
git commit -m "feat(aggregate): wire aggregation into main, wrapping each source handler"
```

---

### Task 9: Integration test — aggregator through the real writer to local disk

**Files:**
- Create: `tests/aggregate_local_integration.rs`

**Interfaces:**
- Consumes: everything public from Tasks 1-7.

**Notes:** Model this on `tests/zeek_local_integration.rs` — same `tempfile::tempdir()` + `LocalDiskSink` + `ParquetRecordBatchReaderBuilder` read-back pattern, including its recursive `walk_all_files` helper (copy it; integration tests do not share code).

- [ ] **Step 1: Write the failing test**

```rust
//! Integration test: Aggregator → real PartitionedParquetWriter → Parquet on
//! local disk, read back with a real Parquet reader.
//!
//! Needs no external service, so it runs unconditionally in CI.

use logthing::forwarding::aggregate::{
    AggKind, AggSpec, AggregateWriterHandle, Aggregator, CompiledRule, handlers, rule_schema,
    start_aggregate_writer,
};
use logthing::forwarding::local_sink::LocalDiskSink;
use logthing::zeek::ZeekRecord;
use logthing::zeek::listener::ZeekHandler;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

fn walk_all_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk_all_files(&path));
        } else {
            out.push(path);
        }
    }
    out
}

fn dns_record(query: &str, client: &str) -> ZeekRecord {
    ZeekRecord {
        log_path: "dns".to_string(),
        fields: serde_json::json!({
            "_path": "dns",
            "query": query,
            "id.orig_h": client,
            "rtt": 5,
        }),
        received_at: chrono::Utc::now(),
    }
}

fn conn_record() -> ZeekRecord {
    ZeekRecord {
        log_path: "conn".to_string(),
        fields: serde_json::json!({"_path": "conn", "uid": "CNotAggregated"}),
        received_at: chrono::Utc::now(),
    }
}

fn dns_rule() -> CompiledRule {
    let group_by = vec!["query".to_string(), "id.orig_h".to_string()];
    let aggs = vec![AggSpec {
        kind: AggKind::Sum,
        field: "rtt".to_string(),
        column: "sum_rtt".to_string(),
    }];
    CompiledRule {
        name: Arc::from("dns_by_query"),
        source: "zeek".to_string(),
        stream: Some("dns".to_string()),
        group_by: group_by.clone(),
        aggs: aggs.clone(),
        schema: rule_schema(&group_by, &aggs),
    }
}

struct CountingZeek(AtomicUsize);

#[async_trait::async_trait]
impl ZeekHandler for CountingZeek {
    async fn handle_record(&self, _r: ZeekRecord, _s: std::net::SocketAddr) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn aggregated_counts_land_in_parquet_and_raw_records_are_suppressed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sink = Arc::new(
        LocalDiskSink::new(dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new"),
    );

    let rules = vec![dns_rule()];
    let (handle, _writer_task) = start_aggregate_writer(
        &rules,
        "aggregate".to_string(),
        1, // 1s window so the test does not sleep long
        256,
        sink,
        Arc::new(logthing::stats::SourceHourlyStats::new()),
        None,
    );
    let handle: Arc<AggregateWriterHandle> = Arc::new(handle);

    let agg = Arc::new(Aggregator::new(rules, 1000));
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let emit = agg.clone().spawn_emit_task(
        vec![handle],
        std::time::Duration::from_secs(1),
        shutdown_rx,
    );

    let inner = Arc::new(CountingZeek(AtomicUsize::new(0)));
    let decorated = handlers::AggregatingZeekHandler {
        agg: agg.clone(),
        inner: inner.clone(),
    };
    let src: std::net::SocketAddr = "127.0.0.1:47760".parse().unwrap();

    // 3 records for one group, 1 for another, plus a conn record with no rule.
    for _ in 0..3 {
        decorated
            .handle_record(dns_record("a.example", "10.0.0.1"), src)
            .await;
    }
    decorated
        .handle_record(dns_record("b.example", "10.0.0.2"), src)
        .await;
    decorated.handle_record(conn_record(), src).await;

    assert_eq!(
        inner.0.load(Ordering::SeqCst),
        1,
        "only the unaggregated conn record may reach the raw handler"
    );

    // Let the window close and the writer flush on its age trigger.
    tokio::time::sleep(std::time::Duration::from_secs(4)).await;
    shutdown_tx.send(true).expect("shutdown");
    emit.await.expect("emit task joins");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    let rule_dir = dir.path().join("aggregate/dns_by_query");
    assert!(rule_dir.is_dir(), "expected {rule_dir:?} to exist");
    let parquet_files: Vec<_> = walk_all_files(&rule_dir)
        .into_iter()
        .filter(|p| p.extension().is_some_and(|e| e == "parquet"))
        .collect();
    assert!(!parquet_files.is_empty(), "expected a Parquet file under {rule_dir:?}");

    use arrow::array::{Float64Array, StringArray, UInt64Array};
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

    let mut rows: Vec<(String, String, u64, Option<f64>)> = Vec::new();
    for file in &parquet_files {
        let bytes = std::fs::read(file).expect("read parquet");
        let builder = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(bytes))
            .expect("parquet builder");
        let schema = builder.schema().clone();
        for col in ["query", "id.orig_h", "count", "sum_rtt", "window_start", "window_end"] {
            assert!(
                schema.field_with_name(col).is_ok(),
                "expected column '{col}' in the aggregate schema"
            );
        }
        let reader = builder.build().expect("parquet reader");
        for batch in reader {
            let batch = batch.expect("batch ok");
            let q = batch
                .column_by_name("query")
                .unwrap()
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let c = batch
                .column_by_name("id.orig_h")
                .unwrap()
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let n = batch
                .column_by_name("count")
                .unwrap()
                .as_any()
                .downcast_ref::<UInt64Array>()
                .unwrap();
            let s = batch
                .column_by_name("sum_rtt")
                .unwrap()
                .as_any()
                .downcast_ref::<Float64Array>()
                .unwrap();
            for i in 0..batch.num_rows() {
                rows.push((
                    q.value(i).to_string(),
                    c.value(i).to_string(),
                    n.value(i),
                    (!s.is_null(i)).then(|| s.value(i)),
                ));
            }
        }
    }

    rows.sort();
    assert_eq!(rows.len(), 2, "one row per distinct group, got {rows:?}");
    assert_eq!(rows[0].0, "a.example");
    assert_eq!(rows[0].1, "10.0.0.1");
    assert_eq!(rows[0].2, 3, "three records collapsed into one counted row");
    assert_eq!(rows[0].3, Some(15.0), "sum_rtt = 5 * 3");
    assert_eq!(rows[1].2, 1);
}
```

- [ ] **Step 2: Run the test to verify it fails, then passes**

Run: `cargo test --test aggregate_local_integration`
Expected: initially FAIL if any wiring is wrong; after Tasks 1-7 are complete it must PASS. Debug real failures — do not weaken the assertions. If the test is flaky on timing, increase the sleeps rather than removing the assertions.

- [ ] **Step 3: Commit**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
git add tests/aggregate_local_integration.rs
git commit -m "test(aggregate): integration test through the real writer to local disk"
```

---

### Task 10: End-to-end test — Zeek TCP listener to aggregated Parquet

**Files:**
- Create: `tests/aggregate_e2e.rs`

**Notes:** Model on `tests/zeek_backpressure_e2e.rs` / `tests/zeek_flush_decoupling_e2e.rs` for the listener-on-an-ephemeral-port pattern. This exercises the outermost interface: bytes on a socket in, aggregated Parquet on disk out.

- [ ] **Step 1: Write the test**

```rust
//! End-to-end: NDJSON over a real TCP socket → Zeek listener → aggregating
//! handler → Parquet on local disk. Exercises the whole path through the
//! outermost interface, with no in-process shortcuts around the listener.

use logthing::forwarding::aggregate::{
    AggregateWriterHandle, Aggregator, CompiledRule, handlers, rule_schema, start_aggregate_writer,
};
use logthing::forwarding::local_sink::LocalDiskSink;
use logthing::zeek::listener::{ZeekListener, ZeekListenerConfig};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

fn walk_all_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk_all_files(&path));
        } else {
            out.push(path);
        }
    }
    out
}

#[tokio::test]
async fn ndjson_over_tcp_becomes_an_aggregated_parquet_table() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sink = Arc::new(
        LocalDiskSink::new(dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new"),
    );

    let group_by = vec!["query".to_string()];
    let rules = vec![CompiledRule {
        name: Arc::from("dns_by_query"),
        source: "zeek".to_string(),
        stream: Some("dns".to_string()),
        group_by: group_by.clone(),
        aggs: Vec::new(),
        schema: rule_schema(&group_by, &[]),
    }];

    let (handle, _writer_task) = start_aggregate_writer(
        &rules,
        "aggregate".to_string(),
        1,
        256,
        sink,
        Arc::new(logthing::stats::SourceHourlyStats::new()),
        None,
    );
    let handle: Arc<AggregateWriterHandle> = Arc::new(handle);

    let agg = Arc::new(Aggregator::new(rules, 1000));
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let emit = agg.clone().spawn_emit_task(
        vec![handle],
        std::time::Duration::from_secs(1),
        shutdown_rx.clone(),
    );

    let decorated: Arc<dyn logthing::zeek::listener::ZeekHandler> =
        Arc::new(handlers::AggregatingZeekHandler {
            agg: agg.clone(),
            inner: Arc::new(logthing::zeek::listener::DefaultZeekHandler),
        });

    // Bind an ephemeral port so parallel test runs never collide.
    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("probe bind");
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    let listener_cfg = ZeekListenerConfig {
        tcp_port: port,
        bind_address: "127.0.0.1".to_string(),
    };
    let listener_shutdown = shutdown_rx.clone();
    let listener_task = tokio::spawn(async move {
        let listener = ZeekListener::new(listener_cfg, decorated);
        let _ = listener.start_with_shutdown(listener_shutdown).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // Speak the wire protocol: newline-delimited JSON over TCP.
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect to the zeek listener");
    for _ in 0..4 {
        stream
            .write_all(b"{\"_path\":\"dns\",\"query\":\"noisy.example\"}\n")
            .await
            .expect("write dns line");
    }
    stream
        .write_all(b"{\"_path\":\"dns\",\"query\":\"quiet.example\"}\n")
        .await
        .expect("write dns line");
    stream.flush().await.expect("flush");
    drop(stream);

    tokio::time::sleep(std::time::Duration::from_secs(4)).await;
    shutdown_tx.send(true).expect("shutdown");
    emit.await.expect("emit task joins");
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), listener_task).await;
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    let rule_dir = dir.path().join("aggregate/dns_by_query");
    let parquet_files: Vec<_> = walk_all_files(&rule_dir)
        .into_iter()
        .filter(|p| p.extension().is_some_and(|e| e == "parquet"))
        .collect();
    assert!(
        !parquet_files.is_empty(),
        "expected aggregated Parquet under {rule_dir:?}"
    );

    use arrow::array::{StringArray, UInt64Array};
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

    let mut counts: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for file in &parquet_files {
        let bytes = std::fs::read(file).expect("read parquet");
        let reader = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(bytes))
            .expect("parquet builder")
            .build()
            .expect("parquet reader");
        for batch in reader {
            let batch = batch.expect("batch ok");
            let q = batch
                .column_by_name("query")
                .unwrap()
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let n = batch
                .column_by_name("count")
                .unwrap()
                .as_any()
                .downcast_ref::<UInt64Array>()
                .unwrap();
            for i in 0..batch.num_rows() {
                *counts.entry(q.value(i).to_string()).or_default() += n.value(i);
            }
        }
    }

    assert_eq!(
        counts.get("noisy.example").copied(),
        Some(4),
        "four identical queries must collapse to one row with count=4, got {counts:?}"
    );
    assert_eq!(counts.get("quiet.example").copied(), Some(1));
}
```

- [ ] **Step 2: Run it**

Run: `cargo test --test aggregate_e2e -- --nocapture`
Expected: PASS. If it is flaky, lengthen the sleeps — never weaken the count assertions.

- [ ] **Step 3: Commit**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
git add tests/aggregate_e2e.rs
git commit -m "test(aggregate): e2e from NDJSON over TCP to aggregated parquet"
```

---

### Task 11: Documentation

**Files:**
- Modify: `README.md` (feature bullet + a configuration subsection)
- Modify: `logthing.toml` (commented example section)

- [ ] **Step 1: Add the README feature bullet**

In the `## Features` list, after the Parquet S3 Storage bullet:

```markdown
- **Log Aggregation**: Optionally count records as they arrive, grouped by configured columns, writing an SQL `GROUP BY`-style table to Parquet instead of the raw rows — cuts noisy streams down to their useful summary
```

- [ ] **Step 2: Add the README configuration section**

Add a `### Log Aggregation` section after the existing per-source configuration documentation:

````markdown
### Log Aggregation

Aggregation counts records as they arrive, grouped by configured columns, and
writes the counted table to Parquet. A stream covered by a rule **stops
writing raw rows entirely** — that is the point: the noisy stream is reduced to
its summary.

```toml
[aggregate]
enabled = true
flush_interval_secs = 300   # window length; each row carries window_start/window_end
max_groups = 100000         # per rule, per window

[aggregate.local]           # and/or [aggregate.s3], same shape as other sources
directory = "/data/agg"
prefix = "aggregate"

[[aggregate.rules]]
name = "dns_by_query"       # unique; becomes the output partition
source = "zeek"             # zeek | suricata | syslog | ipfix | sflow
stream = "dns"              # optional; omitted = every record from that source
group_by = ["query", "id.orig_h"]

[[aggregate.rules]]
name = "flow_talkers"
source = "ipfix"
group_by = ["src_addr", "dst_addr", "dst_port"]
sum = ["octet_delta_count", "packet_delta_count"]
```

Output lands at `<prefix>/<rule>/year=/month=/day=/<uuid>.parquet` with one
column per `group_by` field, a `count`, one column per `sum`/`min`/`max`, and
`window_start`/`window_end`.

Notes:

- `stream` matches the Zeek `_path`, Suricata `event_type`, syslog `app_name`,
  sFlow `"flow"`/`"counter"`, or IPFIX `"flows"`.
- A record matching two rules is counted in both.
- Aggregates follow SQL semantics: missing and non-numeric values are skipped,
  the record is still counted, and a group with no numeric observations emits
  NULL rather than 0.
- Past `max_groups` distinct groups in a window, further keys fold into a
  single `_other` row so the window total stays exact.
- Invalid rules (unknown or disabled source, empty `group_by`, duplicate name,
  no destination) are fatal at startup rather than silently inert.
````

- [ ] **Step 3: Add the commented example to `logthing.toml`**

Append:

```toml
# Optional log aggregation: count records as they arrive, grouped by configured
# columns, and write the counted table to Parquet instead of the raw rows.
# Disabled by default.
# [aggregate]
# enabled = true
# flush_interval_secs = 300
# max_groups = 100000
#
# [aggregate.local]
# directory = "/data/agg"
# prefix = "aggregate"
#
# [[aggregate.rules]]
# name = "dns_by_query"
# source = "zeek"
# stream = "dns"
# group_by = ["query", "id.orig_h"]
```

- [ ] **Step 4: Verify the documented TOML actually parses**

Run the config unit tests, which cover this shape: `cargo test --lib config::tests::aggregate`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add README.md logthing.toml
git commit -m "docs(aggregate): document group-by aggregation configuration"
```

---

## Final verification

- [ ] `cargo fmt --check`
- [ ] `cargo clippy --all-targets -- -D warnings`
- [ ] `cargo test` — the full suite, including the two new test files
- [ ] Confirm existing behavior is untouched with aggregation off: `[aggregate].enabled` defaults to `false`, so every pre-existing test must pass unchanged.
