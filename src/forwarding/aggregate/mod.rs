//! Optional record aggregation: an SQL `GROUP BY` evaluated at ingest.
//!
//! A record matching a rule is counted here and NOT forwarded to the raw
//! writer (suppression) — that is the whole point, reducing noisy logging at
//! the input stage while keeping the valuable summary.

pub mod fields;
pub mod handlers;

use arrow_schema::{DataType, Field, Schema, TimeUnit};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
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

/// Group map plus the per-rule live-group counts that keep the cardinality
/// cap an O(1) check. Both live under the same mutex so they can never drift
/// out of sync with each other.
struct AggState {
    groups: HashMap<(usize, GroupKey), Acc>,
    /// Live `Keys` (non-`Other`) group count per rule index, mirroring
    /// `groups`. Incremented exactly once per genuinely new `Keys` entry;
    /// reset to zero alongside `groups` in `drain()`.
    counts: Vec<usize>,
}

/// Metric handles resolved once per rule at construction, so `consume()`
/// never allocates a label string on the hot path.
struct RuleMetrics {
    consumed: metrics::Counter,
    overflow: metrics::Counter,
}

/// In-memory group state for every rule.
pub struct Aggregator {
    rules: Vec<CompiledRule>,
    max_groups: usize,
    metrics: Vec<RuleMetrics>,
    // ponytail: one mutex over all rules' groups. A hashmap lookup plus a
    // counter bump is tens of nanoseconds; shard by rule if a profile ever
    // shows contention here.
    state: Mutex<AggState>,
}

impl Aggregator {
    pub fn new(rules: Vec<CompiledRule>, max_groups: usize) -> Self {
        let metrics = rules
            .iter()
            .map(|r| RuleMetrics {
                consumed: metrics::counter!("aggregate_records_consumed", "rule" => r.name.to_string()),
                overflow: metrics::counter!("aggregate_overflow_records", "rule" => r.name.to_string()),
            })
            .collect();
        let counts = vec![0; rules.len()];
        Self {
            rules,
            max_groups,
            metrics,
            state: Mutex::new(AggState {
                groups: HashMap::new(),
                counts,
            }),
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

            let mut guard = self.state.lock().expect("aggregator state mutex poisoned");
            // Split the guard into disjoint field borrows up front: through
            // a `MutexGuard`, `state.groups.entry(key)` ties up the *whole*
            // guard for the borrow checker (it can't see `groups` and
            // `counts` as independent places across the deref), so checking
            // `state.counts[idx]` from inside that match's arms does not
            // borrow-check. Destructuring into two local `&mut` bindings
            // first makes the two fields provably disjoint again.
            let AggState { groups, counts } = &mut *guard;
            let key = (idx, GroupKey::Keys(keys));
            // O(1) cap check: `counts[idx]` mirrors the live number of
            // `Keys` groups for this rule, so no per-record scan of the
            // (shared, all-rules) map is needed. On a genuinely new key that
            // would exceed the cap, abandon the vacant entry for `key` and
            // re-enter under `(idx, GroupKey::Other)` instead — one extra
            // hash lookup only on the rare overflow path, never on the
            // common "already tracked" or "room under the cap" paths.
            let entry = match groups.entry(key) {
                Entry::Occupied(e) => e.into_mut(),
                Entry::Vacant(e) => {
                    if counts[idx] >= self.max_groups {
                        self.metrics[idx].overflow.increment(1);
                        groups.entry((idx, GroupKey::Other)).or_insert_with(|| Acc {
                            count: 0,
                            aggs: rule.aggs.iter().map(|_| AggAcc::new()).collect(),
                        })
                    } else {
                        counts[idx] += 1;
                        e.insert(Acc {
                            count: 0,
                            aggs: rule.aggs.iter().map(|_| AggAcc::new()).collect(),
                        })
                    }
                }
            };

            entry.count += 1;
            for (acc, obs) in entry.aggs.iter_mut().zip(observations) {
                if let Some(v) = obs {
                    acc.observe(v);
                }
            }
            drop(guard);

            self.metrics[idx].consumed.increment(1);
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
            // Reset the per-rule counters alongside the map they mirror —
            // they must never drift out of sync across a window boundary.
            state.counts.iter_mut().for_each(|c| *c = 0);
            std::mem::take(&mut state.groups)
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
            anyhow::bail!(
                "[[aggregate.rules]] '{}' has an empty `group_by`",
                rule.name
            );
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

        let schema = rule_schema(&rule.group_by, &aggs);
        compiled.push(CompiledRule {
            name: Arc::from(rule.name.as_str()),
            source: rule.source.clone(),
            stream: rule.stream.clone(),
            group_by: rule.group_by.clone(),
            aggs,
            schema,
        });
    }

    Ok(compiled)
}

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
            assert!(agg.consume(
                "zeek",
                &zeek("dns", serde_json::json!({"query": "a.example"}))
            ));
        }
        assert!(agg.consume(
            "zeek",
            &zeek("dns", serde_json::json!({"query": "b.example"}))
        ));

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
            &zeek(
                "dns",
                serde_json::json!({"query": "a", "id.orig_h": "10.0.0.1"})
            )
        ));
        let rows = drain_sorted(&agg);
        assert_eq!(rows.len(), 2, "one record must feed both rules");
        assert!(rows.iter().all(|r| r.count == 1));
    }

    #[test]
    fn a_missing_group_field_becomes_null_and_the_record_is_still_counted() {
        let agg = Aggregator::new(
            vec![rule("r", "zeek", Some("dns"), &["query", "absent"])],
            1000,
        );
        assert!(agg.consume("zeek", &zeek("dns", serde_json::json!({"query": "a"}))));
        let rows = drain_sorted(&agg);
        assert_eq!(rows[0].keys, vec![Some("a".to_string()), None]);
        assert_eq!(rows[0].count, 1);
    }

    #[test]
    fn sum_min_max_accumulate_over_numeric_fields() {
        let mut r = rule("r", "zeek", Some("conn"), &["proto"]);
        r.aggs = vec![
            AggSpec {
                kind: AggKind::Sum,
                field: "orig_bytes".into(),
                column: "sum_orig_bytes".into(),
            },
            AggSpec {
                kind: AggKind::Min,
                field: "orig_bytes".into(),
                column: "min_orig_bytes".into(),
            },
            AggSpec {
                kind: AggKind::Max,
                field: "orig_bytes".into(),
                column: "max_orig_bytes".into(),
            },
        ];
        let agg = Aggregator::new(vec![r], 1000);
        for b in [10.0, 30.0, 20.0] {
            agg.consume(
                "zeek",
                &zeek("conn", serde_json::json!({"proto": "tcp", "orig_bytes": b})),
            );
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
        agg.consume(
            "zeek",
            &zeek("conn", serde_json::json!({"proto": "tcp", "orig_bytes": 5})),
        );
        agg.consume("zeek", &zeek("conn", serde_json::json!({"proto": "tcp"})));
        agg.consume(
            "zeek",
            &zeek(
                "conn",
                serde_json::json!({"proto": "tcp", "orig_bytes": "abc"}),
            ),
        );
        // A numeric string DOES contribute.
        agg.consume(
            "zeek",
            &zeek(
                "conn",
                serde_json::json!({"proto": "tcp", "orig_bytes": "7"}),
            ),
        );
        // Non-finite (JSON itself cannot carry NaN/Infinity, but a numeric
        // string parses to one, which is exactly what `numeric_value` must
        // still reject).
        agg.consume(
            "zeek",
            &zeek(
                "conn",
                serde_json::json!({"proto": "tcp", "orig_bytes": "NaN"}),
            ),
        );

        let rows = drain_sorted(&agg);
        assert_eq!(
            rows[0].count, 5,
            "every record counts regardless of aggregate usability"
        );
        assert_eq!(
            rows[0].aggs,
            vec![Some(12.0)],
            "NaN must not pollute the sum"
        );
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
        assert_eq!(
            rows[0].aggs,
            vec![None],
            "SUM over zero rows is NULL, not 0.0"
        );
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
            agg.consume(
                "zeek",
                &zeek("dns", serde_json::json!({"query": format!("q{i}"), "n": 1})),
            );
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
        assert_eq!(
            other.aggs,
            vec![Some(3.0)],
            "aggregates accumulate into _other too"
        );
    }

    #[test]
    fn the_per_rule_group_counter_resets_on_drain_so_a_fresh_window_admits_max_groups_again() {
        let agg = Aggregator::new(vec![rule("r", "zeek", Some("dns"), &["query"])], 2);
        // Fill past the cap in window 1: 3 distinct keys against a cap of 2
        // must fold the 3rd into `_other`.
        for i in 0..3 {
            agg.consume(
                "zeek",
                &zeek("dns", serde_json::json!({"query": format!("q{i}")})),
            );
        }
        let rows = drain_sorted(&agg);
        assert_eq!(rows.len(), 3, "2 real groups + 1 overflow row in window 1");

        // If the per-rule live-group counter did not reset alongside the
        // map on drain, it would still read >= max_groups here and every
        // key in window 2 — even brand new ones — would immediately
        // overflow into `_other`.
        for i in 0..2 {
            agg.consume(
                "zeek",
                &zeek("dns", serde_json::json!({"query": format!("w2-{i}")})),
            );
        }
        let rows = drain_sorted(&agg);
        assert_eq!(
            rows.len(),
            2,
            "a fresh window must admit max_groups real groups again, not overflow immediately"
        );
        assert!(
            rows.iter()
                .all(|r| r.keys.iter().all(|k| k.as_deref() != Some(OTHER_LABEL))),
            "neither key should have overflowed: {rows:?}"
        );
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
        assert_eq!(
            rows[0].keys,
            vec![None],
            "null key, not the _other sentinel"
        );
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
        assert!(
            err.contains("nosuch"),
            "error must name the bad source: {err}"
        );
    }

    #[test]
    fn compile_rules_rejects_a_source_that_is_disabled() {
        let mut cfg = config_with(vec![raw_rule("r", "zeek", &["query"])]);
        cfg.zeek.enabled = false;
        let err = compile_rules(&cfg).unwrap_err().to_string();
        assert!(
            err.contains("zeek"),
            "error must name the disabled source: {err}"
        );
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
        assert!(
            compile_rules(&cfg)
                .expect("disabled is not an error")
                .is_empty()
        );
    }

    // -- Task 5: rule_schema / AggregateSink --

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
            vec![
                "query",
                "id.orig_h",
                "count",
                "sum_n",
                "window_start",
                "window_end"
            ]
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

        use arrow::array::{Array, Float64Array, StringArray, UInt64Array};
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
}
