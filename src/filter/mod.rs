//! Event filter: drop whole records that match a `[[filter.rules]]` entry before they are
//! enqueued, on every source. Rules are compiled once at startup ([`compile_filters`]) and
//! partitioned per source, so each hook only evaluates its own source's rules and a source
//! with no rules pays one `Option` check per record. Field lookup goes through
//! [`AggFields`], the same adapter aggregation and cardinality watching use. Semantics are
//! documented in `docs/filter.md`.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::{Context, bail};
use regex::{Regex, RegexBuilder};
use serde_json::Value;

use crate::config::{Config, FilterRule};
use crate::forwarding::aggregate::fields::{AggFields, FieldValue};

/// Sources a filter rule may name.
pub const KNOWN_SOURCES: [&str; 8] = [
    "wef", "syslog", "zeek", "suricata", "ipfix", "sflow", "hec", "otlp",
];

/// Compiled-regex size cap so a pathological pattern fails at startup.
const REGEX_SIZE_LIMIT: usize = 1 << 20;

/// Largest integer an f64 holds exactly (2^53).
const F64_EXACT_INT: f64 = 9_007_199_254_740_992.0;

#[derive(Debug)]
enum Condition {
    Equals(String),
    AnyOf(Vec<String>),
    Regex(Regex),
}

impl Condition {
    fn matches(&self, text: &str) -> bool {
        match self {
            Condition::Equals(want) => text == want,
            Condition::AnyOf(wants) => wants.iter().any(|w| w == text),
            Condition::Regex(re) => re.is_match(text),
        }
    }
}

#[derive(Debug)]
struct CompiledRule {
    name: String,
    conditions: Vec<(String, Condition)>,
}

impl CompiledRule {
    fn matches<R: AggFields>(&self, rec: &R) -> bool {
        self.conditions.iter().all(|(field, cond)| {
            rec.field(field)
                .is_some_and(|v| cond.matches(&filter_text(v)))
        })
    }
}

/// The compiled rules for one source.
#[derive(Debug)]
pub struct SourceFilter {
    source: &'static str,
    rules: Vec<CompiledRule>,
}

impl SourceFilter {
    /// The source these rules apply to (the `source` label on `events_filtered`).
    pub fn source(&self) -> &'static str {
        self.source
    }

    /// Name of the first rule that matches `rec`, without counting anything.
    pub fn matching_rule<R: AggFields>(&self, rec: &R) -> Option<&str> {
        self.rules
            .iter()
            .find(|r| r.matches(rec))
            .map(|r| r.name.as_str())
    }

    /// True when `rec` matches a rule; increments `events_filtered{source,rule}`.
    pub fn drops<R: AggFields>(&self, rec: &R) -> bool {
        match self.matching_rule(rec) {
            Some(rule) => {
                metrics::counter!("events_filtered",
                    "source" => self.source,
                    "rule" => rule.to_owned()
                )
                .increment(1);
                true
            }
            None => false,
        }
    }

    /// Remove (and count) every record that matches a rule.
    pub fn retain_unmatched<R: AggFields>(&self, recs: &mut Vec<R>) {
        recs.retain(|r| !self.drops(r));
    }
}

/// `filter.drops(rec)` when a filter is configured for the source, else `false`.
pub fn should_drop<R: AggFields>(filter: Option<&SourceFilter>, rec: &R) -> bool {
    filter.is_some_and(|f| f.drops(rec))
}

/// Every source's compiled filter; sources without rules have none.
#[derive(Debug, Default, Clone)]
pub struct CompiledFilters {
    by_source: HashMap<&'static str, Arc<SourceFilter>>,
}

impl CompiledFilters {
    /// The filter for `source`, or `None` when it has no rules.
    pub fn for_source(&self, source: &str) -> Option<Arc<SourceFilter>> {
        self.by_source.get(source).cloned()
    }
}

/// Text form used for every comparison: strings as-is, integral numbers below 2^53 without a
/// fractional part, other numbers via f64 `Display`, booleans as `true`/`false`. Never
/// truncates (unlike aggregation's `group_value_string`).
pub fn filter_text(v: FieldValue<'_>) -> Cow<'_, str> {
    match v {
        FieldValue::Str(s) => s,
        FieldValue::Num(x) => Cow::Owned(num_text(x)),
        FieldValue::Bool(true) => Cow::Borrowed("true"),
        FieldValue::Bool(false) => Cow::Borrowed("false"),
    }
}

fn num_text(x: f64) -> String {
    if x.fract() == 0.0 && x.abs() < F64_EXACT_INT {
        format!("{}", x as i64)
    } else {
        format!("{x}")
    }
}

fn source_enabled(config: &Config, source: &str) -> bool {
    match source {
        "wef" => true,
        "syslog" => config.syslog.enabled,
        "zeek" => config.zeek.enabled,
        "suricata" => config.suricata.enabled,
        "ipfix" => config.ipfix.enabled,
        "sflow" => config.sflow.enabled,
        "hec" => config.hec.enabled,
        "otlp" => cfg!(feature = "otlp") && config.otlp.enabled,
        _ => false,
    }
}

fn scalar_text(rule: &str, field: &str, v: &Value) -> anyhow::Result<String> {
    match v {
        Value::String(s) => Ok(s.clone()),
        Value::Bool(b) => Ok(b.to_string()),
        Value::Number(n) if n.is_i64() || n.is_u64() => Ok(n.to_string()),
        Value::Number(n) => Ok(num_text(n.as_f64().unwrap_or(f64::NAN))),
        _ => bail!(
            "[[filter.rules]] \"{rule}\": field {field:?} must be a string, number, boolean, \
             a list of those, or {{ regex = \"...\" }}"
        ),
    }
}

fn compile_regex(rule: &str, field: &str, p: &str) -> anyhow::Result<Regex> {
    let ctx = || format!("[[filter.rules]] \"{rule}\": field {field:?}: invalid regex {p:?}");
    let re = RegexBuilder::new(p)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .with_context(ctx)?;
    // `^`, `.*`, `x?` ... match the empty string, i.e. every value of the field.
    let min_len = regex_syntax::parse(p)
        .with_context(ctx)?
        .properties()
        .minimum_len();
    if min_len == Some(0) {
        bail!(
            "[[filter.rules]] \"{rule}\": field {field:?}: regex {p:?} can match the empty \
             string (it would drop every event carrying the field); require at least one \
             character"
        );
    }
    Ok(re)
}

fn compile_condition(rule: &str, field: &str, v: &Value) -> anyhow::Result<Condition> {
    match v {
        Value::Array(items) => {
            if items.is_empty() {
                bail!("[[filter.rules]] \"{rule}\": field {field:?} has an empty list");
            }
            let texts = items
                .iter()
                .map(|i| scalar_text(rule, field, i))
                .collect::<anyhow::Result<Vec<_>>>()?;
            Ok(Condition::AnyOf(texts))
        }
        Value::Object(m) => match (m.len(), m.get("regex")) {
            (1, Some(Value::String(p))) => Ok(Condition::Regex(compile_regex(rule, field, p)?)),
            _ => bail!(
                "[[filter.rules]] \"{rule}\": field {field:?}: a table condition must be \
                 exactly {{ regex = \"...\" }}"
            ),
        },
        other => Ok(Condition::Equals(scalar_text(rule, field, other)?)),
    }
}

fn compile_rule(rule: &FilterRule) -> anyhow::Result<CompiledRule> {
    let name = &rule.name;
    if rule.r#match.is_empty() {
        bail!("[[filter.rules]] \"{name}\": match is empty (it would drop every event)");
    }
    let mut conditions = Vec::with_capacity(rule.r#match.len());
    for (field, v) in &rule.r#match {
        if field.is_empty() {
            bail!("[[filter.rules]] \"{name}\": empty field name in match");
        }
        conditions.push((field.clone(), compile_condition(name, field, v)?));
    }
    Ok(CompiledRule {
        name: name.clone(),
        conditions,
    })
}

/// Validate and compile `[[filter.rules]]`. Every failure is fatal at startup and names the
/// rule. Field names are not checked against a schema (free-form JSON is open-ended); a field a
/// record lacks simply never matches.
pub fn compile_filters(config: &Config) -> anyhow::Result<CompiledFilters> {
    let mut seen = HashSet::new();
    let mut grouped: HashMap<&'static str, Vec<CompiledRule>> = HashMap::new();
    for rule in &config.filter.rules {
        if rule.name.is_empty() {
            bail!("[[filter.rules]] entry has an empty name");
        }
        if !seen.insert(rule.name.as_str()) {
            bail!("[[filter.rules]] duplicate rule name \"{}\"", rule.name);
        }
        let Some(source) = KNOWN_SOURCES.iter().copied().find(|s| *s == rule.source) else {
            bail!(
                "[[filter.rules]] \"{}\": unknown source '{}' (expected one of {:?})",
                rule.name,
                rule.source,
                KNOWN_SOURCES
            );
        };
        if !source_enabled(config, source) {
            bail!(
                "[[filter.rules]] \"{}\": source '{source}' is disabled in config",
                rule.name
            );
        }
        grouped.entry(source).or_default().push(compile_rule(rule)?);
    }
    let by_source = grouped
        .into_iter()
        .map(|(source, rules)| (source, Arc::new(SourceFilter { source, rules })))
        .collect();
    Ok(CompiledFilters { by_source })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, FilterRule};
    use std::borrow::Cow;
    use std::collections::{BTreeMap, HashMap};

    /// Minimal record: a flat map of field name -> JSON scalar.
    struct Rec(HashMap<&'static str, serde_json::Value>);
    impl AggFields for Rec {
        fn stream(&self) -> &str {
            ""
        }
        fn field(&self, name: &str) -> Option<FieldValue<'_>> {
            match self.0.get(name)? {
                serde_json::Value::String(s) => Some(FieldValue::Str(Cow::Borrowed(s))),
                serde_json::Value::Number(n) => n.as_f64().map(FieldValue::Num),
                serde_json::Value::Bool(b) => Some(FieldValue::Bool(*b)),
                _ => None,
            }
        }
    }
    fn rec(pairs: &[(&'static str, serde_json::Value)]) -> Rec {
        Rec(pairs.iter().cloned().collect())
    }
    fn rule(name: &str, source: &str, m: serde_json::Value) -> FilterRule {
        let r#match: BTreeMap<String, serde_json::Value> =
            serde_json::from_value(m).expect("match must be an object");
        FilterRule {
            name: name.into(),
            source: source.into(),
            r#match,
        }
    }
    fn config(rules: Vec<FilterRule>) -> Config {
        let mut c = Config::default();
        c.syslog.enabled = true;
        c.zeek.enabled = true;
        c.ipfix.enabled = false;
        c.filter.rules = rules;
        c
    }
    fn syslog_filter(rules: Vec<FilterRule>) -> Arc<SourceFilter> {
        compile_filters(&config(rules))
            .unwrap()
            .for_source("syslog")
            .unwrap()
    }
    fn err(rules: Vec<FilterRule>) -> String {
        format!("{:#}", compile_filters(&config(rules)).unwrap_err())
    }

    #[test]
    fn no_rules_yields_no_filter_for_any_source() {
        let f = compile_filters(&config(vec![])).unwrap();
        for s in KNOWN_SOURCES {
            assert!(f.for_source(s).is_none(), "{s}");
        }
    }

    #[test]
    fn rules_are_partitioned_by_source() {
        let f = compile_filters(&config(vec![
            rule("a", "syslog", serde_json::json!({"app_name": "x"})),
            rule("b", "zeek", serde_json::json!({"log_path": "dns"})),
        ]))
        .unwrap();
        assert_eq!(f.for_source("syslog").unwrap().source(), "syslog");
        assert_eq!(f.for_source("zeek").unwrap().source(), "zeek");
        assert!(f.for_source("ipfix").is_none());
    }

    #[test]
    fn equals_any_of_and_regex_conditions_match() {
        let f = syslog_filter(vec![
            rule("eq", "syslog", serde_json::json!({"app_name": "systemd"})),
            rule("in", "syslog", serde_json::json!({"hostname": ["a", "b"]})),
            rule(
                "re",
                "syslog",
                serde_json::json!({"message": {"regex": "^Started "}}),
            ),
        ]);
        let m = |pairs: &[(&'static str, serde_json::Value)]| {
            f.matching_rule(&rec(pairs)).map(str::to_owned)
        };
        assert_eq!(m(&[("app_name", "systemd".into())]), Some("eq".into()));
        assert_eq!(m(&[("hostname", "b".into())]), Some("in".into()));
        assert_eq!(m(&[("message", "Started foo".into())]), Some("re".into()));
        assert_eq!(m(&[("message", "Not Started".into())]), None);
        assert_eq!(m(&[("app_name", "Systemd".into())]), None, "case-sensitive");
    }

    #[test]
    fn regex_is_an_unanchored_search() {
        let f = syslog_filter(vec![rule(
            "re",
            "syslog",
            serde_json::json!({"message": {"regex": "disk"}}),
        )]);
        assert!(
            f.matching_rule(&rec(&[("message", "low disk space".into())]))
                .is_some()
        );
    }

    #[test]
    fn conditions_in_one_rule_are_anded_and_rules_are_ored() {
        let f = syslog_filter(vec![
            rule(
                "both",
                "syslog",
                serde_json::json!({"app_name": "a", "hostname": "h"}),
            ),
            rule("other", "syslog", serde_json::json!({"msg_id": "m"})),
        ]);
        assert!(f.matching_rule(&rec(&[("app_name", "a".into())])).is_none());
        assert_eq!(
            f.matching_rule(&rec(&[("app_name", "a".into()), ("hostname", "h".into())])),
            Some("both")
        );
        assert_eq!(
            f.matching_rule(&rec(&[("msg_id", "m".into())])),
            Some("other")
        );
    }

    #[test]
    fn numbers_and_numeric_strings_compare_equal() {
        let f = syslog_filter(vec![
            rule("int", "syslog", serde_json::json!({"severity": 3})),
            rule("float", "syslog", serde_json::json!({"facility": 4.0})),
            rule("str", "syslog", serde_json::json!({"priority": "13"})),
            rule("frac", "syslog", serde_json::json!({"ratio": 0.5})),
            rule("bool", "syslog", serde_json::json!({"flag": true})),
        ]);
        let m = |pairs: &[(&'static str, serde_json::Value)]| {
            f.matching_rule(&rec(pairs)).map(str::to_owned)
        };
        assert_eq!(m(&[("severity", 3.into())]), Some("int".into()));
        assert_eq!(m(&[("severity", "3".into())]), Some("int".into()));
        assert_eq!(m(&[("facility", 4.into())]), Some("float".into()));
        assert_eq!(m(&[("priority", 13.into())]), Some("str".into()));
        assert_eq!(m(&[("ratio", serde_json::json!(0.5))]), Some("frac".into()));
        assert_eq!(m(&[("flag", true.into())]), Some("bool".into()));
        assert_eq!(m(&[("flag", "true".into())]), Some("bool".into()));
    }

    #[test]
    fn missing_field_and_null_never_match() {
        let f = syslog_filter(vec![rule(
            "r",
            "syslog",
            serde_json::json!({"app_name": "x"}),
        )]);
        assert!(f.matching_rule(&rec(&[])).is_none());
        assert!(
            f.matching_rule(&rec(&[("app_name", serde_json::Value::Null)]))
                .is_none()
        );
    }

    #[test]
    fn filter_text_renders_without_truncation() {
        let long = "x".repeat(1000);
        assert_eq!(
            filter_text(FieldValue::Str(Cow::Borrowed(&long))).len(),
            1000
        );
        assert_eq!(filter_text(FieldValue::Num(5156.0)), "5156");
        assert_eq!(filter_text(FieldValue::Num(-2.0)), "-2");
        assert_eq!(filter_text(FieldValue::Num(0.25)), "0.25");
        assert_eq!(filter_text(FieldValue::Bool(false)), "false");
    }

    #[test]
    fn retain_unmatched_removes_only_matches() {
        let f = syslog_filter(vec![rule(
            "r",
            "syslog",
            serde_json::json!({"app_name": "x"}),
        )]);
        let mut v = vec![
            rec(&[("app_name", "x".into())]),
            rec(&[("app_name", "y".into())]),
        ];
        f.retain_unmatched(&mut v);
        assert_eq!(v.len(), 1);
        assert!(f.matching_rule(&v[0]).is_none());
    }

    #[test]
    fn should_drop_is_false_without_a_filter() {
        assert!(!should_drop::<Rec>(None, &rec(&[("app_name", "x".into())])));
    }

    #[test]
    fn empty_matching_regex_is_rejected() {
        for p in ["^", ".*", "x?", ""] {
            let e = err(vec![rule(
                "r",
                "syslog",
                serde_json::json!({"message": {"regex": p}}),
            )]);
            assert!(e.contains("\"r\"") && e.contains("message"), "{p}: {e}");
        }
    }

    #[test]
    fn invalid_rules_fail_with_rule_name() {
        let cases = vec![
            (
                vec![rule("", "syslog", serde_json::json!({"a": 1}))],
                "name",
            ),
            (
                vec![
                    rule("d", "syslog", serde_json::json!({"a": 1})),
                    rule("d", "syslog", serde_json::json!({"b": 1})),
                ],
                "duplicate",
            ),
            (
                vec![rule("u", "nope", serde_json::json!({"a": 1}))],
                "unknown source",
            ),
            (
                vec![rule("dis", "ipfix", serde_json::json!({"a": 1}))],
                "disabled",
            ),
            (vec![rule("e", "syslog", serde_json::json!({}))], "empty"),
            (
                vec![rule("f", "syslog", serde_json::json!({"": 1}))],
                "field",
            ),
            (
                vec![rule("l", "syslog", serde_json::json!({"a": []}))],
                "empty",
            ),
            (
                vec![rule("n", "syslog", serde_json::json!({"a": null}))],
                "a",
            ),
            (
                vec![rule("nest", "syslog", serde_json::json!({"a": [[1]]}))],
                "a",
            ),
            (
                vec![rule("obj", "syslog", serde_json::json!({"a": {"x": 1}}))],
                "regex",
            ),
            (
                vec![rule(
                    "bad",
                    "syslog",
                    serde_json::json!({"a": {"regex": "("}}),
                )],
                "regex",
            ),
        ];
        for (rules, needle) in cases {
            let e = err(rules);
            assert!(
                e.to_lowercase().contains(needle),
                "expected {needle:?} in {e}"
            );
        }
    }

    #[test]
    fn wef_is_always_enabled() {
        let c = config(vec![rule(
            "w",
            "wef",
            serde_json::json!({"event_id": 5156}),
        )]);
        assert!(compile_filters(&c).unwrap().for_source("wef").is_some());
    }

    #[test]
    fn toml_rules_deserialize_into_config() {
        let toml = r#"
            [[filter.rules]]
            name = "wfp"
            source = "wef"
            match = { event_id = [5156, 5158], "data.Application" = { regex = "svchost" } }
        "#;
        let c: Config = ::config::Config::builder()
            .add_source(::config::File::from_str(toml, ::config::FileFormat::Toml))
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap();
        let f = compile_filters(&c).unwrap().for_source("wef").unwrap();
        let mut ok = HashMap::new();
        ok.insert("event_id", serde_json::json!(5158));
        ok.insert("data.Application", serde_json::json!("C:\\svchost.exe"));
        assert_eq!(f.matching_rule(&Rec(ok)), Some("wfp"));
    }

    #[test]
    fn test_source_enabled_unknown_source_is_false() {
        let config = Config::default();
        assert!(source_enabled(&config, "wef"));
        assert!(!source_enabled(&config, "carrier-pigeon"));
    }
}
