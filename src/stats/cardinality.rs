//! Bounded distinct-value counter for a single, operator-configured field
//! watch (`[metrics] cardinality_watch_field`).
//!
//! Answers "is ingestion working?" by comparing a field's observed distinct
//! value count against a known-good number — e.g. "we have ~5000 hosts; is
//! `/metrics` reporting ~5000 distinct `id.orig_h` values?" Exposed as
//! `field_distinct_values{stream,field}` (gauge, most-recently-completed
//! window — see [`CardinalityWatcher::tick`]) and
//! `field_distinct_values_capped{stream,field}` (counter, fires each time a
//! never-before-seen value was discarded because the cap was already
//! reached).
//!
//! # Reading the gauge
//!
//! - `id.orig_h` (this repo's shipped default, `logthing.toml`) is an IP,
//!   not a stable host identity: DHCP churn, NAT, and multi-homing move the
//!   distinct-IP count independently of ingestion health, and a sensor that
//!   sees inbound/external traffic counts external originators that are not
//!   org hosts at all. Treat the gauge as a proxy for host count, not an
//!   exact one.
//! - A gauge sitting at EXACTLY `cardinality_max_values` means "read
//!   `field_distinct_values_capped`", not "this is the real count" — the
//!   set stopped growing at the cap, it did not stop because that's how
//!   many distinct values actually exist.
//! - Alert on a SUSTAINED multi-window drop, not on absolute equality to a
//!   known host count. A single window's value is noisy (see the doc on
//!   `cardinality_window_secs` for why the default window is an hour, not a
//!   few minutes).
//! - Two distinct values that share the same first `MAX_GROUP_VALUE_BYTES`
//!   (256) bytes collapse into one tracked entry — `group_value_string`
//!   truncates before this module ever sees the value (see `fields.rs`'s
//!   own disclosure of the same truncation for the aggregator). This
//!   undercounts, same direction as cap saturation, but is essentially
//!   never reached by an IP-shaped field like `id.orig_h`.
//!
//! # Structurally zeek-only, structurally single-stream
//!
//! ponytail: there is no `source` config key — watching a non-zeek field is
//! out of scope, not validated away, and there is no "every stream" mode:
//! the stream a watch counts on is required whenever a field is configured
//! (counting one field name across every stream at once would conflate
//! e.g. `conn`'s and `dns`'s `id.orig_h` into one number with no way to
//! tell which stream contributed it). Ceiling: exactly one watch, exactly
//! one source (zeek), exactly one stream. Upgrade path: wiring a second
//! source needs that source's own `AggFields` impl (already exists for all
//! five sources in `forwarding::aggregate::fields`), a matching config knob
//! alongside `cardinality_watch_field`/`_stream`, and one
//! `watcher.observe(&record)` call at that source's listener observation
//! point, mirroring zeek's; supporting more than one watch needs
//! `CardinalityWatcher` to hold a `Vec` of watch state instead of one, and
//! `compile_watch` to become `compile_watches` (an earlier draft of this
//! module did exactly that before design review cut it back to one — see
//! git history). Mirrors `forwarding::aggregate`'s compile-then-consume
//! shape: [`compile_watch`] validates config at startup, fatal on a bad
//! watch (`aggregate::compile_rules` is the precedent — a watch that
//! silently never matches is worse than a startup error), and
//! [`CardinalityWatcher::observe`] is the per-record hot path, called from
//! `zeek::listener` alongside `zeek_records_received`.
//!
//! In-memory only, same as every other stat in this module — resets on
//! restart (see the doc comment on `SourceHourlyStats`).
//!
//! # Safety property
//!
//! `stream` and `field` both come from CONFIG, never the wire. A
//! wire-derived label would let any client that can reach the zeek listener
//! mint unbounded Prometheus series — the same reasoning behind
//! `metric_event_type` (`suricata::schema`) and `metric_log_path`
//! (`zeek::schema`). Only the *value count* is wire-influenced, and it is
//! bounded by `cardinality_max_values` before it ever reaches a metric.

use crate::config::Config;
use crate::forwarding::aggregate::fields::{AggFields, group_value_string};
use dashmap::DashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tracing::warn;

/// A validated watch, ready to construct a `CardinalityWatcher` from.
#[derive(Debug)]
pub struct CompiledWatch {
    pub stream: String,
    pub field: String,
}

/// Validate `config.metrics.cardinality_watch_field` (and the
/// stream/window/cap knobs it enables). Returns `None` when
/// `cardinality_watch_field` is unset (feature off). Every failure is fatal
/// at startup: a bad field name would leave an operator staring at a gauge
/// stuck at 0 with no error telling them why, an unset stream would
/// silently mean "watch nothing representable" (see the module doc's
/// "structurally single-stream" section), a zero window would panic later
/// when `tokio::time::interval` is constructed — see
/// `aggregate::compile_rules`'s `flush_interval_secs == 0` check for the
/// exact same trap — and a zero cap would pin the gauge at 0 forever, which
/// reads identically to "ingestion is dead" (see the `cardinality_max_values
/// == 0` check below, matching `compile_rules`'s `max_groups == 0` check).
pub fn compile_watch(config: &Config) -> anyhow::Result<Option<CompiledWatch>> {
    let cfg = &config.metrics;
    let Some(field) = cfg.cardinality_watch_field.as_ref() else {
        return Ok(None);
    };
    if field.trim().is_empty() {
        anyhow::bail!("[metrics] cardinality_watch_field must not be empty");
    }
    let stream = match cfg.cardinality_watch_stream.as_deref() {
        Some(s) if !s.trim().is_empty() => s.to_string(),
        _ => anyhow::bail!(
            "[metrics] cardinality_watch_stream must be set whenever cardinality_watch_field is \
             set (watching a field across every stream at once is not supported)"
        ),
    };
    if cfg.cardinality_window_secs == 0 {
        anyhow::bail!(
            "[metrics] cardinality_window_secs must be greater than 0 (tokio::time::interval \
             panics on a zero period)"
        );
    }
    if cfg.cardinality_max_values == 0 {
        anyhow::bail!(
            "[metrics] cardinality_max_values must be greater than 0 (0 pins \
             field_distinct_values at 0 forever while field_distinct_values_capped climbs — \
             indistinguishable from ingestion being completely dead, the exact misreading this \
             feature exists to prevent)"
        );
    }
    Ok(Some(CompiledWatch {
        stream,
        field: field.clone(),
    }))
}

/// Live state for the configured watch.
pub struct CardinalityWatcher {
    stream: String,
    field: String,
    values: DashSet<String>,
    max_values: usize,
    // Req 5: distinguish "misconfigured field name" from "ingestion is
    // down" — both otherwise look identical (gauge stuck at 0). Set (not
    // incremented) on the hot path, so `observe` stays a single atomic
    // store per record rather than a CAS loop; read-and-reset once per
    // window in `tick`.
    matched_this_window: AtomicBool,
    field_seen_this_window: AtomicBool,
}

impl CardinalityWatcher {
    pub fn new(watch: CompiledWatch, max_values: usize) -> Self {
        Self {
            stream: watch.stream,
            field: watch.field,
            values: DashSet::new(),
            max_values,
            matched_this_window: AtomicBool::new(false),
            field_seen_this_window: AtomicBool::new(false),
        }
    }

    /// Observe one record. Mirrors `Aggregator::consume`'s stream match.
    ///
    /// A record whose configured field is absent is simply not observed —
    /// no entry, no phantom value — mirroring the `count == 0` early return
    /// in `SourceHourlyStats::record`.
    pub fn observe<R: AggFields>(&self, rec: &R) {
        if self.stream != rec.stream() {
            return;
        }
        self.matched_this_window.store(true, Ordering::Relaxed);

        // ponytail: `group_value_string` heap-allocates (and truncates) the
        // value BEFORE the `contains` check below, so an already-tracked
        // value — the common case once the set has warmed up — still pays
        // an allocation that is immediately dropped. Same trade this
        // module's sibling `Aggregator::consume` makes for its group key
        // (`forwarding/aggregate/mod.rs`, `AggState` doc comment). Upgrade
        // path: `truncate_to_bytes` alone does not allocate, so a
        // `contains(&truncated)` check could run first and only call
        // `group_value_string` on a genuine miss — at the cost of bypassing
        // `group_value_string`'s `Str` branch (which reuses an owned
        // `String`'s buffer rather than allocating fresh).
        let Some(value) = rec.field(&self.field).map(group_value_string) else {
            return;
        };
        self.field_seen_this_window.store(true, Ordering::Relaxed);

        // ponytail: check-then-act over a lock-free DashSet — the exact
        // same accepted race as `ThroughputStats::record_event`'s
        // capped-DashMap idiom (see that function's comment). Concurrent
        // callers can each observe room under the cap and all insert,
        // overshooting by up to (concurrent callers - 1) values. Bounded by
        // caller concurrency, not by input size, so it's accepted rather
        // than closed with a Mutex that would serialize this hot path.
        if !self.values.contains(&value) {
            if self.values.len() >= self.max_values {
                // Resolved per-call, not cached on `self`: `CardinalityWatcher::new`
                // runs before `metrics::set_global_recorder` in production
                // (`main.rs` constructs it, `start_metrics_server` installs the
                // recorder later, on the `server.run(...)` path) — a handle
                // captured at construction time binds to the no-op recorder
                // forever. This only runs on a cap miss, not the hot path.
                metrics::counter!("field_distinct_values_capped",
                    "stream" => self.stream.clone(),
                    "field" => self.field.clone()
                )
                .increment(1);
            } else {
                self.values.insert(value);
            }
        }
    }

    /// Publish the distinct count for the just-completed window, then
    /// clear. The gauge reports the MOST RECENTLY COMPLETED window, not
    /// since-boot: since-boot could only ratchet upward and would never
    /// show a source going silent, which is the failure an operator is
    /// trying to catch.
    //
    // ponytail: `len()` then `clear()` on a DashSet is not atomic — an
    // insert landing between the two calls can be reported a window late or
    // lost entirely. The default window is an hour; a handful of records at
    // the boundary is not worth a `Mutex<HashSet>` that would serialize the
    // hot `observe()` path for every caller to close.
    // `pub(crate)` (not private): `spawn_ticker` below is the production
    // caller, and the zeek-listener integration test that drives a window
    // boundary end to end (`zeek::listener::tests`) needs to call this
    // directly rather than waiting out a real interval.
    pub(crate) fn tick(&self) {
        // Resolved per-call, not cached on `self` — see the matching comment
        // in `observe`'s cap-miss branch. This only runs once per window, so
        // resolving the handle here instead of caching it costs nothing.
        metrics::gauge!("field_distinct_values",
            "stream" => self.stream.clone(),
            "field" => self.field.clone()
        )
        .set(self.values.len() as f64);
        self.values.clear();

        // Register the capped counter at its current value so the series
        // exists from the first window, even when the cap is never hit.
        // `increment(0)` records without changing it. Without this the
        // counter is absent from `/metrics` until the first cap miss, and a
        // freshly started process publishes neither series for a full window
        // (an hour, by default) — leaving an operator unable to tell "the
        // watch is running and healthy" from "I mistyped the config and
        // nothing is watching". That is the exact ambiguity this metric
        // exists to remove, and initialising counters to zero is the
        // conventional Prometheus answer to it.
        metrics::counter!("field_distinct_values_capped",
            "stream" => self.stream.clone(),
            "field" => self.field.clone()
        )
        .increment(0);

        // Req 5: records matched this watch's stream filter, but the
        // configured field was never found in any of them — almost always
        // a typo in `cardinality_watch_field`, not an outage (an outage
        // means NO records matched at all, which is silently and correctly
        // just a gauge of 0). One warning per affected window, not once per
        // record.
        let matched = self.matched_this_window.swap(false, Ordering::Relaxed);
        let field_seen = self.field_seen_this_window.swap(false, Ordering::Relaxed);
        if matched && !field_seen {
            warn!(
                field = %self.field,
                "cardinality watch: records matched this window but field '{}' was never \
                 found on any of them — check cardinality_watch_field for a typo",
                self.field
            );
        }
    }

    /// Spawn the window ticker: publishes and clears every `window_secs`,
    /// and once more on shutdown so a partial window is not lost.
    ///
    /// Unlike `Aggregator::spawn_emit_task` (`forwarding/aggregate/mod.rs`),
    /// this does NOT sleep and take a second pass after that final tick.
    /// `spawn_emit_task`'s second pass exists because Zeek/Suricata
    /// per-connection tasks are detached and keep handing `consume()`
    /// records to the aggregator for a couple of seconds after the
    /// shutdown signal — missing those would mean durable S3 rows silently
    /// never written, real data loss. Here a miss only means a gauge
    /// value on a `/metrics` endpoint that is itself about to stop being
    /// scraped, and this state resets on restart anyway (see the module
    /// doc). So: values observed after the shutdown signal fires may not
    /// reach the final gauge publish — accepted, not mirrored.
    pub fn spawn_ticker(
        self: Arc<Self>,
        window_secs: u64,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            // Belt-and-braces: `compile_watch` already rejects
            // `cardinality_window_secs == 0`, but `tokio::time::interval`
            // panics on a zero period, so clamp here too — matches
            // `Aggregator::spawn_emit_task`'s identical clamp.
            let mut ticker =
                tokio::time::interval(Duration::from_secs(window_secs).max(Duration::from_secs(1)));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            ticker.tick().await; // the first tick completes immediately

            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        self.tick();
                    }
                    res = shutdown.changed() => {
                        if res.is_err() || *shutdown.borrow() {
                            self.tick();
                            return;
                        }
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, MetricsConfig};
    use metrics::set_default_local_recorder;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};

    /// Minimal `AggFields` fake: one named field, one stream name, matching
    /// how the real `ZeekRecord` impl works but without needing JSON. `field`
    /// only resolves a lookup for the exact configured `field_name` — like
    /// the real `json_field` lookup, a watch for a DIFFERENT field name must
    /// see a miss, not whatever value this record happens to carry.
    struct FakeRecord {
        stream: &'static str,
        field_name: &'static str,
        value: Option<String>,
    }

    impl AggFields for FakeRecord {
        fn stream(&self) -> &str {
            self.stream
        }
        fn field(
            &self,
            name: &str,
        ) -> Option<crate::forwarding::aggregate::fields::FieldValue<'_>> {
            if name != self.field_name {
                return None;
            }
            self.value
                .as_deref()
                .map(|s| crate::forwarding::aggregate::fields::FieldValue::Str(s.into()))
        }
    }

    fn rec(stream: &'static str, value: &str) -> FakeRecord {
        FakeRecord {
            stream,
            field_name: "id.orig_h",
            value: Some(value.to_string()),
        }
    }

    fn watch(stream: &str, field: &str) -> CompiledWatch {
        CompiledWatch {
            stream: stream.to_string(),
            field: field.to_string(),
        }
    }

    // False positive, same as every other `into_hashmap()` use in this
    // codebase (e.g. `forwarding::buffered_writer`'s tests): `CompositeKey`'s
    // interior mutability is an `AtomicBool` clippy can't see is never
    // hashed.
    #[allow(clippy::mutable_key_type)]
    fn gauge_value(snapshotter: &metrics_util::debugging::Snapshotter, name: &str) -> f64 {
        let map = snapshotter.snapshot().into_hashmap();
        map.iter()
            .find_map(|(k, (_, _, v))| {
                if k.key().name() == name
                    && let DebugValue::Gauge(g) = v
                {
                    return Some(g.into_inner());
                }
                None
            })
            .unwrap_or(0.0)
    }

    #[allow(clippy::mutable_key_type)]
    fn counter_value(snapshotter: &metrics_util::debugging::Snapshotter, name: &str) -> u64 {
        let map = snapshotter.snapshot().into_hashmap();
        map.iter()
            .find_map(|(k, (_, _, v))| {
                if k.key().name() == name
                    && let DebugValue::Counter(c) = v
                {
                    return Some(*c);
                }
                None
            })
            .unwrap_or(0)
    }

    // -- compile_watch: config validation --

    fn config_with(field: Option<&str>, stream: Option<&str>) -> Config {
        Config {
            metrics: MetricsConfig {
                cardinality_watch_field: field.map(str::to_string),
                cardinality_watch_stream: stream.map(str::to_string),
                ..MetricsConfig::default()
            },
            ..Config::default()
        }
    }

    #[test]
    fn compile_watch_accepts_a_valid_watch() {
        let cfg = config_with(Some("id.orig_h"), Some("conn"));
        let watch = compile_watch(&cfg)
            .expect("valid watch compiles")
            .expect("field configured => Some");
        assert_eq!(watch.field, "id.orig_h");
        assert_eq!(watch.stream, "conn");
    }

    #[test]
    fn compile_watch_is_a_noop_when_unconfigured() {
        let cfg = Config::default();
        assert!(compile_watch(&cfg).expect("unset field compiles").is_none());
    }

    #[test]
    fn compile_watch_rejects_an_empty_field() {
        let cfg = config_with(Some(""), Some("conn"));
        let err = compile_watch(&cfg).unwrap_err().to_string();
        assert!(err.contains("cardinality_watch_field"), "got: {err}");
    }

    #[test]
    fn compile_watch_rejects_a_field_with_no_stream() {
        let cfg = config_with(Some("id.orig_h"), None);
        let err = compile_watch(&cfg).unwrap_err().to_string();
        assert!(
            err.contains("cardinality_watch_stream"),
            "error must name the missing key: {err}"
        );
    }

    #[test]
    fn compile_watch_rejects_a_field_with_an_empty_stream() {
        let cfg = config_with(Some("id.orig_h"), Some(""));
        let err = compile_watch(&cfg).unwrap_err().to_string();
        assert!(err.contains("cardinality_watch_stream"), "got: {err}");
    }

    #[test]
    fn compile_watch_rejects_a_zero_window() {
        let mut cfg = config_with(Some("id.orig_h"), Some("conn"));
        cfg.metrics.cardinality_window_secs = 0;
        let err = compile_watch(&cfg).unwrap_err().to_string();
        assert!(err.contains("window"), "got: {err}");
    }

    #[test]
    fn compile_watch_rejects_a_zero_cap() {
        let mut cfg = config_with(Some("id.orig_h"), Some("conn"));
        cfg.metrics.cardinality_max_values = 0;
        let err = compile_watch(&cfg).unwrap_err().to_string();
        assert!(err.contains("cardinality_max_values"), "got: {err}");
    }

    // -- CardinalityWatcher: the capped set --

    #[test]
    #[allow(clippy::mutable_key_type)]
    fn distinct_values_below_the_cap_are_all_counted() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let w = CardinalityWatcher::new(watch("conn", "id.orig_h"), 100);
        for i in 0..10 {
            w.observe(&rec("conn", &format!("10.0.0.{i}")));
        }
        w.tick();

        assert_eq!(gauge_value(&snapshotter, "field_distinct_values"), 10.0);
        assert_eq!(
            counter_value(&snapshotter, "field_distinct_values_capped"),
            0
        );
    }

    #[test]
    #[allow(clippy::mutable_key_type)]
    fn a_value_at_the_cap_is_still_counted_but_the_next_new_one_is_dropped() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let w = CardinalityWatcher::new(watch("conn", "id.orig_h"), 3);
        for i in 0..3 {
            w.observe(&rec("conn", &format!("10.0.0.{i}")));
        }
        // At the cap: one more never-before-seen value must be dropped and
        // counted as capped, not silently grown past the cap.
        w.observe(&rec("conn", "10.0.0.99"));
        w.tick();

        assert_eq!(
            gauge_value(&snapshotter, "field_distinct_values"),
            3.0,
            "the set must not grow past the cap"
        );
        assert_eq!(
            counter_value(&snapshotter, "field_distinct_values_capped"),
            1,
            "the overflowing value must increment the capped counter exactly once"
        );
    }

    #[test]
    #[allow(clippy::mutable_key_type)]
    fn re_observing_an_already_tracked_value_at_the_cap_is_not_capped() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let w = CardinalityWatcher::new(watch("conn", "id.orig_h"), 2);
        w.observe(&rec("conn", "a"));
        w.observe(&rec("conn", "b"));
        // Set is at the cap. Re-observing an existing value must not be
        // charged against the cap via the `contains`-then-insert
        // short-circuit.
        w.observe(&rec("conn", "a"));
        w.tick();

        assert_eq!(gauge_value(&snapshotter, "field_distinct_values"), 2.0);
        assert_eq!(
            counter_value(&snapshotter, "field_distinct_values_capped"),
            0
        );
    }

    /// Two distinct values sharing the same first `MAX_GROUP_VALUE_BYTES`
    /// bytes are truncated by `group_value_string` before this module ever
    /// sees them, so they collapse into ONE tracked entry — pins the
    /// undercount caveat documented in the module doc's "Reading the gauge"
    /// section as tested behaviour, not just a comment.
    #[test]
    #[allow(clippy::mutable_key_type)]
    fn values_sharing_a_256_byte_prefix_merge_into_one_distinct_value() {
        use crate::forwarding::aggregate::fields::MAX_GROUP_VALUE_BYTES;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let w = CardinalityWatcher::new(watch("conn", "id.orig_h"), 100);
        let prefix = "a".repeat(MAX_GROUP_VALUE_BYTES);
        w.observe(&rec("conn", &format!("{prefix}-tail-one")));
        w.observe(&rec("conn", &format!("{prefix}-tail-two")));
        w.tick();

        assert_eq!(
            gauge_value(&snapshotter, "field_distinct_values"),
            1.0,
            "two values differing only past the {MAX_GROUP_VALUE_BYTES}-byte truncation \
             boundary must merge into a single tracked value, not count as two"
        );
    }

    #[test]
    #[allow(clippy::mutable_key_type)]
    fn window_clear_resets_the_count() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let w = CardinalityWatcher::new(watch("conn", "id.orig_h"), 100);
        w.observe(&rec("conn", "a"));
        w.observe(&rec("conn", "b"));
        w.tick();
        assert_eq!(gauge_value(&snapshotter, "field_distinct_values"), 2.0);

        // Second window, no records at all: a silent source must show up as
        // the gauge dropping to 0, not staying stuck at 2.
        w.tick();
        assert_eq!(
            gauge_value(&snapshotter, "field_distinct_values"),
            0.0,
            "a window with no observations must report 0, not the previous window's count"
        );
    }

    #[test]
    #[allow(clippy::mutable_key_type)]
    fn an_absent_field_is_not_observed() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let w = CardinalityWatcher::new(watch("conn", "id.orig_h"), 100);
        w.observe(&FakeRecord {
            stream: "conn",
            field_name: "id.orig_h",
            value: None,
        });
        w.tick();

        assert_eq!(
            gauge_value(&snapshotter, "field_distinct_values"),
            0.0,
            "a record with the field absent must not create a phantom value"
        );
    }

    #[test]
    #[allow(clippy::mutable_key_type)]
    fn stream_filter_matches_and_excludes() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let w = CardinalityWatcher::new(watch("conn", "id.orig_h"), 100);
        w.observe(&rec("conn", "a"));
        // Different stream — must be excluded by the filter.
        w.observe(&rec("dns", "b"));
        w.tick();

        assert_eq!(
            gauge_value(&snapshotter, "field_distinct_values"),
            1.0,
            "a record from a non-matching stream must not be observed"
        );
    }

    // -- Req 5: mistyped field name vs. real outage --

    #[test]
    fn a_matched_stream_whose_field_is_always_absent_warns_once_per_window() {
        // Regression for a mistyped `cardinality_watch_field`: records ARE
        // flowing and DO match the stream filter, but the configured field
        // name never resolves — that must not look identical to "ingestion
        // is down" (gauge stuck at 0 either way). We can't assert on the
        // log line without the tracing test-capture harness wired up here,
        // so this test asserts the *distinguishing state* the warning is
        // computed from: `matched_this_window` was true while
        // `field_seen_this_window` stayed false, and both reset after
        // `tick()` so the next window starts clean.
        let w = CardinalityWatcher::new(watch("conn", "nonexistent_field"), 100);
        w.observe(&rec("conn", "a"));
        assert!(w.matched_this_window.load(Ordering::Relaxed));
        assert!(!w.field_seen_this_window.load(Ordering::Relaxed));
        w.tick();
        assert!(!w.matched_this_window.load(Ordering::Relaxed));
        assert!(!w.field_seen_this_window.load(Ordering::Relaxed));
    }

    #[test]
    fn a_correctly_configured_field_never_flags_the_typo_state() {
        let w = CardinalityWatcher::new(watch("conn", "id.orig_h"), 100);
        w.observe(&rec("conn", "a"));
        assert!(w.matched_this_window.load(Ordering::Relaxed));
        assert!(w.field_seen_this_window.load(Ordering::Relaxed));
    }

    #[test]
    fn no_matching_records_at_all_is_a_real_outage_not_a_typo() {
        // Nothing matched this window (e.g. the stream genuinely stopped
        // sending) — `matched_this_window` stays false, which must NOT
        // trigger the typo warning path (that's a silent, correct 0).
        let w = CardinalityWatcher::new(watch("conn", "id.orig_h"), 100);
        w.observe(&rec("dns", "a")); // does not match the "conn" filter
        assert!(!w.matched_this_window.load(Ordering::Relaxed));
    }

    // -- Hostile input: labels stay config-derived, memory stays bounded --

    /// In the spirit of `metric_event_type_bounds_the_label_to_the_known_set`:
    /// no matter how adversarial the observed *values* are, only ONE gauge
    /// series and ONE counter series ever exist — the wire never reaches a
    /// label — and the tracked-value set never exceeds the cap.
    #[test]
    #[allow(clippy::mutable_key_type)]
    fn hostile_values_bound_series_count_and_memory_not_labels() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let max_values = 50;
        let w = CardinalityWatcher::new(watch("conn", "id.orig_h"), max_values);

        // A 16 KiB string, a NUL-injected one, an empty-but-present one, and
        // thousands of unique values.
        w.observe(&rec("conn", &"x".repeat(16 * 1024)));
        w.observe(&rec("conn", "evil\0value"));
        w.observe(&rec("conn", ""));
        for i in 0..5000 {
            w.observe(&rec("conn", &format!("hostile-{i}")));
        }
        w.tick();

        let map = snapshotter.snapshot().into_hashmap();
        let gauge_series = map
            .keys()
            .filter(|k| k.key().name() == "field_distinct_values")
            .count();
        let counter_series = map
            .keys()
            .filter(|k| k.key().name() == "field_distinct_values_capped")
            .count();
        assert_eq!(
            gauge_series, 1,
            "thousands of distinct wire values must never mint more than one gauge series"
        );
        assert_eq!(
            counter_series, 1,
            "thousands of distinct wire values must never mint more than one counter series"
        );

        assert_eq!(
            gauge_value(&snapshotter, "field_distinct_values"),
            max_values as f64,
            "the tracked set must be capped, not grow to the ~5003 distinct values observed"
        );
        assert!(
            counter_value(&snapshotter, "field_distinct_values_capped") > 0,
            "values past the cap must have been counted as capped"
        );
    }
}
