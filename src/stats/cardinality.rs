//! Bounded distinct-value counter for operator-configured field watches
//! (`[[metrics.cardinality_watch]]`).
//!
//! Answers "is ingestion working?" by comparing a field's observed distinct
//! value count against a known-good number — e.g. "we have ~5000 hosts; is
//! `/metrics` reporting ~5000 distinct `computer` values?" Exposed as
//! `field_distinct_values{source,stream,field}` (gauge,
//! most-recently-completed window — see [`CardinalityWatcher::tick`]) and
//! `field_distinct_values_capped{source,stream,field}` (counter, fires each
//! time a never-before-seen value was discarded because the cap was already
//! reached).
//!
//! # Reading the gauge
//!
//! - zeek's `id.orig_h` is an IP, not a stable host identity: DHCP churn,
//!   NAT, and multi-homing move the distinct-IP count independently of
//!   ingestion health, and a sensor that sees inbound/external traffic
//!   counts external originators that are not org hosts at all. WEF's
//!   `computer` is a materially better signal for the same "do I see all my
//!   hosts" question — see the `AggFields for WindowsEvent` doc comment
//!   (`forwarding::aggregate::fields`) for the `source_host`-vs-`computer`
//!   distinction. Either way, treat the gauge as a proxy for host count,
//!   not an exact one.
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
//!   never reached by an IP- or hostname-shaped field.
//!
//! # Two sources, any number of watches
//!
//! ponytail: exactly two supported `source`s ("zeek", "wef") — one
//! `AggFields` impl each, wired at each source's own per-record observation
//! point (`zeek::listener` / `server::process_single_event`). Ceiling: a
//! third source needs that source's own `AggFields` impl (four more already
//! exist for aggregation in `forwarding::aggregate::fields` — suricata,
//! ipfix, sflow, syslog — but none is wired to this watcher yet), a new
//! arm in `compile_watches`'s source-name check, and one
//! `watcher.observe(&record)` call at that source's own observation point.
//! There is still no "every stream" mode: the stream a watch counts on is
//! always required (counting one field name across every stream at once
//! would conflate e.g. zeek's `conn` and `dns` streams' `id.orig_h` into
//! one number with no way to tell which stream contributed it).
//!
//! This used to be "exactly one watch, exactly one source (zeek)" — a
//! single flat `cardinality_watch_field`/`_stream` pair, with every source
//! but `"zeek"` rejected. That was deliberately cut back from an earlier
//! `Vec`-and-`source` draft during design review, on the grounds that a
//! second source wasn't wired yet and the flexibility was speculative. It's
//! no longer speculative now that WEF has its own `AggFields` impl and its
//! own genuinely better identity field (`computer`) — see
//! `config::CardinalityWatch`'s doc comment for the reasoning recorded
//! there.
//!
//! Mirrors `forwarding::aggregate`'s compile-then-consume shape:
//! [`compile_watches`] validates config at startup, fatal on a bad watch
//! (`aggregate::compile_rules` is the precedent — a watch that silently
//! never matches is worse than a startup error), and
//! [`CardinalityWatcher::observe`] is the per-record hot path, called from
//! `zeek::listener` alongside `zeek_records_received` and from
//! `server::process_single_event` alongside `throughput.record_event`.
//!
//! In-memory only, same as every other stat in this module — resets on
//! restart (see the doc comment on `SourceHourlyStats`).
//!
//! # Safety property
//!
//! `source`, `stream`, and `field` all come from CONFIG, never the wire. A
//! wire-derived label would let any client that can reach a listener mint
//! unbounded Prometheus series — the same reasoning behind
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

/// Sources a `[[metrics.cardinality_watch]]` entry may name.
const KNOWN_WATCH_SOURCES: [&str; 2] = ["zeek", "wef"];

/// A validated watch, ready to construct a `CardinalityWatcher` from.
#[derive(Debug)]
pub struct CompiledWatch {
    pub source: String,
    pub stream: String,
    pub field: String,
}

/// Validate `config.metrics.cardinality_watch` (and the shared
/// window/cap knobs every entry uses). Returns an empty `Vec` when
/// `cardinality_watch` is empty (feature off). Every failure is fatal at
/// startup, mirroring `aggregate::compile_rules`: a bad field name would
/// leave an operator staring at a gauge stuck at 0 with no error telling
/// them why, an unknown `source` would silently watch nothing, a zero
/// window would panic later when `tokio::time::interval` is constructed
/// (see `aggregate::compile_rules`'s `flush_interval_secs == 0` check for
/// the exact same trap), and a zero cap would pin every gauge at 0 forever,
/// which reads identically to "ingestion is dead" (see the
/// `cardinality_max_values == 0` check below, matching `compile_rules`'s
/// `max_groups == 0` check).
pub fn compile_watches(config: &Config) -> anyhow::Result<Vec<CompiledWatch>> {
    let cfg = &config.metrics;
    if cfg.cardinality_watch.is_empty() {
        return Ok(Vec::new());
    }
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

    let mut seen: Vec<(&str, &str, &str)> = Vec::with_capacity(cfg.cardinality_watch.len());
    let mut compiled = Vec::with_capacity(cfg.cardinality_watch.len());

    for watch in &cfg.cardinality_watch {
        if !KNOWN_WATCH_SOURCES.contains(&watch.source.as_str()) {
            anyhow::bail!(
                "[[metrics.cardinality_watch]] names unknown source '{}' (expected one of {:?})",
                watch.source,
                KNOWN_WATCH_SOURCES
            );
        }
        if watch.field.trim().is_empty() {
            anyhow::bail!("[[metrics.cardinality_watch]] has an empty `field`");
        }
        if watch.stream.trim().is_empty() {
            anyhow::bail!(
                "[[metrics.cardinality_watch]] has an empty `stream` (watching a field across \
                 every stream at once is not supported)"
            );
        }
        let key = (
            watch.source.as_str(),
            watch.stream.as_str(),
            watch.field.as_str(),
        );
        if seen.contains(&key) {
            anyhow::bail!(
                "[[metrics.cardinality_watch]] duplicate watch: source '{}', stream '{}', \
                 field '{}'",
                watch.source,
                watch.stream,
                watch.field
            );
        }
        seen.push(key);

        compiled.push(CompiledWatch {
            source: watch.source.clone(),
            stream: watch.stream.clone(),
            field: watch.field.clone(),
        });
    }

    Ok(compiled)
}

/// Live state for one configured watch.
pub struct CardinalityWatcher {
    source: String,
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
            source: watch.source,
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
                    "source" => self.source.clone(),
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
            "source" => self.source.clone(),
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
            "source" => self.source.clone(),
            "stream" => self.stream.clone(),
            "field" => self.field.clone()
        )
        .increment(0);

        // Req 5: records matched this watch's stream filter, but the
        // configured field was never found in any of them — almost always
        // a typo in the watch's `field`, not an outage (an outage means NO
        // records matched at all, which is silently and correctly just a
        // gauge of 0). One warning per affected window, not once per
        // record.
        let matched = self.matched_this_window.swap(false, Ordering::Relaxed);
        let field_seen = self.field_seen_this_window.swap(false, Ordering::Relaxed);
        if matched && !field_seen {
            warn!(
                source = %self.source,
                stream = %self.stream,
                field = %self.field,
                "cardinality watch: records matched this window but field '{}' was never \
                 found on any of them — check this [[metrics.cardinality_watch]] entry's \
                 `field` for a typo",
                self.field
            );
        }
    }
}

/// Spawn ONE shared window ticker for every configured watch: publishes and
/// clears each watcher every `window_secs`, and once more on shutdown so a
/// partial window is not lost. One task for the whole list, not one per
/// watch — `tick()` itself is cheap (one gauge set, one counter set, a
/// `DashSet::clear`), so looping over however many watches are configured
/// (0, 1, or several) inside a single tick is negligible next to spawning
/// and scheduling a separate task per watch. This loop runs once per
/// window, not per record — it is not on the `observe()` hot path.
///
/// Unlike `Aggregator::spawn_emit_task` (`forwarding/aggregate/mod.rs`),
/// this does NOT sleep and take a second pass after that final tick.
/// `spawn_emit_task`'s second pass exists because Zeek/Suricata
/// per-connection tasks are detached and keep handing `consume()` records
/// to the aggregator for a couple of seconds after the shutdown signal —
/// missing those would mean durable S3 rows silently never written, real
/// data loss. Here a miss only means a gauge value on a `/metrics` endpoint
/// that is itself about to stop being scraped, and this state resets on
/// restart anyway (see the module doc). So: values observed after the
/// shutdown signal fires may not reach the final gauge publish — accepted,
/// not mirrored.
pub fn spawn_ticker(
    watchers: Vec<Arc<CardinalityWatcher>>,
    window_secs: u64,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Belt-and-braces: `compile_watches` already rejects
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
                    for w in &watchers {
                        w.tick();
                    }
                }
                res = shutdown.changed() => {
                    if res.is_err() || *shutdown.borrow() {
                        for w in &watchers {
                            w.tick();
                        }
                        return;
                    }
                }
            }
        }
    })
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
            source: "zeek".to_string(),
            stream: stream.to_string(),
            field: field.to_string(),
        }
    }

    /// Gauge value for one specific `stream` label, so a test with more than
    /// one watch can tell the two series apart — `gauge_value` matches on
    /// metric name alone and would return whichever series it happened to
    /// find first.
    #[allow(clippy::mutable_key_type)]
    fn gauge_value_for_stream(
        snapshotter: &metrics_util::debugging::Snapshotter,
        name: &str,
        stream: &str,
    ) -> f64 {
        let map = snapshotter.snapshot().into_hashmap();
        map.iter()
            .find_map(|(k, (_, _, v))| {
                let matches_stream = k
                    .key()
                    .labels()
                    .any(|l| l.key() == "stream" && l.value() == stream);
                if k.key().name() == name
                    && matches_stream
                    && let DebugValue::Gauge(g) = v
                {
                    return Some(g.into_inner());
                }
                None
            })
            .unwrap_or(0.0)
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

    // -- compile_watches: config validation --

    use crate::config::CardinalityWatch;

    fn raw_watch(source: &str, stream: &str, field: &str) -> CardinalityWatch {
        CardinalityWatch {
            source: source.to_string(),
            stream: stream.to_string(),
            field: field.to_string(),
        }
    }

    fn config_with(watches: Vec<CardinalityWatch>) -> Config {
        Config {
            metrics: MetricsConfig {
                cardinality_watch: watches,
                ..MetricsConfig::default()
            },
            ..Config::default()
        }
    }

    #[test]
    fn compile_watches_accepts_a_valid_zeek_watch() {
        let cfg = config_with(vec![raw_watch("zeek", "conn", "id.orig_h")]);
        let watches = compile_watches(&cfg).expect("valid watch compiles");
        assert_eq!(watches.len(), 1);
        assert_eq!(watches[0].source, "zeek");
        assert_eq!(watches[0].stream, "conn");
        assert_eq!(watches[0].field, "id.orig_h");
    }

    #[test]
    fn compile_watches_accepts_a_valid_wef_watch() {
        let cfg = config_with(vec![raw_watch("wef", "Security", "computer")]);
        let watches = compile_watches(&cfg).expect("valid watch compiles");
        assert_eq!(watches.len(), 1);
        assert_eq!(watches[0].source, "wef");
        assert_eq!(watches[0].stream, "Security");
        assert_eq!(watches[0].field, "computer");
    }

    #[test]
    fn compile_watches_is_a_noop_when_unconfigured() {
        let cfg = Config::default();
        assert!(
            compile_watches(&cfg)
                .expect("empty list compiles")
                .is_empty()
        );
    }

    #[test]
    fn compile_watches_accepts_a_zeek_watch_and_a_wef_watch_together() {
        let cfg = config_with(vec![
            raw_watch("zeek", "conn", "id.orig_h"),
            raw_watch("wef", "Security", "computer"),
        ]);
        let watches = compile_watches(&cfg).expect("both watches compile");
        assert_eq!(watches.len(), 2);
        assert!(watches.iter().any(|w| w.source == "zeek"));
        assert!(watches.iter().any(|w| w.source == "wef"));
    }

    #[test]
    fn compile_watches_rejects_an_unknown_source() {
        let cfg = config_with(vec![raw_watch("suricata", "dns", "query")]);
        let err = compile_watches(&cfg).unwrap_err().to_string();
        assert!(
            err.contains("suricata"),
            "error must name the bad source: {err}"
        );
        assert!(
            err.contains("zeek") && err.contains("wef"),
            "error must name both valid sources: {err}"
        );
    }

    #[test]
    fn compile_watches_rejects_an_empty_field() {
        let cfg = config_with(vec![raw_watch("zeek", "conn", "")]);
        let err = compile_watches(&cfg).unwrap_err().to_string();
        assert!(err.contains("field"), "got: {err}");
    }

    #[test]
    fn compile_watches_rejects_an_empty_stream() {
        let cfg = config_with(vec![raw_watch("zeek", "", "id.orig_h")]);
        let err = compile_watches(&cfg).unwrap_err().to_string();
        assert!(err.contains("stream"), "got: {err}");
    }

    #[test]
    fn compile_watches_rejects_a_duplicate_source_stream_field_triple() {
        let cfg = config_with(vec![
            raw_watch("zeek", "conn", "id.orig_h"),
            raw_watch("zeek", "conn", "id.orig_h"),
        ]);
        let err = compile_watches(&cfg).unwrap_err().to_string();
        assert!(err.contains("duplicate"), "got: {err}");
        assert!(err.contains("zeek") && err.contains("conn") && err.contains("id.orig_h"));
    }

    #[test]
    fn compile_watches_allows_the_same_stream_field_on_different_sources() {
        // Same stream/field text, different source — not a duplicate: zeek
        // and wef are independent series (source is part of the key).
        let cfg = config_with(vec![
            raw_watch("zeek", "Security", "computer"),
            raw_watch("wef", "Security", "computer"),
        ]);
        let watches = compile_watches(&cfg).expect("not a duplicate across sources");
        assert_eq!(watches.len(), 2);
    }

    #[test]
    fn compile_watches_rejects_a_zero_window() {
        let mut cfg = config_with(vec![raw_watch("zeek", "conn", "id.orig_h")]);
        cfg.metrics.cardinality_window_secs = 0;
        let err = compile_watches(&cfg).unwrap_err().to_string();
        assert!(err.contains("window"), "got: {err}");
    }

    #[test]
    fn compile_watches_rejects_a_zero_cap() {
        let mut cfg = config_with(vec![raw_watch("zeek", "conn", "id.orig_h")]);
        cfg.metrics.cardinality_max_values = 0;
        let err = compile_watches(&cfg).unwrap_err().to_string();
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

    /// The shared ticker drives a `Vec` of watchers, so each one's set and
    /// window accounting must stay entirely its own. Every other test in
    /// this module configures exactly one watch, which would leave the
    /// multi-watcher path — the whole point of the shared-ticker shape —
    /// with no regression net: a future change that hoisted per-watch state
    /// onto something shared would pass the rest of this suite untouched.
    #[test]
    #[allow(clippy::mutable_key_type)]
    fn two_watchers_on_one_source_keep_independent_counts() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let conn = CardinalityWatcher::new(watch("conn", "id.orig_h"), 100);
        let dns = CardinalityWatcher::new(watch("dns", "id.orig_h"), 100);

        // Every record is offered to BOTH watchers, exactly as the
        // observation sites do — each must take only its own stream.
        for r in [
            rec("conn", "10.0.0.1"),
            rec("conn", "10.0.0.2"),
            rec("conn", "10.0.0.1"), // repeat: must not double-count
            rec("dns", "10.0.0.7"),
            rec("dns", "10.0.0.8"),
            rec("dns", "10.0.0.9"),
            rec("ssl", "10.0.0.99"), // matches neither
        ] {
            conn.observe(&r);
            dns.observe(&r);
        }

        // Tick both in one pass, the way `spawn_ticker`'s loop does.
        conn.tick();
        dns.tick();

        assert_eq!(
            gauge_value_for_stream(&snapshotter, "field_distinct_values", "conn"),
            2.0,
            "the conn watch must count only its own stream's distinct values"
        );
        assert_eq!(
            gauge_value_for_stream(&snapshotter, "field_distinct_values", "dns"),
            3.0,
            "the dns watch must count only its own stream's distinct values"
        );

        // Clearing is per-watcher too: ticking one must not reset the other.
        conn.observe(&rec("conn", "10.0.0.5"));
        conn.tick();
        assert_eq!(
            gauge_value_for_stream(&snapshotter, "field_distinct_values", "conn"),
            1.0,
            "conn's second window sees one value"
        );
        assert_eq!(
            gauge_value_for_stream(&snapshotter, "field_distinct_values", "dns"),
            3.0,
            "dns's gauge must still report its own last completed window, \
             untouched by conn's tick"
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
