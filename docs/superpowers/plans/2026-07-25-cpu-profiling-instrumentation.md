# CPU Profiling Instrumentation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a feature-gated, env-var-triggered `pprof-rs` sampling profiler to `logthing` that produces a self-validating flamegraph, then use it to determine where the measured ~94.6µs of CPU per received syslog datagram actually goes.

**Architecture:** A new `src/profiling` module. Config parsing, counter parsing and metadata types are **always compiled** (so the default test suite covers them); only the sampler itself sits behind an off-by-default `pprof` cargo feature. `src/main.rs` gets exactly one unconditional call site. The sampler writes three artifacts, one of which (`profile-metadata.json`) records whether the sampling window actually overlapped real load — so a mistimed run fails loudly instead of silently producing an idle-thread flamegraph.

**Tech Stack:** Rust 2024, tokio, `pprof` 0.14 (features `flamegraph` + `protobuf-codec`), `serde`/`serde_json` (already dependencies), `tracing` (already a dependency), criterion (not used here).

**Full design rationale:** `docs/superpowers/specs/2026-07-25-cpu-profiling-instrumentation-design.md` — read it before starting. Its decisions are not re-litigated here.

## Global Constraints

- Branch: `perf/cpu-profiling-instrumentation` (already exists, branched from `master` `55b88b9`; spec committed at `aebf8a1`). **Never commit to `master`.**
- Build environment: this machine has a `zig-cc` shim on `PATH` that breaks C dependencies. **Always** `export CC=/usr/bin/gcc CXX=/usr/bin/g++` before any cargo command.
- Style (`AGENTS.md`): Rust 2024, 100-char lines, 4-space indent, no tabs, trailing newline, import order std → external → internal, `///` docs on public items, `#[derive(Debug)]` on structs/enums.
- `cargo fmt` and `cargo clippy -- -D warnings` must be clean before every commit.
- The `pprof` dependency must be `optional = true` and **must not** appear in `default` features — `binaries.yml` cross-compiles static musl with default features only, and this repo has a documented history of C dependencies breaking those builds.
- Do **not** add per-record work to any ingest hot path. Nothing in this plan touches `src/syslog/`, `src/forwarding/`, or any listener.
- Commit messages use conventional-commit prefixes (`feat:`, `test:`, `ci:`, `docs:`, `chore:`).

---

## File Structure

| File | Responsibility |
|---|---|
| `src/profiling/mod.rs` (create) | Config parsing, counter parsing, metadata, `maybe_start` entry point, feature-gated sampler |
| `src/lib.rs` (modify) | Register `pub mod profiling;` |
| `src/main.rs` (modify) | One unconditional `profiling::maybe_start(...)` call |
| `src/server/mod.rs` (modify, ~line 2556) | Publish the Prometheus handle via a `OnceLock` so the activity probe can read it |
| `Cargo.toml` (modify) | `pprof` optional dependency + `pprof` feature |
| `tests/profiling_integration.rs` (create) | Cross-thread sampling integration test, `#[cfg(feature = "pprof")]` |
| `.github/workflows/rust.yml` (modify) | `build-pprof` job mirroring `build-kerberos` |
| `scripts/profile-syslog-udp.sh` (create) | E2E: server + loadgen + metadata assertions |
| `scripts/profile-server.sh`, `scripts/run-flamegraph.sh` (delete) | Dead — hard-depend on unavailable `perf`/`cargo flamegraph` |
| `docs/performance/2026-07-25-syslog-udp-cpu-profile.md` (create) | The finding — where the ~94.6µs goes |

---

## Task 1: Config, counter parsing, and metadata (no feature gate)

**Files:**
- Create: `src/profiling/mod.rs`
- Modify: `src/lib.rs` (add module registration)

**Interfaces:**
- Consumes: nothing.
- Produces: `ProfileConfig { duration_secs: u64, delay_secs: u64, frequency_hz: i32, output_dir: PathBuf }` with `ProfileConfig::from_env() -> Option<ProfileConfig>` and `pub(crate) ProfileConfig::from_vars(get: impl Fn(&str) -> Option<String>) -> Option<ProfileConfig>`; `parse_counter(rendered: &str, name: &str) -> Option<u64>`; `ProfileMetadata::new(cfg: &ProfileConfig, sample_count: usize, before: Option<u64>, after: Option<u64>) -> ProfileMetadata`; `is_representative(sample_count: usize, activity_delta: Option<u64>) -> bool`; `MIN_REPRESENTATIVE_SAMPLES: usize`.

- [ ] **Step 1: Write the failing tests**

Create `src/profiling/mod.rs` containing ONLY this test module for now (the implementation comes in Step 3):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn vars(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        move |k: &str| map.get(k).cloned()
    }

    #[test]
    fn from_vars_returns_none_when_secs_absent() {
        assert_eq!(ProfileConfig::from_vars(vars(&[])), None);
    }

    #[test]
    fn from_vars_returns_none_when_secs_zero() {
        assert_eq!(
            ProfileConfig::from_vars(vars(&[("LOGTHING_PROFILE_SECS", "0")])),
            None
        );
    }

    #[test]
    fn from_vars_returns_none_when_secs_not_numeric() {
        assert_eq!(
            ProfileConfig::from_vars(vars(&[("LOGTHING_PROFILE_SECS", "abc")])),
            None
        );
    }

    #[test]
    fn from_vars_applies_documented_defaults() {
        let cfg = ProfileConfig::from_vars(vars(&[("LOGTHING_PROFILE_SECS", "30")])).unwrap();
        assert_eq!(cfg.duration_secs, 30);
        assert_eq!(cfg.delay_secs, 0);
        assert_eq!(cfg.frequency_hz, 99);
        assert_eq!(cfg.output_dir, PathBuf::from("./profiling-results"));
    }

    #[test]
    fn from_vars_reads_all_overrides() {
        let cfg = ProfileConfig::from_vars(vars(&[
            ("LOGTHING_PROFILE_SECS", "10"),
            ("LOGTHING_PROFILE_DELAY_SECS", "5"),
            ("LOGTHING_PROFILE_HZ", "250"),
            ("LOGTHING_PROFILE_DIR", "/tmp/prof"),
        ]))
        .unwrap();
        assert_eq!(cfg.duration_secs, 10);
        assert_eq!(cfg.delay_secs, 5);
        assert_eq!(cfg.frequency_hz, 250);
        assert_eq!(cfg.output_dir, PathBuf::from("/tmp/prof"));
    }

    #[test]
    fn from_vars_falls_back_on_out_of_range_hz() {
        let cfg = ProfileConfig::from_vars(vars(&[
            ("LOGTHING_PROFILE_SECS", "10"),
            ("LOGTHING_PROFILE_HZ", "0"),
        ]))
        .unwrap();
        assert_eq!(cfg.frequency_hz, 99);

        let cfg = ProfileConfig::from_vars(vars(&[
            ("LOGTHING_PROFILE_SECS", "10"),
            ("LOGTHING_PROFILE_HZ", "99999"),
        ]))
        .unwrap();
        assert_eq!(cfg.frequency_hz, 99);
    }

    #[test]
    fn from_vars_falls_back_on_non_numeric_delay() {
        let cfg = ProfileConfig::from_vars(vars(&[
            ("LOGTHING_PROFILE_SECS", "10"),
            ("LOGTHING_PROFILE_DELAY_SECS", "later"),
        ]))
        .unwrap();
        assert_eq!(cfg.delay_secs, 0);
    }

    #[test]
    fn parse_counter_sums_all_label_sets() {
        let rendered = "\
# HELP syslog_messages_received count
# TYPE syslog_messages_received counter
syslog_messages_received{proto=\"udp\"} 100
syslog_messages_received{proto=\"tcp\"} 23
other_metric 999
";
        assert_eq!(parse_counter(rendered, "syslog_messages_received"), Some(123));
    }

    #[test]
    fn parse_counter_reads_unlabelled_metric() {
        assert_eq!(parse_counter("syslog_messages_received 42", "syslog_messages_received"), Some(42));
    }

    #[test]
    fn parse_counter_returns_none_when_absent() {
        assert_eq!(parse_counter("other_metric 1", "syslog_messages_received"), None);
    }

    #[test]
    fn parse_counter_ignores_prefix_collisions() {
        assert_eq!(parse_counter("syslog_messages_received_total 5", "syslog_messages_received"), None);
    }

    #[test]
    fn representative_requires_enough_samples() {
        assert!(!is_representative(MIN_REPRESENTATIVE_SAMPLES - 1, Some(1000)));
        assert!(is_representative(MIN_REPRESENTATIVE_SAMPLES, Some(1000)));
    }

    #[test]
    fn representative_is_false_when_counter_did_not_move() {
        assert!(!is_representative(10_000, Some(0)));
    }

    #[test]
    fn representative_tolerates_absent_probe() {
        assert!(is_representative(10_000, None));
    }

    #[test]
    fn metadata_computes_delta_and_flag() {
        let cfg = ProfileConfig {
            duration_secs: 30,
            delay_secs: 2,
            frequency_hz: 99,
            output_dir: PathBuf::from("/tmp"),
        };
        let meta = ProfileMetadata::new(&cfg, 5_000, Some(10), Some(1_010));
        assert_eq!(meta.activity_delta, Some(1_000));
        assert!(meta.representative);
        assert_eq!(meta.sample_count, 5_000);
        assert_eq!(meta.frequency_hz, 99);
    }

    #[test]
    fn metadata_marks_unrepresentative_when_counter_flat() {
        let cfg = ProfileConfig {
            duration_secs: 30,
            delay_secs: 0,
            frequency_hz: 99,
            output_dir: PathBuf::from("/tmp"),
        };
        let meta = ProfileMetadata::new(&cfg, 5_000, Some(7), Some(7));
        assert_eq!(meta.activity_delta, Some(0));
        assert!(!meta.representative);
    }
}
```

Add to `src/lib.rs`, keeping the module list alphabetical (between `protocol` and `server`):

```rust
pub mod profiling;
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
export CC=/usr/bin/gcc CXX=/usr/bin/g++
cargo test --lib profiling:: 2>&1 | tail -20
```

Expected: FAIL to compile — `cannot find type ProfileConfig in this scope` and similar for `parse_counter`, `ProfileMetadata`, `is_representative`, `MIN_REPRESENTATIVE_SAMPLES`.

- [ ] **Step 3: Write the implementation**

Prepend to `src/profiling/mod.rs`, above the `#[cfg(test)] mod tests` block:

```rust
//! CPU profiling instrumentation.
//!
//! Configuration parsing, Prometheus counter parsing and metadata types are
//! always compiled so the default test suite covers them. Only the sampler
//! itself sits behind the off-by-default `pprof` cargo feature — see
//! `docs/superpowers/specs/2026-07-25-cpu-profiling-instrumentation-design.md`.

use std::path::PathBuf;
use std::str::FromStr;

use serde::Serialize;

/// Minimum number of samples before a profile is considered representative of
/// real load rather than of an idle process.
pub const MIN_REPRESENTATIVE_SAMPLES: usize = 100;

/// Default sampling frequency. Prime, so it does not fall into lockstep with
/// the buffered writer's one-second flush ticker.
const DEFAULT_FREQUENCY_HZ: i32 = 99;

/// Default output directory for profiling artifacts.
const DEFAULT_OUTPUT_DIR: &str = "./profiling-results";

/// Metric whose movement proves the sampling window overlapped real ingest.
pub const ACTIVITY_METRIC: &str = "syslog_messages_received";

/// A probe returning some monotonically increasing measure of ingest activity,
/// used only to decide whether a profile is representative. Returns `None`
/// when the measure is unavailable (for example, metrics are disabled).
pub type ActivityProbe = Box<dyn Fn() -> Option<u64> + Send + Sync>;

/// Profiling configuration, parsed from environment variables.
///
/// Environment variables are used rather than the config file deliberately:
/// `logthing.admin.toml` is git-tracked and loaded at higher precedence than
/// `logthing.toml`, which has previously overridden settings during a
/// benchmark run without anyone noticing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileConfig {
    /// How long to sample for, in seconds. Never zero.
    pub duration_secs: u64,
    /// How long to wait after startup before sampling begins.
    pub delay_secs: u64,
    /// Sampling frequency in Hz, in the range `1..=1000`.
    pub frequency_hz: i32,
    /// Directory the artifacts are written to.
    pub output_dir: PathBuf,
}

impl ProfileConfig {
    /// Read configuration from the process environment. Returns `None` when
    /// profiling is disabled.
    pub fn from_env() -> Option<Self> {
        Self::from_vars(|key| std::env::var(key).ok())
    }

    /// Environment-agnostic form of [`ProfileConfig::from_env`], so the
    /// parsing rules can be tested without mutating process state.
    pub(crate) fn from_vars(get: impl Fn(&str) -> Option<String>) -> Option<Self> {
        let raw = get("LOGTHING_PROFILE_SECS")?;
        let duration_secs = match raw.trim().parse::<u64>() {
            Ok(0) => return None,
            Ok(secs) => secs,
            Err(_) => {
                tracing::warn!(
                    value = %raw,
                    "LOGTHING_PROFILE_SECS is not a valid number of seconds; profiling disabled"
                );
                return None;
            }
        };

        let delay_secs = parse_or_default(&get, "LOGTHING_PROFILE_DELAY_SECS", 0u64);

        let requested_hz = parse_or_default(&get, "LOGTHING_PROFILE_HZ", DEFAULT_FREQUENCY_HZ);
        let frequency_hz = if (1..=1000).contains(&requested_hz) {
            requested_hz
        } else {
            tracing::warn!(
                value = requested_hz,
                default = DEFAULT_FREQUENCY_HZ,
                "LOGTHING_PROFILE_HZ outside 1..=1000; using default"
            );
            DEFAULT_FREQUENCY_HZ
        };

        let output_dir = get("LOGTHING_PROFILE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_OUTPUT_DIR));

        Some(Self {
            duration_secs,
            delay_secs,
            frequency_hz,
            output_dir,
        })
    }
}

/// Parse an optional environment variable, warning and falling back to
/// `default` when it is present but unparseable.
fn parse_or_default<T>(get: &impl Fn(&str) -> Option<String>, key: &str, default: T) -> T
where
    T: FromStr + std::fmt::Display + Copy,
{
    match get(key) {
        None => default,
        Some(raw) => raw.trim().parse::<T>().unwrap_or_else(|_| {
            tracing::warn!(key, value = %raw, %default, "invalid value; using default");
            default
        }),
    }
}

/// Sum every label-set of a counter in rendered Prometheus exposition text.
///
/// Returns `None` when the metric does not appear at all, which is how an
/// absent or not-yet-installed recorder is distinguished from a genuine zero.
pub fn parse_counter(rendered: &str, name: &str) -> Option<u64> {
    let mut total: u64 = 0;
    let mut found = false;

    for line in rendered.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.rsplit_once(' ') else {
            continue;
        };
        let metric = key.split('{').next().unwrap_or(key);
        if metric != name {
            continue;
        }
        if let Ok(parsed) = value.trim().parse::<f64>() {
            total = total.saturating_add(parsed as u64);
            found = true;
        }
    }

    found.then_some(total)
}

/// Decide whether a completed profile actually observed load.
///
/// A profile is unrepresentative when too few samples were collected, or when
/// the activity probe proves no records arrived during the window — the two
/// ways a mistimed run can produce well-formed but useless artifacts.
pub fn is_representative(sample_count: usize, activity_delta: Option<u64>) -> bool {
    if sample_count < MIN_REPRESENTATIVE_SAMPLES {
        return false;
    }
    !matches!(activity_delta, Some(0))
}

/// Machine-readable record of what a profiling run actually captured.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProfileMetadata {
    /// Total samples across all stacks.
    pub sample_count: usize,
    /// Sampling frequency actually used.
    pub frequency_hz: i32,
    /// Configured sampling duration.
    pub duration_secs: u64,
    /// Configured startup delay.
    pub delay_secs: u64,
    /// Activity counter before the window, if the probe was available.
    pub activity_before: Option<u64>,
    /// Activity counter after the window, if the probe was available.
    pub activity_after: Option<u64>,
    /// Records observed during the window, if the probe was available.
    pub activity_delta: Option<u64>,
    /// Whether these artifacts can be trusted to describe loaded behaviour.
    pub representative: bool,
}

impl ProfileMetadata {
    /// Build metadata from a completed run.
    pub fn new(
        cfg: &ProfileConfig,
        sample_count: usize,
        activity_before: Option<u64>,
        activity_after: Option<u64>,
    ) -> Self {
        let activity_delta = match (activity_before, activity_after) {
            (Some(before), Some(after)) => Some(after.saturating_sub(before)),
            _ => None,
        };
        Self {
            sample_count,
            frequency_hz: cfg.frequency_hz,
            duration_secs: cfg.duration_secs,
            delay_secs: cfg.delay_secs,
            activity_before,
            activity_after,
            activity_delta,
            representative: is_representative(sample_count, activity_delta),
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
export CC=/usr/bin/gcc CXX=/usr/bin/g++
cargo test --lib profiling:: 2>&1 | tail -20
cargo fmt && cargo clippy -- -D warnings
```

Expected: all 15 tests pass; fmt and clippy clean.

- [ ] **Step 5: Commit**

```bash
git add src/profiling/mod.rs src/lib.rs
git commit -m "feat(profiling): add config, counter and metadata types (unwired)"
```

---

## Task 2: No-op stub, `maybe_start` entry point, and wiring

**Files:**
- Modify: `src/profiling/mod.rs`
- Modify: `src/server/mod.rs` (add `METRICS_HANDLE`, ~line 2554-2558)
- Modify: `src/main.rs` (one call site in `async_main`)

**Interfaces:**
- Consumes: `ProfileConfig::from_env`, `ActivityProbe`, `parse_counter`, `ACTIVITY_METRIC` from Task 1.
- Produces: `pub fn maybe_start(probe: Option<ActivityProbe>)`; `pub static logthing::server::METRICS_HANDLE: OnceLock<PrometheusHandle>`.

- [ ] **Step 1: Write the failing test**

Append to the `tests` module in `src/profiling/mod.rs`:

```rust
    #[test]
    fn maybe_start_is_a_noop_when_disabled() {
        // No LOGTHING_PROFILE_SECS in the test environment: must not panic,
        // must not spawn, must not require a tokio runtime.
        maybe_start(None);
    }
```

- [ ] **Step 2: Run test to verify it fails**

```bash
export CC=/usr/bin/gcc CXX=/usr/bin/g++
cargo test --lib profiling::tests::maybe_start_is_a_noop_when_disabled 2>&1 | tail -10
```

Expected: FAIL to compile — `cannot find function maybe_start in this scope`.

- [ ] **Step 3: Write the implementation**

Add to `src/profiling/mod.rs`, after `impl ProfileMetadata` and before the test module:

```rust
/// Start CPU profiling if `LOGTHING_PROFILE_SECS` requests it.
///
/// Safe and cheap to call unconditionally: when profiling is not requested it
/// returns immediately, and when the binary was built without the `pprof`
/// feature it warns rather than silently doing nothing.
pub fn maybe_start(probe: Option<ActivityProbe>) {
    let Some(cfg) = ProfileConfig::from_env() else {
        return;
    };

    #[cfg(feature = "pprof")]
    {
        sampler::spawn(cfg, probe);
    }

    #[cfg(not(feature = "pprof"))]
    {
        let _ = probe;
        tracing::warn!(
            duration_secs = cfg.duration_secs,
            "LOGTHING_PROFILE_SECS is set but this binary was built without the `pprof` \
             feature, so no profile will be produced. Rebuild with `--features pprof`."
        );
    }
}
```

Add to `src/server/mod.rs`. Immediately after the `use` block at the top of the file, add:

```rust
/// Handle onto the installed Prometheus recorder, published so profiling can
/// read counters to verify a sampling window overlapped real traffic.
/// `OnceLock` because the recorder is installed exactly once, at startup.
pub static METRICS_HANDLE: std::sync::OnceLock<metrics_exporter_prometheus::PrometheusHandle> =
    std::sync::OnceLock::new();
```

Then in `start_metrics_server`, immediately after the existing `let handle = recorder.handle();` line (currently `src/server/mod.rs:2556`), add:

```rust
    let _ = METRICS_HANDLE.set(handle.clone());
```

Add to `src/main.rs` in `async_main()`, immediately after the `info!("Configuration loaded successfully");` line:

```rust
    // Start CPU profiling if requested. No-op unless LOGTHING_PROFILE_SECS is
    // set; warns if set on a binary built without the `pprof` feature.
    logthing::profiling::maybe_start(Some(Box::new(|| {
        let handle = logthing::server::METRICS_HANDLE.get()?;
        logthing::profiling::parse_counter(
            &handle.render(),
            logthing::profiling::ACTIVITY_METRIC,
        )
    })));
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
export CC=/usr/bin/gcc CXX=/usr/bin/g++
cargo test --lib profiling:: 2>&1 | tail -10
cargo build 2>&1 | tail -5
cargo fmt && cargo clippy -- -D warnings
```

Expected: all profiling tests pass; the default (no-feature) build succeeds; fmt and clippy clean.

- [ ] **Step 5: Verify the loud-failure path by hand**

```bash
export CC=/usr/bin/gcc CXX=/usr/bin/g++
LOGTHING_PROFILE_SECS=5 timeout 5 cargo run 2>&1 | grep -i "built without the .pprof. feature" || echo "WARN NOT EMITTED — investigate"
```

Expected: the warning line appears. (The server will be killed by `timeout`; that is fine.)

- [ ] **Step 6: Commit**

```bash
git add src/profiling/mod.rs src/server/mod.rs src/main.rs
git commit -m "feat(profiling): wire maybe_start with activity probe and no-op stub"
```

---

## Task 3: The sampler behind the `pprof` feature

**Files:**
- Modify: `Cargo.toml`
- Modify: `src/profiling/mod.rs`

**Interfaces:**
- Consumes: `ProfileConfig`, `ProfileMetadata`, `ActivityProbe` from Task 1; `maybe_start`'s `#[cfg(feature = "pprof")]` branch from Task 2.
- Produces: `mod sampler` with `pub(super) fn spawn(cfg: ProfileConfig, probe: Option<ActivityProbe>)`, writing `flamegraph.svg`, `profile.pb`, `profile-metadata.json`.

- [ ] **Step 1: Add the dependency and feature**

In `Cargo.toml`, add to `[features]`:

```toml
pprof = ["dep:pprof"]
```

and to `[dependencies]`:

```toml
# CPU sampling profiler. Optional and excluded from `default` on purpose:
# binaries.yml cross-compiles static musl with default features only, and this
# repo has a history of C dependencies breaking those builds.
# `protobuf-codec` (pure-Rust rust-protobuf 2.x) rather than `prost-codec`:
# pprof 0.14 pins prost ^0.12 while this crate resolves prost 0.14, so
# prost-codec would add a second, incompatible prost rather than reuse ours.
pprof = { version = "0.14", default-features = false, features = [
    "flamegraph",
    "protobuf-codec",
], optional = true }
```

- [ ] **Step 2: Verify the dependency resolves and the encode path compiles**

```bash
export CC=/usr/bin/gcc CXX=/usr/bin/g++
cargo check --features pprof 2>&1 | tail -20
cargo tree -i prost 2>/dev/null | head -5
```

Expected: `cargo check` succeeds. `cargo tree -i prost` must show only **one** prost (0.14.x, via `opentelemetry-proto`) — if a second prost 0.12 appears, the wrong codec feature was enabled; fix it before continuing.

- [ ] **Step 3: Write the sampler**

Add to `src/profiling/mod.rs`, after `maybe_start` and before the test module:

```rust
#[cfg(feature = "pprof")]
mod sampler {
    use std::io::Write;
    use std::time::Duration;

    use super::{ActivityProbe, ProfileConfig, ProfileMetadata};

    /// Spawn the background sampling task. Never blocks startup; every failure
    /// is logged and swallowed, because a profiler must not be able to take
    /// down the daemon it is observing.
    pub(super) fn spawn(cfg: ProfileConfig, probe: Option<ActivityProbe>) {
        tokio::spawn(async move {
            if cfg.delay_secs > 0 {
                tokio::time::sleep(Duration::from_secs(cfg.delay_secs)).await;
            }

            let activity_before = probe.as_ref().and_then(|p| p());

            let guard = match pprof::ProfilerGuardBuilder::default()
                .frequency(cfg.frequency_hz)
                .build()
            {
                Ok(guard) => guard,
                Err(e) => {
                    tracing::error!("failed to start CPU profiler: {e}");
                    return;
                }
            };

            tracing::info!(
                duration_secs = cfg.duration_secs,
                frequency_hz = cfg.frequency_hz,
                "CPU profiling started"
            );
            tokio::time::sleep(Duration::from_secs(cfg.duration_secs)).await;

            let report = match guard.report().build() {
                Ok(report) => report,
                Err(e) => {
                    tracing::error!("failed to build CPU profile report: {e}");
                    return;
                }
            };
            drop(guard);

            let activity_after = probe.as_ref().and_then(|p| p());
            let sample_count: usize = report.data.values().map(|count| *count as usize).sum();
            let metadata =
                ProfileMetadata::new(&cfg, sample_count, activity_before, activity_after);

            if let Err(e) = write_artifacts(&cfg, &report, &metadata) {
                tracing::error!("failed to write profiling artifacts: {e}");
                return;
            }

            if metadata.representative {
                tracing::info!(
                    dir = %cfg.output_dir.display(),
                    sample_count,
                    activity_delta = ?metadata.activity_delta,
                    "CPU profile written"
                );
            } else {
                tracing::error!(
                    dir = %cfg.output_dir.display(),
                    sample_count,
                    activity_delta = ?metadata.activity_delta,
                    "profile did not overlap load; artifacts are not representative"
                );
            }
        });
    }

    /// Write the flamegraph, the pprof protobuf, and the metadata record.
    fn write_artifacts(
        cfg: &ProfileConfig,
        report: &pprof::Report,
        metadata: &ProfileMetadata,
    ) -> anyhow::Result<()> {
        use anyhow::Context;
        use pprof::protos::Message;

        std::fs::create_dir_all(&cfg.output_dir)
            .with_context(|| format!("creating {}", cfg.output_dir.display()))?;

        let svg_path = cfg.output_dir.join("flamegraph.svg");
        let svg = std::fs::File::create(&svg_path)
            .with_context(|| format!("creating {}", svg_path.display()))?;
        report
            .flamegraph(svg)
            .with_context(|| format!("writing {}", svg_path.display()))?;

        let pb_path = cfg.output_dir.join("profile.pb");
        let profile = report.pprof().context("building pprof protobuf")?;
        let mut pb = std::fs::File::create(&pb_path)
            .with_context(|| format!("creating {}", pb_path.display()))?;
        pb.write_all(&profile.write_to_bytes().context("encoding pprof protobuf")?)
            .with_context(|| format!("writing {}", pb_path.display()))?;

        let meta_path = cfg.output_dir.join("profile-metadata.json");
        std::fs::write(&meta_path, serde_json::to_vec_pretty(metadata)?)
            .with_context(|| format!("writing {}", meta_path.display()))?;

        Ok(())
    }
}
```

- [ ] **Step 4: Verify it builds and existing tests still pass under the feature**

```bash
export CC=/usr/bin/gcc CXX=/usr/bin/g++
cargo build --features pprof 2>&1 | tail -5
cargo test --features pprof --lib profiling:: 2>&1 | tail -10
cargo fmt && cargo clippy --features pprof -- -D warnings
```

Expected: builds; all Task 1/2 tests still pass; fmt and clippy clean.

If `report.pprof()` or `write_to_bytes()` fails to compile, the codec feature is wrong — re-check Step 2's `cargo tree -i prost` output.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock src/profiling/mod.rs
git commit -m "feat(profiling): add pprof-rs sampler behind off-by-default feature"
```

---

## Task 4: Cross-thread sampling integration test

This test exists because a design reviewer argued `setitimer(ITIMER_PROF)`/SIGPROF only samples the thread that armed it — true of gprof and of Go before 1.9 — which would make tokio's worker threads invisible. That was disproved experimentally (761 samples, 100% on busy spawned threads, 0 on the idle arming thread). This test pins that behaviour so a platform or crate change cannot silently reintroduce it.

**Files:**
- Create: `tests/profiling_integration.rs`

**Interfaces:**
- Consumes: `logthing::profiling::{ProfileConfig, ProfileMetadata}`, and the sampler's artifact contract (three files in `output_dir`).
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Write the failing test**

Create `tests/profiling_integration.rs`:

```rust
//! Integration coverage for the `pprof` sampler.
//!
//! Only compiled with `--features pprof`; see the `build-pprof` CI job.

#![cfg(feature = "pprof")]

use std::hint::black_box;
use std::time::{Duration, Instant};

/// Distinctly named so it can be found in the flamegraph's symbol text.
#[inline(never)]
fn logthing_profiling_test_burner(iterations: u64) -> u64 {
    let mut acc = 0u64;
    for i in 0..iterations {
        acc = acc.wrapping_add(black_box(i).wrapping_mul(2_654_435_761));
    }
    acc
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sampler_attributes_cpu_burned_on_a_different_thread() {
    let dir = tempfile::tempdir().expect("tempdir");

    // SAFETY: single-threaded setup before any profiling task is spawned.
    unsafe {
        std::env::set_var("LOGTHING_PROFILE_SECS", "2");
        std::env::set_var("LOGTHING_PROFILE_HZ", "99");
        std::env::set_var("LOGTHING_PROFILE_DIR", dir.path());
        std::env::remove_var("LOGTHING_PROFILE_DELAY_SECS");
    }

    // The guard is built by the spawned sampler task. The burner runs on a
    // *different* OS thread entirely, which is the property under test.
    logthing::profiling::maybe_start(Some(Box::new(|| Some(0))));

    let burner = std::thread::spawn(|| {
        let start = Instant::now();
        let mut acc = 0u64;
        while start.elapsed() < Duration::from_secs(3) {
            acc = acc.wrapping_add(logthing_profiling_test_burner(200_000));
        }
        acc
    });

    tokio::time::sleep(Duration::from_secs(4)).await;
    let _ = burner.join();

    let svg = std::fs::read_to_string(dir.path().join("flamegraph.svg")).expect("flamegraph.svg");
    let meta_raw =
        std::fs::read_to_string(dir.path().join("profile-metadata.json")).expect("metadata");
    let pb = std::fs::metadata(dir.path().join("profile.pb")).expect("profile.pb");

    assert!(!svg.is_empty(), "flamegraph.svg is empty");
    assert!(pb.len() > 0, "profile.pb is empty");
    assert!(
        svg.contains("logthing_profiling_test_burner"),
        "flamegraph does not attribute samples to the burner running on another \
         thread — cross-thread SIGPROF sampling may be broken on this platform"
    );

    let meta: serde_json::Value = serde_json::from_str(&meta_raw).expect("metadata parses");
    assert!(
        meta["sample_count"].as_u64().unwrap() > 0,
        "no samples collected"
    );
}
```

Add `tempfile` to `[dev-dependencies]` in `Cargo.toml` if it is not already present (check first — `AGENTS.md` says the repo already uses it for temp files in tests):

```bash
grep -n "tempfile" Cargo.toml
```

- [ ] **Step 2: Run test to verify it fails**

```bash
export CC=/usr/bin/gcc CXX=/usr/bin/g++
cargo test --features pprof --test profiling_integration 2>&1 | tail -20
```

Expected: FAIL. If Task 3 is complete it may already pass — that is acceptable here, because the test's purpose is regression protection rather than driving new code. If it fails on the `svg.contains(...)` assertion, **stop and report**: that means cross-thread sampling does not work on this platform and the design's core premise needs revisiting.

- [ ] **Step 3: Run the full feature test suite**

```bash
export CC=/usr/bin/gcc CXX=/usr/bin/g++
cargo test --features pprof 2>&1 | tail -20
cargo fmt && cargo clippy --features pprof --all-targets -- -D warnings
```

Expected: everything passes; fmt and clippy clean.

- [ ] **Step 4: Commit**

```bash
git add tests/profiling_integration.rs Cargo.toml Cargo.lock
git commit -m "test(profiling): pin cross-thread SIGPROF sampling behaviour"
```

---

## Task 5: CI job for the `pprof` feature

Without this the feature and its `#[cfg]`-gated integration test never compile in CI, because the root `cargo build/test/clippy` uses default features only.

**Files:**
- Modify: `.github/workflows/rust.yml`

**Interfaces:**
- Consumes: the `pprof` feature from Task 3, the integration test from Task 4.
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Read the existing convention**

```bash
sed -n '54,80p' .github/workflows/rust.yml
```

Expected: the `build-kerberos` job, which runs build, test and clippy under `--features kerberos-auth`.

- [ ] **Step 2: Add the mirrored job**

Append to `.github/workflows/rust.yml`, matching the `build-kerberos` job's structure exactly (same `runs-on`, same checkout/toolchain/cache steps — copy them verbatim from that job, substituting the feature name):

```yaml
  build-pprof:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - name: Install Rust toolchain
      uses: dtolnay/rust-toolchain@stable
    - name: Cache cargo registry
      uses: Swatinem/rust-cache@v2
    - name: Build (pprof)
      run: cargo build --features pprof --verbose
    - name: Test (pprof)
      run: cargo test --features pprof --verbose
    - name: Clippy (pprof)
      run: cargo clippy --features pprof --all-targets -- -D warnings
```

If the `build-kerberos` job's checkout/toolchain/cache steps differ from the above, use **its** versions verbatim rather than these — consistency with the existing job matters more than these exact lines.

- [ ] **Step 3: Validate the workflow parses**

```bash
python3 -c "import yaml,sys; d=yaml.safe_load(open('.github/workflows/rust.yml')); print(sorted(d['jobs'].keys()))"
```

Expected: output includes `build-pprof` alongside `build` and `build-kerberos`.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/rust.yml
git commit -m "ci: build, test and lint the pprof feature"
```

---

## Task 6: Replace the dead profiling scripts with a working e2e runner

`scripts/profile-server.sh` and `scripts/run-flamegraph.sh` hard-depend on `perf record`/`perf script` and `cargo flamegraph`. Neither is installed, and `/proc/sys/kernel/perf_event_paranoid` is `3`, which blocks unprivileged `perf_event_open` outright — so both are dead code that will mislead the next reader into thinking `perf` profiling is supported. `scripts/run-with-profiling.sh` is deliberately **kept**: it is an unrelated WEF/S3 environment runner with no `perf` dependency.

**Files:**
- Delete: `scripts/profile-server.sh`, `scripts/run-flamegraph.sh`
- Create: `scripts/profile-syslog-udp.sh`

**Interfaces:**
- Consumes: the built `target/profiling/logthing` binary, `target/release/loadgen`, `tools/loadgen/ci/logthing-baseline.toml`, and the artifact contract from Task 3.
- Produces: the artifacts consumed by Task 7.

- [ ] **Step 1: Delete the dead scripts**

```bash
git rm scripts/profile-server.sh scripts/run-flamegraph.sh
```

- [ ] **Step 2: Create the e2e runner**

Create `scripts/profile-syslog-udp.sh`, `chmod +x` it:

```bash
#!/bin/bash
# Profile logthing's syslog-UDP ingest path under load and assert the sampling
# window actually overlapped that load.
#
# Deliberately drives ONE rate point per run: the profile is a single fixed
# window, so a multi-rate sweep would blend idle and loaded regimes into one
# indistinguishable flamegraph.
#
# Restores repo config files on every exit path -- logthing.admin.toml is
# git-tracked and overrides logthing.toml, a trap documented in commit 87b1d5e.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${OUT:-$REPO/profiling-results}"
RATE="${RATE:-50000}"
DURATION="${DURATION:-30}"
DELAY="${DELAY:-5}"
HZ="${HZ:-99}"
BK="$(mktemp -d)"

cd "$REPO"
cp logthing.toml "$BK/logthing.toml.orig"
cp logthing.admin.toml "$BK/logthing.admin.toml.orig"

SRV_PID=""
restore() {
    [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null
    sleep 1
    [ -n "$SRV_PID" ] && kill -9 "$SRV_PID" 2>/dev/null
    cp "$BK/logthing.toml.orig" "$REPO/logthing.toml"
    cp "$BK/logthing.admin.toml.orig" "$REPO/logthing.admin.toml"
    rm -rf "$BK"
}
trap restore EXIT INT TERM

rm -f logthing.admin.toml
cp tools/loadgen/ci/logthing-baseline.toml logthing.toml
rm -rf /tmp/logthing-perf-local "$OUT"
mkdir -p /tmp/logthing-perf-local

LOGTHING_PROFILE_SECS="$DURATION" \
LOGTHING_PROFILE_DELAY_SECS="$DELAY" \
LOGTHING_PROFILE_HZ="$HZ" \
LOGTHING_PROFILE_DIR="$OUT" \
    "$REPO/target/profiling/logthing" > /tmp/logthing-profile-stdout.log 2>&1 &
SRV_PID=$!

for _ in $(seq 1 30); do
    curl -sf http://127.0.0.1:9090/metrics >/dev/null 2>&1 && break
    sleep 0.5
done
curl -sf http://127.0.0.1:9090/metrics >/dev/null || {
    echo "SERVER DID NOT COME UP"; tail -20 /tmp/logthing-profile-stdout.log; exit 1
}

# Start load immediately; the server waits $DELAY before sampling, so the
# window opens well inside the load period.
"$REPO/target/release/loadgen" syslog-udp --host 127.0.0.1 --port 15514 \
    --target-rate "$RATE" --duration-secs "$((DELAY + DURATION + 10))" | tail -3

sleep 5

META="$OUT/profile-metadata.json"
[ -f "$META" ] || { echo "FAIL: $META not written"; exit 1; }
python3 - "$META" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
print(json.dumps(m, indent=2))
if not m["representative"]:
    sys.exit("FAIL: profile is not representative "
             f"(samples={m['sample_count']}, delta={m['activity_delta']})")
print("OK: representative profile")
PY
echo "artifacts in $OUT"
```

- [ ] **Step 3: Build both binaries and run it**

```bash
export CC=/usr/bin/gcc CXX=/usr/bin/g++
cargo build --profile profiling --features pprof
cargo build -p loadgen --release
bash scripts/profile-syslog-udp.sh
```

Expected: `OK: representative profile`, and `profiling-results/` containing `flamegraph.svg`, `profile.pb`, `profile-metadata.json` with `"representative": true` and a non-zero `activity_delta`.

If it reports `FAIL: profile is not representative`, increase `DELAY` or `DURATION` and re-run — do **not** weaken the assertion.

- [ ] **Step 4: Confirm the working tree is clean**

```bash
git status --short -- logthing.toml logthing.admin.toml
```

Expected: empty output (the trap restored both files).

- [ ] **Step 5: Add `profiling-results/` to `.gitignore` and commit**

```bash
grep -q '^profiling-results/' .gitignore || echo 'profiling-results/' >> .gitignore
git add scripts/profile-syslog-udp.sh .gitignore
git commit -m "chore(scripts): replace perf-dependent scripts with profile-syslog-udp.sh"
```

---

## Task 7: Run the profile and write up the finding

The tooling is not the deliverable. This task is.

**Files:**
- Create: `docs/performance/2026-07-25-syslog-udp-cpu-profile.md`

**Interfaces:**
- Consumes: `scripts/profile-syslog-udp.sh` and its artifacts from Task 6.
- Produces: the written finding.

- [ ] **Step 1: Read the template and the baseline it must be comparable with**

```bash
cat docs/performance/methodology-template.md
sed -n '1,60p' docs/performance/2026-07-24-syslog-udp-baseline-results.md
```

- [ ] **Step 2: Capture the profile**

```bash
export CC=/usr/bin/gcc CXX=/usr/bin/g++
RATE=50000 DURATION=30 DELAY=5 bash scripts/profile-syslog-udp.sh
```

- [ ] **Step 3: Extract the top CPU consumers from the flamegraph**

```bash
python3 - <<'PY'
import re, collections
svg = open('profiling-results/flamegraph.svg').read()
# Flamegraph frames carry their sample counts in the <title> elements.
rows = re.findall(r'<title>(.*?) \(([\d,]+) samples, ([\d.]+)%\)</title>', svg)
agg = collections.Counter()
for name, samples, pct in rows:
    agg[name] = max(agg[name], float(pct))
for name, pct in agg.most_common(40):
    print(f"{pct:6.2f}%  {name}")
PY
```

- [ ] **Step 4: Run the overhead validation**

Three repeats each with and without profiling, on an otherwise-idle box. The
metric is **CPU-seconds per received datagram** — not the raw received counter,
which is confounded by the kernel dropping ~42% of datagrams before the
application sees them.

```bash
# With profiling
for i in 1 2 3; do RATE=50000 DURATION=30 DELAY=5 bash scripts/profile-syslog-udp.sh >/dev/null 2>&1; done
# Without: re-run with LOGTHING_PROFILE_SECS unset by setting DURATION=0
```

For each run record total process CPU-seconds (`/proc/<pid>/stat` fields 14+15, or the per-thread sampler used to produce the original figure) and the `syslog_messages_received` delta, then compute CPU-sec ÷ received.

- [ ] **Step 5: Write the document**

Create `docs/performance/2026-07-25-syslog-udp-cpu-profile.md` following `methodology-template.md`'s structure. It **must** contain:

1. Exact commit SHA, config, and commands run.
2. The metadata JSON proving the profile was representative.
3. A table of the top CPU consumers by percentage, with real symbol names.
4. **An explicit accounting of the ~94.6µs/datagram**: how much is envelope regex parse, payload dispatch, Arrow mapping, metrics, allocation, and what remains unexplained. State the unexplained remainder plainly rather than forcing the numbers to add up.
5. The overhead-validation result, including the caveat that profiling may itself shift the kernel drop rate and therefore the denominator.
6. A short section reconciling against the bottom-up criterion benches on `perf/syslog-recv-path-benches` (if that branch has landed) — do the top-down and bottom-up numbers agree?
7. Limitations, in the candid style of the existing baseline document.

- [ ] **Step 6: Commit**

```bash
git add docs/performance/2026-07-25-syslog-udp-cpu-profile.md
git commit -m "docs(perf): record where syslog-udp CPU time actually goes"
```

---

## Completion criteria

- [ ] `cargo test` (default features) passes; `cargo test --features pprof` passes.
- [ ] `cargo clippy --all-targets -- -D warnings` and `cargo clippy --features pprof --all-targets -- -D warnings` are clean.
- [ ] `cargo build` with default features does **not** compile `pprof` (`cargo tree | grep -c pprof` returns 0).
- [ ] `git status` clean — in particular `logthing.toml` and `logthing.admin.toml` byte-identical to committed state.
- [ ] `docs/performance/2026-07-25-syslog-udp-cpu-profile.md` exists and accounts for the ~94.6µs/datagram.
- [ ] Nothing committed to `master`. The branch is left for the user to review and merge.
