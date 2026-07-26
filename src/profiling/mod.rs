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
        pb.write_all(
            &profile
                .write_to_bytes()
                .context("encoding pprof protobuf")?,
        )
        .with_context(|| format!("writing {}", pb_path.display()))?;

        let meta_path = cfg.output_dir.join("profile-metadata.json");
        std::fs::write(&meta_path, serde_json::to_vec_pretty(metadata)?)
            .with_context(|| format!("writing {}", meta_path.display()))?;

        Ok(())
    }
}

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
        assert_eq!(
            parse_counter(rendered, "syslog_messages_received"),
            Some(123)
        );
    }

    #[test]
    fn parse_counter_reads_unlabelled_metric() {
        assert_eq!(
            parse_counter("syslog_messages_received 42", "syslog_messages_received"),
            Some(42)
        );
    }

    #[test]
    fn parse_counter_returns_none_when_absent() {
        assert_eq!(
            parse_counter("other_metric 1", "syslog_messages_received"),
            None
        );
    }

    #[test]
    fn parse_counter_ignores_prefix_collisions() {
        assert_eq!(
            parse_counter(
                "syslog_messages_received_total 5",
                "syslog_messages_received"
            ),
            None
        );
    }

    #[test]
    fn representative_requires_enough_samples() {
        assert!(!is_representative(
            MIN_REPRESENTATIVE_SAMPLES - 1,
            Some(1000)
        ));
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

    #[test]
    fn maybe_start_is_a_noop_when_disabled() {
        // No LOGTHING_PROFILE_SECS in the test environment: must not panic,
        // must not spawn, must not require a tokio runtime.
        maybe_start(None);
    }
}
