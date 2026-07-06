# sFlow Local-Disk Persistence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `LocalDiskSink` support to sFlow, so `[sflow.local]` can persist flow and counter samples to local disk as Parquet, independently of or alongside `[sflow.s3]`.

**Architecture:** Mirror IPFIX's just-landed pattern: `sflow_start` currently inlines `BufferedWriterConfig`/`FlushPolicy` construction directly — migrate it to call the shared `crate::forwarding::buffered_writer::start_writer::<SflowSink>` directly (no new `build_sflow_handle` wrapper), add a new `sflow_local_start`, and add a `MultiSflowHandler` fan-out wrapper. sFlow's `Handler` trait method (`SflowHandler::handle_samples`) takes a `Vec<SflowRecord>` batch, same shape as IPFIX — `MultiSflowHandler` clones the whole `Vec` once per destination. Wire `main.rs`'s sFlow block the same way the Zeek/Suricata/IPFIX blocks already are.

**Tech Stack:** Rust, tokio, arrow/parquet, existing `UploadSink`/`ParquetSink`/`start_writer<S>` — no new dependencies.

## Global Constraints

- sFlow has exactly two fixed partitions, `"flow"` and `"counter"` — `max_partitions: 2` is hardcoded at the `start_writer` call site in both `sflow_start` and the new `sflow_local_start` (matches the existing literal `2` inline comment `// "flow" and "counter"` in `src/forwarding/sflow_s3.rs:269`).
- `SflowLocalConfig`'s flush-policy fields reuse the exact same default functions as `SflowS3Config` (`default_sflow_s3_prefix`, `default_sflow_flush_bytes`, `default_sflow_flush_secs`, `default_sflow_channel_capacity`, `default_sflow_max_buffer_rows`) — no new default functions or values.
- No new Cargo dependencies. No new Cargo features.
- `sflow_start` and the new `sflow_local_start` must both call `crate::forwarding::buffered_writer::start_writer::<SflowSink>(...)` directly — do NOT write a new `build_sflow_handle` wrapper function.
- `MultiSflowHandler`'s record type is `Vec<SflowRecord>` (the whole batch `SflowHandler::handle_samples` receives in one call) — cloning the `Vec` once per destination.
- This plan does NOT add e2e (docker-compose simulation-environment) coverage — sFlow has no existing `sflow-generator`/`sflow-s3-verifier` pair to extend (confirmed by grep: sFlow does not appear anywhere in `tests/e2e/simulation-environment/docker-compose.yml` or `run.sh`), matching the precedent already set for Suricata. The Rust-level integration test in Task 4 is the most rigorous verification level this plan delivers; full e2e docker-based coverage remains a pre-existing gap for sFlow, not something this feature is expected to fix as a side effect.
- Every new test function name must be distinct from existing ones in the same file.
- **Rustfmt note:** a prior plan in this series (IPFIX) shipped test snippets that weren't themselves rustfmt-clean, which slipped through both implementation and per-task review and was only caught at the final whole-branch review. Every code block below has been pre-wrapped to match rustfmt's expected line-breaking — copy it verbatim, and still run `cargo fmt --all -- --check` as directed in each task's steps to confirm.

---

### Task 1: Add `SflowLocalConfig` to `src/config/mod.rs`

**Files:**
- Modify: `src/config/mod.rs` (add `SflowLocalConfig` struct after `SflowS3Config`, currently ending at line 787; add `local` field to `SflowConfig` at lines 720-733 and its `Default` impl at lines 735-744)
- Test: same file's `#[cfg(test)] mod tests` block

**Interfaces:**
- Consumes: `default_sflow_s3_prefix`, `default_sflow_flush_bytes`, `default_sflow_flush_secs`, `default_sflow_channel_capacity`, `default_sflow_max_buffer_rows` (all already exist at lines 773-787).
- Produces: `pub struct SflowLocalConfig { pub directory: PathBuf, pub prefix: String, pub flush_threshold_bytes: usize, pub flush_interval_secs: u64, pub channel_capacity: usize, pub max_buffer_rows: usize }`, and `SflowConfig.local: Option<SflowLocalConfig>` — both consumed by Task 2 (`sflow_s3.rs`) and Task 3 (`main.rs`).

- [ ] **Step 1: Write the failing tests**

Add these four tests inside the existing `#[cfg(test)] mod tests { ... }` block in `src/config/mod.rs`. Find the existing sFlow config tests (search for a test name containing `sflow` near the IPFIX/Suricata test groups) and insert directly after that group:

```rust
    #[test]
    fn sflow_local_absent_gives_none() {
        let cfg = Config::default();
        assert!(
            cfg.sflow.local.is_none(),
            "absent [sflow.local] must deserialize to None"
        );
    }

    #[test]
    fn sflow_local_config_deserializes_from_toml() {
        let toml_str = r#"
directory = "/var/log/logthing/sflow"
prefix = "sflow"
flush_threshold_bytes = 52428800
flush_interval_secs = 300
channel_capacity = 512
max_buffer_rows = 50000
"#;
        let cfg: SflowLocalConfig = toml::from_str(toml_str).expect("deserialize");
        assert_eq!(
            cfg.directory,
            std::path::PathBuf::from("/var/log/logthing/sflow")
        );
        assert_eq!(cfg.prefix, "sflow");
        assert_eq!(cfg.flush_threshold_bytes, 52_428_800);
        assert_eq!(cfg.flush_interval_secs, 300);
        assert_eq!(cfg.channel_capacity, 512);
        assert_eq!(cfg.max_buffer_rows, 50_000);
    }

    #[test]
    fn sflow_local_config_defaults_apply_when_only_directory_given() {
        let toml_str = r#"directory = "/data/sflow""#;
        let cfg: SflowLocalConfig = toml::from_str(toml_str).expect("deserialize");
        assert_eq!(cfg.prefix, "sflow");
        assert_eq!(cfg.flush_threshold_bytes, 100 * 1024 * 1024);
        assert_eq!(cfg.flush_interval_secs, 900);
        assert_eq!(cfg.channel_capacity, 256);
        assert_eq!(cfg.max_buffer_rows, 100_000);
    }

    #[test]
    fn sflow_s3_and_local_can_both_be_configured_simultaneously() {
        let toml_str = r#"
[sflow]
enabled = true

[sflow.s3]
endpoint = "http://minio:9000"
bucket = "b"
region = "us-east-1"
access_key = "k"
secret_key = "s"

[sflow.local]
directory = "/data/sflow"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("deserialize");
        assert!(
            cfg.sflow.s3.is_some(),
            "s3 must deserialize when both present"
        );
        assert!(
            cfg.sflow.local.is_some(),
            "local must deserialize when both present"
        );
    }
```

- [ ] **Step 2: Run tests to verify they fail (struct doesn't exist yet)**

Run: `cargo test --lib config::tests::sflow_local -- --nocapture`
Expected: FAIL with a compile error — `SflowLocalConfig` is not defined and `SflowConfig` has no field `local`.

- [ ] **Step 3: Add `SflowLocalConfig` and wire it into `SflowConfig`**

In `src/config/mod.rs`, change the `SflowConfig` struct (lines 720-733) from:

```rust
pub struct SflowConfig {
    #[serde(default = "default_sflow_enabled")]
    pub enabled: bool,

    #[serde(default = "default_sflow_udp_port")]
    pub udp_port: u16,

    #[serde(default = "default_sflow_bind_address")]
    pub bind_address: String,

    /// Optional S3 persistence. Absent from TOML → `None` (backward compatible).
    #[serde(default)]
    pub s3: Option<SflowS3Config>,
}

impl Default for SflowConfig {
    fn default() -> Self {
        Self {
            enabled: default_sflow_enabled(),
            udp_port: default_sflow_udp_port(),
            bind_address: default_sflow_bind_address(),
            s3: None,
        }
    }
}
```

to:

```rust
pub struct SflowConfig {
    #[serde(default = "default_sflow_enabled")]
    pub enabled: bool,

    #[serde(default = "default_sflow_udp_port")]
    pub udp_port: u16,

    #[serde(default = "default_sflow_bind_address")]
    pub bind_address: String,

    /// Optional S3 persistence. Absent from TOML → `None` (backward compatible).
    #[serde(default)]
    pub s3: Option<SflowS3Config>,

    /// Optional local-disk persistence. Absent from TOML → `None` → no
    /// persistence. Independent of `s3` — both may be configured
    /// simultaneously, in which case records are written to both.
    #[serde(default)]
    pub local: Option<SflowLocalConfig>,
}

impl Default for SflowConfig {
    fn default() -> Self {
        Self {
            enabled: default_sflow_enabled(),
            udp_port: default_sflow_udp_port(),
            bind_address: default_sflow_bind_address(),
            s3: None,
            local: None,
        }
    }
}
```

Then, immediately after `fn default_sflow_max_buffer_rows() -> usize { 100_000 }` (line 785-787), insert:

```rust

/// Per-source local-disk persistence config for the sFlow listener. Mirrors
/// `SflowS3Config`'s flush-policy shape (reusing the same default
/// functions), swapping the S3 connection for a root directory.
/// Independent of `s3`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SflowLocalConfig {
    /// Root directory Parquet files are written under (created if missing).
    pub directory: PathBuf,
    /// Key prefix, slash-free (default: `"sflow"` — same default as `sflow.s3`).
    #[serde(default = "default_sflow_s3_prefix")]
    pub prefix: String,
    /// Flush when estimated buffer bytes exceeds this (default: 100 MiB).
    #[serde(default = "default_sflow_flush_bytes")]
    pub flush_threshold_bytes: usize,
    /// Flush after this many seconds regardless of buffer size (default: 900).
    #[serde(default = "default_sflow_flush_secs")]
    pub flush_interval_secs: u64,
    /// Bounded channel capacity (default: 256).
    #[serde(default = "default_sflow_channel_capacity")]
    pub channel_capacity: usize,
    /// Maximum buffered rows before hard cap kicks in (default: 100_000).
    #[serde(default = "default_sflow_max_buffer_rows")]
    pub max_buffer_rows: usize,
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib config:: -- --nocapture`
Expected: PASS — all four new tests, plus every existing `config::tests::*` test (in particular any pre-existing `sflow_*` tests, which must be unaffected).

- [ ] **Step 5: Run fmt to confirm the new code is clean**

Run: `cargo fmt --all -- --check`
Expected: no output.

- [ ] **Step 6: Commit**

```bash
git add src/config/mod.rs
git commit -m "feat(config): add SflowLocalConfig, SflowConfig.local

Mirrors IpfixLocalConfig's shape exactly: independent Option field, reuses
the existing sflow.s3 default functions for its flush-policy fields. Not
yet wired to any writer — that's the next task."
```

---

### Task 2: Refactor `sflow_s3.rs` — migrate `sflow_start` to `start_writer`, add `sflow_local_start` and `MultiSflowHandler`

**Files:**
- Modify: `src/forwarding/sflow_s3.rs` (add `#[derive(Default)]` to `SflowSink` at line 53; replace the block from the `SflowS3Handler` type-alias section through the end of `sflow_start` at lines 235-277)
- Test: same file's `#[cfg(test)] mod tests` block (starts line 281)

**Interfaces:**
- Consumes: `SflowLocalConfig` (Task 1), `crate::forwarding::buffered_writer::start_writer` (already hoisted), `crate::forwarding::local_sink::LocalDiskSink`, `crate::sflow::listener::SflowHandler` trait (`async fn handle_samples(&self, samples: Vec<SflowRecord>, source: SocketAddr)`, `src/sflow/listener.rs:29-30`).
- Produces: `pub fn sflow_local_start(cfg: &SflowLocalConfig, sink: Arc<LocalDiskSink>, source_stats: Arc<SourceHourlyStats>) -> (SflowS3Handler, JoinHandle<()>)` and `pub struct MultiSflowHandler(pub Vec<Arc<dyn SflowHandler>>)` — both consumed by Task 3 (`main.rs`).

- [ ] **Step 1: Write the failing tests**

Add these tests inside the existing `#[cfg(test)] mod tests { ... }` block in `src/forwarding/sflow_s3.rs`, placed directly after the existing `sflow_sink_reports_into_shared_source_hourly_stats` test (the last test in the file, ending at line 511, right before the file's closing `}` at line 512):

```rust

    // -- sflow_local_start wires handler and join handle --

    #[tokio::test]
    async fn sflow_local_start_wires_handler_and_join_handle() {
        use crate::config::SflowLocalConfig;
        use crate::forwarding::local_sink::LocalDiskSink;
        use crate::sflow::listener::SflowHandler;
        use std::net::SocketAddr;

        let dir = tempfile::tempdir().unwrap();
        let sink = Arc::new(
            LocalDiskSink::new(dir.path().to_path_buf())
                .await
                .expect("LocalDiskSink::new"),
        );
        let cfg = SflowLocalConfig {
            directory: dir.path().to_path_buf(),
            prefix: "sflow".to_string(),
            flush_threshold_bytes: 1, // flush on first push
            flush_interval_secs: 3600,
            channel_capacity: 256,
            max_buffer_rows: 100_000,
        };
        let (handler, join_handle) = sflow_local_start(
            &cfg,
            sink,
            std::sync::Arc::new(crate::stats::SourceHourlyStats::new()),
        );

        let src: SocketAddr = "127.0.0.1:6343".parse().unwrap();
        handler
            .handle_samples(vec![make_flow_record(), make_counter_record()], src)
            .await;

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        drop(handler);
        tokio::time::timeout(std::time::Duration::from_secs(5), join_handle)
            .await
            .expect("writer task must exit within 5s")
            .expect("writer task must not panic");

        for partition in ["flow", "counter"] {
            let dir_path = dir.path().join("sflow").join(partition);
            let mut found = false;
            for entry in walk_all_files(&dir_path) {
                if entry.extension().is_some_and(|e| e == "parquet") {
                    found = true;
                    break;
                }
            }
            assert!(
                found,
                "expected at least one Parquet file under {dir_path:?}"
            );
        }
    }

    /// Recursive walk — sFlow's key layout nests under year=/month=/day=/, so
    /// a flat `read_dir` on the prefix directory alone won't find the file.
    fn walk_all_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries {
                let entry = entry.unwrap();
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    out.push(path);
                }
            }
        }
        out
    }

    // -- MultiSflowHandler tests --

    #[tokio::test]
    async fn multi_sflow_handler_fans_out_to_every_inner_handler() {
        use crate::sflow::listener::SflowHandler;
        use std::net::SocketAddr;
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct CountingHandler(Arc<AtomicUsize>);
        #[async_trait::async_trait]
        impl SflowHandler for CountingHandler {
            async fn handle_samples(&self, _samples: Vec<SflowRecord>, _source: SocketAddr) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let count_a = Arc::new(AtomicUsize::new(0));
        let count_b = Arc::new(AtomicUsize::new(0));
        let multi = MultiSflowHandler(vec![
            Arc::new(CountingHandler(count_a.clone())),
            Arc::new(CountingHandler(count_b.clone())),
        ]);

        let src: SocketAddr = "127.0.0.1:6343".parse().unwrap();
        multi.handle_samples(vec![make_flow_record()], src).await;

        assert_eq!(
            count_a.load(Ordering::SeqCst),
            1,
            "handler A must receive the batch"
        );
        assert_eq!(
            count_b.load(Ordering::SeqCst),
            1,
            "handler B must receive the batch"
        );
    }

    #[tokio::test]
    #[allow(clippy::mutable_key_type)]
    async fn multi_sflow_handler_survives_one_inner_handler_dropping() {
        use crate::config::S3ConnectionConfig;
        use crate::sflow::listener::SflowHandler;
        use metrics::set_default_local_recorder;
        use metrics_util::CompositeKey;
        use metrics_util::MetricKind;
        use metrics_util::debugging::DebuggingRecorder;
        use std::net::SocketAddr;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let s3 = Arc::new(
            crate::forwarding::s3_sink::S3Sink::from_connection(&S3ConnectionConfig {
                endpoint: "http://127.0.0.1:1".to_string(),
                bucket: "test-bucket".to_string(),
                region: "us-east-1".to_string(),
                access_key: "AKIATEST".to_string(),
                secret_key: "SECRETTEST".to_string(),
            })
            .await
            .unwrap(),
        );
        let cfg = SflowS3Config {
            connection: S3ConnectionConfig {
                endpoint: "http://127.0.0.1:1".to_string(),
                bucket: "test-bucket".to_string(),
                region: "us-east-1".to_string(),
                access_key: "AKIATEST".to_string(),
                secret_key: "SECRETTEST".to_string(),
            },
            prefix: "sflow".to_string(),
            flush_threshold_bytes: 1,
            flush_interval_secs: 3600,
            channel_capacity: 1,
            max_buffer_rows: 1,
        };
        let (struggling_handler, _jh) = sflow_start(
            &cfg,
            s3,
            std::sync::Arc::new(crate::stats::SourceHourlyStats::new()),
        );

        use std::sync::atomic::{AtomicUsize, Ordering};
        struct CountingHandler(Arc<AtomicUsize>);
        #[async_trait::async_trait]
        impl SflowHandler for CountingHandler {
            async fn handle_samples(&self, _samples: Vec<SflowRecord>, _source: SocketAddr) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let healthy_count = Arc::new(AtomicUsize::new(0));
        let multi = MultiSflowHandler(vec![
            Arc::new(struggling_handler),
            Arc::new(CountingHandler(healthy_count.clone())),
        ]);

        let src: SocketAddr = "127.0.0.1:6343".parse().unwrap();
        for _ in 0..20 {
            multi.handle_samples(vec![make_flow_record()], src).await;
        }

        assert_eq!(
            healthy_count.load(Ordering::SeqCst),
            20,
            "the healthy handler must receive every batch even if the struggling one drops some"
        );

        let snapshot = snapshotter.snapshot();
        let map = snapshot.into_hashmap();
        let key = CompositeKey::new(
            MetricKind::Counter,
            metrics::Key::from_parts(
                "parquet_s3_dropped",
                vec![
                    metrics::Label::new("source", "sflow"),
                    metrics::Label::new("target", "s3"),
                ],
            ),
        );
        let dropped = map
            .get(&key)
            .map(|(_, _, v)| {
                if let metrics_util::debugging::DebugValue::Counter(c) = v {
                    *c
                } else {
                    0
                }
            })
            .unwrap_or(0);
        assert!(
            dropped >= 1,
            "the struggling handler must actually have dropped at least one batch \
             for this test to prove handler isolation (dropped={dropped})"
        );
    }
```

- [ ] **Step 2: Run tests to verify they fail (functions don't exist yet)**

Run: `cargo test --lib forwarding::sflow_s3::tests::sflow_local_start_wires -- --nocapture`
Expected: FAIL with a compile error — `sflow_local_start` and `MultiSflowHandler` are not defined.

- [ ] **Step 3: Add `#[derive(Default)]` to `SflowSink`, migrate `sflow_start` to `start_writer`, add `MultiSflowHandler` and `sflow_local_start`**

Change `SflowSink`'s declaration (line 53) from:

```rust
pub struct SflowSink;
```

to:

```rust
#[derive(Default)]
pub struct SflowSink;
```

Replace the entire block from the `// ── SflowS3Handler — type alias + SflowHandler impl` section comment (line 235) through the end of `sflow_start` (line 277) — i.e. replace this:

```rust
// ── SflowS3Handler — type alias + SflowHandler impl ─────────────────────────

pub type SflowS3Handler = crate::forwarding::buffered_writer::ParquetWriterHandle<SflowSink>;

#[async_trait::async_trait]
impl crate::sflow::listener::SflowHandler
    for crate::forwarding::buffered_writer::ParquetWriterHandle<SflowSink>
{
    async fn handle_samples(&self, samples: Vec<SflowRecord>, source: std::net::SocketAddr) {
        for record in samples {
            if let Err(_dropped) = self.try_send(record) {
                tracing::warn!("sFlow S3 channel full; dropped record from {}", source);
            }
        }
    }
}

// ── sflow_start — convenience constructor ────────────────────────────────────

pub fn sflow_start(
    cfg: &SflowS3Config,
    s3: Arc<crate::forwarding::s3_sink::S3Sink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
) -> (SflowS3Handler, tokio::task::JoinHandle<()>) {
    use crate::forwarding::buffered_writer::{
        BufferedWriterConfig, FlushPolicy, ParquetWriterHandle,
    };
    let bwc = BufferedWriterConfig {
        connection: cfg.connection.clone(),
        prefix: cfg.prefix.clone(),
        max_buffer_rows: cfg.max_buffer_rows,
        flush_threshold_bytes: cfg.flush_threshold_bytes,
        flush_interval_secs: cfg.flush_interval_secs,
        channel_capacity: cfg.channel_capacity,
        max_partitions: 2, // "flow" and "counter"
    };
    let policy = FlushPolicy {
        max_rows: cfg.max_buffer_rows,
        max_bytes: cfg.flush_threshold_bytes,
        interval: std::time::Duration::from_secs(cfg.flush_interval_secs),
    };
    ParquetWriterHandle::start_with_stats(SflowSink, s3, bwc, policy, source_stats)
}
```

with this:

```rust
// ── SflowS3Handler — type alias + SflowHandler impl ─────────────────────────

pub type SflowS3Handler = crate::forwarding::buffered_writer::ParquetWriterHandle<SflowSink>;

#[async_trait::async_trait]
impl crate::sflow::listener::SflowHandler
    for crate::forwarding::buffered_writer::ParquetWriterHandle<SflowSink>
{
    async fn handle_samples(&self, samples: Vec<SflowRecord>, source: std::net::SocketAddr) {
        for record in samples {
            if let Err(_dropped) = self.try_send(record) {
                tracing::warn!("sFlow S3 channel full; dropped record from {}", source);
            }
        }
    }
}

// ── MultiSflowHandler — fan-out to multiple destinations ────────────────────

/// Fans out each sample batch to every configured handler. Used only when
/// both `.s3` and `.local` persistence resolve to a live handler for the
/// same run, so each destination keeps its own independent buffer, flush
/// policy, backpressure, and hard cap (no shared state between destinations).
pub struct MultiSflowHandler(pub Vec<std::sync::Arc<dyn crate::sflow::listener::SflowHandler>>);

#[async_trait::async_trait]
impl crate::sflow::listener::SflowHandler for MultiSflowHandler {
    async fn handle_samples(&self, samples: Vec<SflowRecord>, source: std::net::SocketAddr) {
        for handler in &self.0 {
            handler.handle_samples(samples.clone(), source).await;
        }
    }
}

// ── sflow_start / sflow_local_start — convenience constructors ──────────────

/// sFlow has exactly two fixed partitions: `"flow"` and `"counter"`.
const SFLOW_MAX_PARTITIONS: usize = 2;

pub fn sflow_start(
    cfg: &SflowS3Config,
    s3: Arc<crate::forwarding::s3_sink::S3Sink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
) -> (SflowS3Handler, tokio::task::JoinHandle<()>) {
    crate::forwarding::buffered_writer::start_writer::<SflowSink>(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        cfg.flush_threshold_bytes,
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        SFLOW_MAX_PARTITIONS,
        s3,
        source_stats,
    )
}

/// Construct an `SflowS3Handler` from an `SflowLocalConfig` and a pre-built
/// `LocalDiskSink`. Structurally identical to `sflow_start`, writing to
/// local disk instead of S3 — same `SflowSink` adapter, same
/// buffering/flush/cap machinery, same S3-key-shaped relative path layout
/// on disk.
pub fn sflow_local_start(
    cfg: &crate::config::SflowLocalConfig,
    sink: std::sync::Arc<crate::forwarding::local_sink::LocalDiskSink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
) -> (SflowS3Handler, tokio::task::JoinHandle<()>) {
    crate::forwarding::buffered_writer::start_writer::<SflowSink>(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        cfg.flush_threshold_bytes,
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        SFLOW_MAX_PARTITIONS,
        sink,
        source_stats,
    )
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib forwarding::sflow_s3:: -- --nocapture`
Expected: PASS — the 3 new tests, plus every pre-existing test in this file (in particular `sink_partition_returns_flow_for_flow_records`, `sink_partition_returns_counter_for_counter_records`, `flow_schema_has_required_columns`, `counter_schema_has_required_columns`, `to_record_batch_flow_produces_correct_values`, `to_record_batch_counter_produces_correct_values`, `sflow_sink_reports_into_shared_source_hourly_stats`, which must be unaffected by the `sflow_start` migration to `start_writer`).

- [ ] **Step 5: Run fmt to confirm the new code is clean**

Run: `cargo fmt --all -- --check`
Expected: no output. If this reports a diff, run `cargo fmt --all` and re-verify — do not skip this step; a prior plan in this series shipped unformatted test code that only got caught at final review.

- [ ] **Step 6: Commit**

```bash
git add src/forwarding/sflow_s3.rs
git commit -m "feat(forwarding): add sflow_local_start + MultiSflowHandler

sflow_start now calls the shared start_writer<SflowSink> directly instead
of inlining BufferedWriterConfig/FlushPolicy construction — no new
build_sflow_handle wrapper. MultiSflowHandler fans out Vec<SflowRecord>
batches to both destinations when .s3 and .local are both configured.
Not yet wired into main.rs."
```

---

### Task 3: Wire `main.rs`'s sFlow block to support `.s3` + `.local` fan-out

**Files:**
- Modify: `src/main.rs:359-401` (the entire `if config.sflow.enabled { ... }` block)

**Interfaces:**
- Consumes: `sflow_local_start`, `MultiSflowHandler` (Task 2), `SflowConfig.local` (Task 1), `crate::forwarding::local_sink::LocalDiskSink::new` (already used identically by the Zeek/Suricata/IPFIX blocks).
- Produces: nothing new for later tasks.

- [ ] **Step 1: Replace the sFlow block**

In `src/main.rs`, replace this entire block (lines 359-401):

```rust
    // -----------------------------------------------------------------------
    // Start sFlow listener if enabled
    // -----------------------------------------------------------------------
    if config.sflow.enabled {
        let sflow_config_clone = config.clone();
        let sflow_shutdown_rx = shutdown_rx.clone();

        let sflow_handler: Arc<dyn sflow::listener::SflowHandler> =
            if let Some(s3_cfg) = sflow_config_clone.sflow.s3.as_ref() {
                match forwarding::s3_sink::S3Sink::from_connection(&s3_cfg.connection).await {
                    Ok(sink) => {
                        let (handler, writer_handle) = forwarding::sflow_s3::sflow_start(
                            s3_cfg,
                            Arc::new(sink),
                            source_stats.clone(),
                        );
                        writer_handles.push(writer_handle);
                        Arc::new(handler)
                    }
                    Err(e) => {
                        error!(
                            "Failed to create S3Sink for sFlow persistence, \
                                 falling back to DefaultSflowHandler: {e}"
                        );
                        Arc::new(sflow::listener::DefaultSflowHandler)
                    }
                }
            } else {
                Arc::new(sflow::listener::DefaultSflowHandler)
            };

        let listener_config = sflow::listener::SflowListenerConfig {
            udp_port: sflow_config_clone.sflow.udp_port,
            bind_address: sflow_config_clone.sflow.bind_address.clone(),
        };
        let handle = tokio::spawn(async move {
            let listener = sflow::listener::SflowListener::new(listener_config, sflow_handler);
            if let Err(e) = listener.start_with_shutdown(sflow_shutdown_rx).await {
                error!("sFlow listener error: {}", e);
            }
        });
        listener_handles.push(handle);
    }
```

with this:

```rust
    // -----------------------------------------------------------------------
    // Start sFlow listener if enabled
    // -----------------------------------------------------------------------
    if config.sflow.enabled {
        let sflow_config_clone = config.clone();
        let sflow_shutdown_rx = shutdown_rx.clone();

        let mut sflow_handlers: Vec<Arc<dyn sflow::listener::SflowHandler>> = Vec::new();

        if let Some(s3_cfg) = sflow_config_clone.sflow.s3.as_ref() {
            match forwarding::s3_sink::S3Sink::from_connection(&s3_cfg.connection).await {
                Ok(sink) => {
                    let (handler, writer_handle) = forwarding::sflow_s3::sflow_start(
                        s3_cfg,
                        Arc::new(sink),
                        source_stats.clone(),
                    );
                    writer_handles.push(writer_handle);
                    sflow_handlers.push(Arc::new(handler));
                }
                Err(e) => {
                    error!(
                        "Failed to create S3Sink for sFlow persistence, \
                             skipping S3 target: {e}"
                    );
                }
            }
        }

        if let Some(local_cfg) = sflow_config_clone.sflow.local.as_ref() {
            match forwarding::local_sink::LocalDiskSink::new(local_cfg.directory.clone()).await {
                Ok(sink) => {
                    let (handler, writer_handle) = forwarding::sflow_s3::sflow_local_start(
                        local_cfg,
                        Arc::new(sink),
                        source_stats.clone(),
                    );
                    writer_handles.push(writer_handle);
                    sflow_handlers.push(Arc::new(handler));
                }
                Err(e) => {
                    error!(
                        "Failed to create LocalDiskSink for sFlow persistence, \
                             skipping local target: {e}"
                    );
                }
            }
        }

        let sflow_handler: Arc<dyn sflow::listener::SflowHandler> = match sflow_handlers.len() {
            0 => Arc::new(sflow::listener::DefaultSflowHandler),
            1 => sflow_handlers.into_iter().next().unwrap(),
            _ => Arc::new(forwarding::sflow_s3::MultiSflowHandler(sflow_handlers)),
        };

        let listener_config = sflow::listener::SflowListenerConfig {
            udp_port: sflow_config_clone.sflow.udp_port,
            bind_address: sflow_config_clone.sflow.bind_address.clone(),
        };
        let handle = tokio::spawn(async move {
            let listener = sflow::listener::SflowListener::new(listener_config, sflow_handler);
            if let Err(e) = listener.start_with_shutdown(sflow_shutdown_rx).await {
                error!("sFlow listener error: {}", e);
            }
        });
        listener_handles.push(handle);
    }
```

- [ ] **Step 2: Build the whole workspace to verify it compiles**

Run: `cargo build --quiet`
Expected: no errors, no warnings introduced.

- [ ] **Step 3: Run the full lib test suite to verify nothing broke**

Run: `cargo test --lib --quiet`
Expected: PASS, no regressions.

- [ ] **Step 4: Run fmt to confirm the change is clean**

Run: `cargo fmt --all -- --check`
Expected: no output.

- [ ] **Step 5: Commit**

```bash
git add src/main.rs
git commit -m "feat(main): wire sflow.local alongside sflow.s3, fan out via MultiSflowHandler when both configured

Mirrors the existing Zeek/Suricata/IPFIX blocks' Vec<Arc<dyn Handler>> +
match-on-length pattern exactly."
```

---

### Task 4: Add `tests/sflow_local_integration.rs` — real Parquet round-trip

**Files:**
- Create: `tests/sflow_local_integration.rs`

**Why this satisfies the integration-test tier:** Drives the real `sflow_local_start` → `LocalDiskSink` → real Parquet-file-on-disk path for BOTH the `"flow"` and `"counter"` partitions, then reads each back with a real Parquet reader — no mocks. Needs no external service, so it runs unconditionally in CI.

**Why no e2e task**: sFlow has no existing e2e (docker-compose simulation-environment) coverage at all — no `sflow-generator`, no `sflow-s3-verifier`. Building that from scratch is a separate, larger effort out of scope for this plan (matching the precedent already set for Suricata). This integration test is the most rigorous verification level this plan delivers for sFlow.

**Interfaces:**
- Consumes: `logthing::config::SflowLocalConfig` (Task 1), `logthing::forwarding::local_sink::LocalDiskSink`, `logthing::forwarding::sflow_s3::sflow_local_start` (Task 2), `logthing::sflow::{SampleType, SflowRecord}`, `logthing::sflow::listener::SflowHandler`.

- [ ] **Step 1: Write the test**

Create `tests/sflow_local_integration.rs`:

```rust
//! Integration test: SflowRecord batches → sflow_local_start → real Parquet
//! files on local disk (both the "flow" and "counter" partitions), read back
//! with a real Parquet reader.
//!
//! Unlike `sflow_s3_integration.rs` (gated on a running MinIO), this test
//! needs no external service — local disk is always available — so it runs
//! unconditionally in CI.

use logthing::config::SflowLocalConfig;
use logthing::forwarding::local_sink::LocalDiskSink;
use logthing::forwarding::sflow_s3::sflow_local_start;
use logthing::sflow::listener::SflowHandler;
use logthing::sflow::{SampleType, SflowRecord};
use std::sync::Arc;

fn make_flow_record() -> SflowRecord {
    SflowRecord {
        sample_type: SampleType::Flow,
        exporter: "10.0.0.1".parse().unwrap(),
        received_at: chrono::Utc::now(),
        src_addr: Some("192.168.1.1".parse().unwrap()),
        dst_addr: Some("10.0.0.2".parse().unwrap()),
        src_port: Some(1234),
        dst_port: Some(443),
        ip_protocol: Some(6),
        sampling_rate: Some(512),
        input_ifindex: Some(1),
        output_ifindex: Some(2),
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
        extra: serde_json::json!([]),
    }
}

fn make_counter_record() -> SflowRecord {
    SflowRecord {
        sample_type: SampleType::Counter,
        exporter: "10.0.0.1".parse().unwrap(),
        received_at: chrono::Utc::now(),
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        ip_protocol: None,
        sampling_rate: None,
        input_ifindex: None,
        output_ifindex: None,
        if_index: Some(1),
        if_type: Some(6),
        if_speed: Some(1_000_000_000),
        if_direction: Some(1),
        if_in_octets: Some(1_000_000),
        if_out_octets: Some(500_000),
        if_in_ucast_pkts: Some(1000),
        if_out_ucast_pkts: Some(500),
        if_in_errors: Some(2),
        if_out_errors: Some(1),
        extra: serde_json::json!([]),
    }
}

#[tokio::test]
async fn sflow_samples_appear_as_parquet_on_local_disk() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sink = Arc::new(
        LocalDiskSink::new(dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new"),
    );
    let cfg = SflowLocalConfig {
        directory: dir.path().to_path_buf(),
        prefix: "sflow".to_string(),
        max_buffer_rows: 1, // flush immediately on first push per partition
        flush_threshold_bytes: 1,
        flush_interval_secs: 3600,
        channel_capacity: 256,
    };

    let (handler, _writer_task) = sflow_local_start(
        &cfg,
        sink,
        Arc::new(logthing::stats::SourceHourlyStats::new()),
    );

    let src: std::net::SocketAddr = "127.0.0.1:6343".parse().unwrap();
    handler
        .handle_samples(vec![make_flow_record(), make_counter_record()], src)
        .await;

    // Give the background task time to flush.
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // --- Verify the "flow" partition ---
    {
        let flow_dir = dir.path().join("sflow/flow");
        assert!(flow_dir.is_dir(), "expected {flow_dir:?} to exist");
        let parquet_files: Vec<_> = walk_all_files(&flow_dir)
            .into_iter()
            .filter(|p| p.extension().is_some_and(|ext| ext == "parquet"))
            .collect();
        assert!(
            !parquet_files.is_empty(),
            "expected at least one Parquet file under {flow_dir:?}"
        );

        let bytes = std::fs::read(&parquet_files[0]).expect("read parquet file");
        use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
        let builder = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(bytes))
            .expect("parquet builder for flow");
        let schema = builder.schema().clone();
        for col in ["sample_type", "src_addr", "sampling_rate", "extra"] {
            assert!(
                schema.field_with_name(col).is_ok(),
                "expected column '{col}' in flow schema"
            );
        }

        let mut reader = builder.build().expect("parquet reader for flow");
        let rb = reader.next().expect("at least one batch").expect("batch ok");
        assert_eq!(rb.num_rows(), 1);

        use arrow::array::StringArray;
        let src_addr = rb
            .column_by_name("src_addr")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(src_addr.value(0), "192.168.1.1");
    }

    // --- Verify the "counter" partition ---
    {
        let counter_dir = dir.path().join("sflow/counter");
        assert!(counter_dir.is_dir(), "expected {counter_dir:?} to exist");
        let parquet_files: Vec<_> = walk_all_files(&counter_dir)
            .into_iter()
            .filter(|p| p.extension().is_some_and(|ext| ext == "parquet"))
            .collect();
        assert!(
            !parquet_files.is_empty(),
            "expected at least one Parquet file under {counter_dir:?}"
        );

        let bytes = std::fs::read(&parquet_files[0]).expect("read parquet file");
        use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
        let builder = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(bytes))
            .expect("parquet builder for counter");
        let schema = builder.schema().clone();
        for col in ["sample_type", "if_speed", "if_in_octets", "extra"] {
            assert!(
                schema.field_with_name(col).is_ok(),
                "expected column '{col}' in counter schema"
            );
        }

        let mut reader = builder.build().expect("parquet reader for counter");
        let rb = reader.next().expect("at least one batch").expect("batch ok");
        assert_eq!(rb.num_rows(), 1);

        use arrow::array::UInt64Array;
        let if_speed = rb
            .column_by_name("if_speed")
            .unwrap()
            .as_any()
            .downcast_ref::<UInt64Array>()
            .unwrap();
        assert_eq!(if_speed.value(0), 1_000_000_000u64);
    }

    // --- No stray temp files left behind anywhere under the root ---
    for entry in walk_all_files(dir.path()) {
        let name = entry.file_name().unwrap().to_string_lossy();
        assert!(
            !name.contains(".tmp-"),
            "found leftover temp file: {entry:?}"
        );
    }
}

fn walk_all_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    out
}
```

- [ ] **Step 2: Run the test to verify it passes**

Run: `cargo test --test sflow_local_integration -- --nocapture`
Expected: PASS — `test sflow_samples_appear_as_parquet_on_local_disk ... ok`.

- [ ] **Step 3: Run the full test suite, fmt, and clippy**

Run: `cargo test --quiet` — expected: PASS, 0 failures.
Run: `cargo fmt --all -- --check` — expected: no output.
Run: `cargo clippy --all-targets --quiet -- -D warnings` — expected: no output.

- [ ] **Step 4: Commit**

```bash
git add tests/sflow_local_integration.rs
git commit -m "test(sflow): integration test proving real Parquet round-trip through LocalDiskSink

Verifies both the flow and counter partitions land correctly. Note: sFlow
has no e2e (docker-compose simulation-environment) coverage at all yet,
for either .s3 or .local — that's a pre-existing gap, out of scope here."
```

---

## Post-plan note for the final whole-branch review

When the final reviewer looks at this branch as a whole, it should confirm:
1. `sflow_s3.rs`'s migration of `sflow_start` to `start_writer` did not change its observable behavior for existing callers — all pre-existing tests in this file must pass unmodified.
2. The `main.rs` sFlow block now structurally matches the Zeek/Suricata/IPFIX blocks.
3. `SflowConfig`'s new `local` field does not change TOML-parsing behavior for existing `[sflow]`/`[sflow.s3]`-only configs.
4. No new `build_sflow_handle` function was introduced anywhere.
5. `cargo fmt --all -- --check` is clean across the whole branch (explicitly re-verify this given the fmt slip in the prior IPFIX plan).
