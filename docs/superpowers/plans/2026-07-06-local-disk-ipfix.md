# IPFIX Local-Disk Persistence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `LocalDiskSink` support to IPFIX, so `[ipfix.local]` can persist flow records to local disk as Parquet, independently of or alongside `[ipfix.s3]`.

**Architecture:** Mirror `src/forwarding/suricata_s3.rs`'s `.s3`/`.local` pattern — but this time, `ipfix_start`/`ipfix_local_start` call the already-shared `crate::forwarding::buffered_writer::start_writer::<IpfixSink>` directly (hoisted in a prior plan), with no per-source `build_ipfix_handle` wrapper needed. Add `MultiIpfixHandler` for `.s3`+`.local` fan-out, matching `MultiSuricataHandler`'s shape but operating on `Vec<FlowRecord>` (IPFIX's batch record type) rather than a single record. Wire `main.rs`'s IPFIX block the same way the Zeek/Suricata blocks already are. Unlike Suricata, IPFIX already has e2e (docker-compose simulation-environment) coverage — add a `.local` verifier alongside the existing `ipfix-generator`/`ipfix-s3-verifier` pair.

**Tech Stack:** Rust, tokio, arrow/parquet, existing `UploadSink`/`ParquetSink`/`start_writer<S>` — no new dependencies.

## Global Constraints

- IPFIX is single-partition: `max_partitions: 1` is hardcoded at the `start_writer` call site in both `ipfix_start` and the new `ipfix_local_start` (matches the existing behavior in `src/forwarding/ipfix_s3.rs:284`, currently a literal `1` inline in `BufferedWriterConfig`).
- `IpfixLocalConfig`'s flush-policy fields (`prefix`, `flush_threshold_bytes`, `flush_interval_secs`, `channel_capacity`, `max_buffer_rows`) reuse the exact same default functions as `IpfixS3Config` (`default_ipfix_s3_prefix`, `default_ipfix_flush_bytes`, `default_ipfix_flush_secs`, `default_ipfix_channel_capacity`, `default_ipfix_max_buffer_rows`) — no new default functions or values.
- No new Cargo dependencies. No new Cargo features.
- Follow the established naming convention: `ipfix_local_start` (not `local_ipfix_start`), `MultiIpfixHandler` (not `IpfixMultiHandler`).
- `IpfixConfig.local` field type is `Option<IpfixLocalConfig>`, default `None`, independent of `s3`.
- `ipfix_start` and the new `ipfix_local_start` must both call `crate::forwarding::buffered_writer::start_writer::<IpfixSink>(...)` directly — do NOT write a new `build_ipfix_handle` wrapper function; that per-source-wrapper pattern was hoisted away specifically so future sources wouldn't repeat it.
- `MultiIpfixHandler`'s record type is `Vec<FlowRecord>` (the whole batch `IpfixHandler::handle_flows` receives in one call), not a single `FlowRecord` — cloning the `Vec` once per destination (`Vec<T: Clone>` is itself `Clone`).
- Every new test function name must be distinct from existing ones in the same file.

---

### Task 1: Add `IpfixLocalConfig` to `src/config/mod.rs`

**Files:**
- Modify: `src/config/mod.rs` (add `IpfixLocalConfig` struct after `IpfixS3Config`, currently ending at line 682; add `local` field to `IpfixConfig` at lines 211-225 and its `Default` impl at lines 227-236)
- Test: same file's `#[cfg(test)] mod tests` block (existing IPFIX tests are near `default_ipfix_config_disabled_on_port_4739` at line 1051)

**Interfaces:**
- Consumes: `default_ipfix_s3_prefix`, `default_ipfix_flush_bytes`, `default_ipfix_flush_secs`, `default_ipfix_channel_capacity`, `default_ipfix_max_buffer_rows` (all already exist at lines 668-682).
- Produces: `pub struct IpfixLocalConfig { pub directory: PathBuf, pub prefix: String, pub flush_threshold_bytes: usize, pub flush_interval_secs: u64, pub channel_capacity: usize, pub max_buffer_rows: usize }`, and `IpfixConfig.local: Option<IpfixLocalConfig>` — both consumed by Task 2 (`ipfix_s3.rs`) and Task 3 (`main.rs`).

- [ ] **Step 1: Write the failing tests**

Add these four tests inside the existing `#[cfg(test)] mod tests { ... }` block in `src/config/mod.rs`, placed directly after the existing `default_ipfix_config_disabled_on_port_4739` test (search for that exact function name, near line 1051) — read the surrounding ~20 lines first to find a test named something like `ipfix_s3_flat_toml_deserializes_correctly` or similar and insert after the full IPFIX test group ends:

```rust
    #[test]
    fn ipfix_local_absent_gives_none() {
        let cfg = Config::default();
        assert!(
            cfg.ipfix.local.is_none(),
            "absent [ipfix.local] must deserialize to None"
        );
    }

    #[test]
    fn ipfix_local_config_deserializes_from_toml() {
        let toml_str = r#"
directory = "/var/log/logthing/ipfix"
prefix = "ipfix"
flush_threshold_bytes = 52428800
flush_interval_secs = 300
channel_capacity = 512
max_buffer_rows = 50000
"#;
        let cfg: IpfixLocalConfig = toml::from_str(toml_str).expect("deserialize");
        assert_eq!(
            cfg.directory,
            std::path::PathBuf::from("/var/log/logthing/ipfix")
        );
        assert_eq!(cfg.prefix, "ipfix");
        assert_eq!(cfg.flush_threshold_bytes, 52_428_800);
        assert_eq!(cfg.flush_interval_secs, 300);
        assert_eq!(cfg.channel_capacity, 512);
        assert_eq!(cfg.max_buffer_rows, 50_000);
    }

    #[test]
    fn ipfix_local_config_defaults_apply_when_only_directory_given() {
        let toml_str = r#"directory = "/data/ipfix""#;
        let cfg: IpfixLocalConfig = toml::from_str(toml_str).expect("deserialize");
        assert_eq!(cfg.prefix, "ipfix");
        assert_eq!(cfg.flush_threshold_bytes, 100 * 1024 * 1024);
        assert_eq!(cfg.flush_interval_secs, 900);
        assert_eq!(cfg.channel_capacity, 256);
        assert_eq!(cfg.max_buffer_rows, 100_000);
    }

    #[test]
    fn ipfix_s3_and_local_can_both_be_configured_simultaneously() {
        let toml_str = r#"
[ipfix]
enabled = true

[ipfix.s3]
endpoint = "http://minio:9000"
bucket = "b"
region = "us-east-1"
access_key = "k"
secret_key = "s"

[ipfix.local]
directory = "/data/ipfix"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("deserialize");
        assert!(
            cfg.ipfix.s3.is_some(),
            "s3 must deserialize when both present"
        );
        assert!(
            cfg.ipfix.local.is_some(),
            "local must deserialize when both present"
        );
    }
```

- [ ] **Step 2: Run tests to verify they fail (struct doesn't exist yet)**

Run: `cargo test --lib config::tests::ipfix_local -- --nocapture`
Expected: FAIL with a compile error — `IpfixLocalConfig` is not defined and `IpfixConfig` has no field `local`.

- [ ] **Step 3: Add `IpfixLocalConfig` and wire it into `IpfixConfig`**

In `src/config/mod.rs`, change the `IpfixConfig` struct (lines 211-225) from:

```rust
pub struct IpfixConfig {
    #[serde(default = "default_ipfix_enabled")]
    pub enabled: bool,

    #[serde(default = "default_ipfix_udp_port")]
    pub udp_port: u16,

    #[serde(default = "default_ipfix_bind_address")]
    pub bind_address: String,

    /// Optional S3 persistence for IPFIX flows.
    /// Absent from TOML → `None` → no S3 persistence (backward compatible).
    #[serde(default)]
    pub s3: Option<IpfixS3Config>,
}

impl Default for IpfixConfig {
    fn default() -> Self {
        Self {
            enabled: default_ipfix_enabled(),
            udp_port: default_ipfix_udp_port(),
            bind_address: default_ipfix_bind_address(),
            s3: None,
        }
    }
}
```

to:

```rust
pub struct IpfixConfig {
    #[serde(default = "default_ipfix_enabled")]
    pub enabled: bool,

    #[serde(default = "default_ipfix_udp_port")]
    pub udp_port: u16,

    #[serde(default = "default_ipfix_bind_address")]
    pub bind_address: String,

    /// Optional S3 persistence for IPFIX flows.
    /// Absent from TOML → `None` → no S3 persistence (backward compatible).
    #[serde(default)]
    pub s3: Option<IpfixS3Config>,

    /// Optional local-disk persistence. Absent from TOML → `None` → no
    /// persistence. Independent of `s3` — both may be configured
    /// simultaneously, in which case records are written to both.
    #[serde(default)]
    pub local: Option<IpfixLocalConfig>,
}

impl Default for IpfixConfig {
    fn default() -> Self {
        Self {
            enabled: default_ipfix_enabled(),
            udp_port: default_ipfix_udp_port(),
            bind_address: default_ipfix_bind_address(),
            s3: None,
            local: None,
        }
    }
}
```

Then, immediately after `fn default_ipfix_max_buffer_rows() -> usize { 100_000 }` (line 680-682), insert:

```rust

/// Per-source local-disk persistence config for the IPFIX listener. Mirrors
/// `IpfixS3Config`'s flush-policy shape (reusing the same default
/// functions), swapping the S3 connection for a root directory.
/// Independent of `s3`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IpfixLocalConfig {
    /// Root directory Parquet files are written under (created if missing).
    pub directory: PathBuf,
    /// Key prefix, slash-free (default: `"ipfix"` — same default as `ipfix.s3`).
    #[serde(default = "default_ipfix_s3_prefix")]
    pub prefix: String,
    /// Flush when estimated buffer bytes exceeds this (default: 100 MiB).
    #[serde(default = "default_ipfix_flush_bytes")]
    pub flush_threshold_bytes: usize,
    /// Flush after this many seconds regardless of buffer size (default: 900).
    #[serde(default = "default_ipfix_flush_secs")]
    pub flush_interval_secs: u64,
    /// Bounded channel capacity (default: 256).
    #[serde(default = "default_ipfix_channel_capacity")]
    pub channel_capacity: usize,
    /// Maximum buffered rows before hard cap kicks in (default: 100_000).
    #[serde(default = "default_ipfix_max_buffer_rows")]
    pub max_buffer_rows: usize,
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib config:: -- --nocapture`
Expected: PASS — all four new tests, plus every existing `config::tests::*` test (in particular `default_ipfix_config_disabled_on_port_4739` and any existing `ipfix_s3_*` tests, which must be unaffected).

- [ ] **Step 5: Commit**

```bash
git add src/config/mod.rs
git commit -m "feat(config): add IpfixLocalConfig, IpfixConfig.local

Mirrors SuricataLocalConfig's shape exactly: independent Option field,
reuses the existing ipfix.s3 default functions for its flush-policy
fields. Not yet wired to any writer — that's the next task."
```

---

### Task 2: Refactor `ipfix_s3.rs` — migrate `ipfix_start` to `start_writer`, add `ipfix_local_start` and `MultiIpfixHandler`

**Files:**
- Modify: `src/forwarding/ipfix_s3.rs` (add `#[derive(Default)]` to `IpfixSink` at line 201; replace `ipfix_start` at lines 269-292 to call `start_writer` directly instead of inlining `BufferedWriterConfig`/`FlushPolicy`; add `MultiIpfixHandler` and `ipfix_local_start`)
- Test: same file's `#[cfg(test)] mod tests` block (starts line 298)

**Interfaces:**
- Consumes: `IpfixLocalConfig` (Task 1), `crate::forwarding::buffered_writer::start_writer` (already hoisted, no action needed), `crate::forwarding::local_sink::LocalDiskSink`, `crate::ipfix::listener::IpfixHandler` trait (`async fn handle_flows(&self, flows: Vec<FlowRecord>, source: SocketAddr)`, `src/ipfix/listener.rs:28-30`).
- Produces: `pub fn ipfix_local_start(cfg: &IpfixLocalConfig, sink: Arc<LocalDiskSink>, source_stats: Arc<SourceHourlyStats>) -> (IpfixS3Handler, JoinHandle<()>)` and `pub struct MultiIpfixHandler(pub Vec<Arc<dyn IpfixHandler>>)` — both consumed by Task 3 (`main.rs`).

- [ ] **Step 1: Write the failing tests**

Add these tests inside the existing `#[cfg(test)] mod tests { ... }` block in `src/forwarding/ipfix_s3.rs`, placed directly after the existing `ipfix_sink_reports_into_shared_source_hourly_stats` test (the last test in the file, ending at line 926, right before the file's closing `}` at line 927):

```rust

    // -- ipfix_local_start wires handler and join handle --

    #[tokio::test]
    async fn ipfix_local_start_wires_handler_and_join_handle() {
        use crate::config::IpfixLocalConfig;
        use crate::forwarding::local_sink::LocalDiskSink;
        use crate::ipfix::listener::IpfixHandler;
        use std::net::SocketAddr;

        let dir = tempfile::tempdir().unwrap();
        let sink = Arc::new(
            LocalDiskSink::new(dir.path().to_path_buf())
                .await
                .expect("LocalDiskSink::new"),
        );
        let cfg = IpfixLocalConfig {
            directory: dir.path().to_path_buf(),
            prefix: "ipfix".to_string(),
            flush_threshold_bytes: 1, // flush on first push
            flush_interval_secs: 3600,
            channel_capacity: 256,
            max_buffer_rows: 100_000,
        };
        let (handler, join_handle) = ipfix_local_start(
            &cfg,
            sink,
            std::sync::Arc::new(crate::stats::SourceHourlyStats::new()),
        );

        let src: SocketAddr = "127.0.0.1:4739".parse().unwrap();
        handler
            .handle_flows(
                vec![make_flow_record(
                    Some("10.0.0.1"),
                    Some(42),
                    serde_json::json!({}),
                )],
                src,
            )
            .await;

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        drop(handler);
        tokio::time::timeout(std::time::Duration::from_secs(5), join_handle)
            .await
            .expect("writer task must exit within 5s")
            .expect("writer task must not panic");

        let ipfix_dir = dir.path().join("ipfix");
        let mut found = false;
        for entry in walkdir_flat(&ipfix_dir) {
            if entry.extension().is_some_and(|e| e == "parquet") {
                found = true;
                break;
            }
        }
        assert!(found, "expected at least one Parquet file under {ipfix_dir:?}");
    }

    /// Minimal recursive walk — IPFIX's key layout nests under year=/month=/day=/,
    /// so a flat `read_dir` on the prefix directory won't find the file directly.
    fn walkdir_flat(root: &std::path::Path) -> Vec<std::path::PathBuf> {
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

    // -- MultiIpfixHandler tests --

    #[tokio::test]
    async fn multi_ipfix_handler_fans_out_to_every_inner_handler() {
        use crate::ipfix::listener::IpfixHandler;
        use std::net::SocketAddr;
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct CountingHandler(Arc<AtomicUsize>);
        #[async_trait::async_trait]
        impl IpfixHandler for CountingHandler {
            async fn handle_flows(&self, _flows: Vec<FlowRecord>, _source: SocketAddr) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let count_a = Arc::new(AtomicUsize::new(0));
        let count_b = Arc::new(AtomicUsize::new(0));
        let multi = MultiIpfixHandler(vec![
            Arc::new(CountingHandler(count_a.clone())),
            Arc::new(CountingHandler(count_b.clone())),
        ]);

        let src: SocketAddr = "127.0.0.1:4739".parse().unwrap();
        multi
            .handle_flows(
                vec![make_flow_record(Some("10.0.0.1"), Some(1), serde_json::json!({}))],
                src,
            )
            .await;

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
    async fn multi_ipfix_handler_survives_one_inner_handler_dropping() {
        use crate::ipfix::listener::IpfixHandler;
        use metrics::set_default_local_recorder;
        use metrics_util::CompositeKey;
        use metrics_util::MetricKind;
        use metrics_util::debugging::DebuggingRecorder;
        use std::net::SocketAddr;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let sink = unreachable_sink().await;
        let cfg = IpfixS3Config {
            connection: crate::config::S3ConnectionConfig {
                endpoint: "http://127.0.0.1:1".to_string(),
                bucket: "test-bucket".to_string(),
                region: "us-east-1".to_string(),
                access_key: "AKIATEST".to_string(),
                secret_key: "SECRETTEST".to_string(),
            },
            prefix: "ipfix".to_string(),
            flush_threshold_bytes: 1,
            flush_interval_secs: 3600,
            channel_capacity: 1,
            max_buffer_rows: 1,
        };
        let (struggling_handler, _jh) = ipfix_start(
            &cfg,
            sink,
            std::sync::Arc::new(crate::stats::SourceHourlyStats::new()),
        );

        use std::sync::atomic::{AtomicUsize, Ordering};
        struct CountingHandler(Arc<AtomicUsize>);
        #[async_trait::async_trait]
        impl IpfixHandler for CountingHandler {
            async fn handle_flows(&self, _flows: Vec<FlowRecord>, _source: SocketAddr) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let healthy_count = Arc::new(AtomicUsize::new(0));
        let multi = MultiIpfixHandler(vec![
            Arc::new(struggling_handler),
            Arc::new(CountingHandler(healthy_count.clone())),
        ]);

        let src: SocketAddr = "127.0.0.1:4739".parse().unwrap();
        for i in 0..20 {
            multi
                .handle_flows(
                    vec![make_flow_record(None, None, serde_json::json!({"i": i}))],
                    src,
                )
                .await;
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
                    metrics::Label::new("source", "ipfix"),
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

Run: `cargo test --lib forwarding::ipfix_s3::tests::ipfix_local_start_wires -- --nocapture`
Expected: FAIL with a compile error — `ipfix_local_start` and `MultiIpfixHandler` are not defined.

- [ ] **Step 3: Add `#[derive(Default)]` to `IpfixSink`, migrate `ipfix_start` to `start_writer`, add `MultiIpfixHandler` and `ipfix_local_start`**

Change `IpfixSink`'s declaration (line 201) from:

```rust
pub struct IpfixSink;
```

to:

```rust
#[derive(Default)]
pub struct IpfixSink;
```

Replace the entire block from the `// IpfixS3Handler — type alias + IpfixHandler impl` section comment (line 231) through the end of `ipfix_start` (line 292) — i.e. replace this:

```rust
// ---------------------------------------------------------------------------
// IpfixS3Handler — type alias + IpfixHandler impl
// ---------------------------------------------------------------------------

/// `IpfixS3Handler` is a thin alias for the generic `ParquetWriterHandle<IpfixSink>`.
pub type IpfixS3Handler = crate::forwarding::buffered_writer::ParquetWriterHandle<IpfixSink>;

#[async_trait::async_trait]
impl crate::ipfix::listener::IpfixHandler
    for crate::forwarding::buffered_writer::ParquetWriterHandle<IpfixSink>
{
    async fn handle_flows(&self, flows: Vec<FlowRecord>, source: std::net::SocketAddr) {
        let count = flows.len() as u64;
        match self.try_send(flows) {
            Ok(()) => {}
            Err(_dropped) => {
                // parquet_s3_dropped{source="ipfix"} is already incremented by try_send;
                // just warn here.
                tracing::warn!(
                    "IPFIX S3 channel full; dropped {} flows from {}",
                    count,
                    source
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ipfix_start — convenience constructor
// ---------------------------------------------------------------------------

/// Construct an `IpfixS3Handler` (i.e. `ParquetWriterHandle<IpfixSink>`) from an
/// `IpfixS3Config` and a pre-built `S3Sink`.
///
/// Returns `(handler, writer_task_handle)`. The caller should retain the `JoinHandle`
/// and await it during graceful shutdown, after all `Arc<dyn IpfixHandler>` references
/// have been dropped so the channel closes and the final flush fires.
pub fn ipfix_start(
    cfg: &IpfixS3Config,
    s3: std::sync::Arc<crate::forwarding::s3_sink::S3Sink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
) -> (IpfixS3Handler, tokio::task::JoinHandle<()>) {
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
        max_partitions: 1,
    };
    let policy = FlushPolicy {
        max_rows: cfg.max_buffer_rows,
        max_bytes: cfg.flush_threshold_bytes,
        interval: std::time::Duration::from_secs(cfg.flush_interval_secs),
    };
    ParquetWriterHandle::start_with_stats(IpfixSink, s3, bwc, policy, source_stats)
}
```

with this:

```rust
// ---------------------------------------------------------------------------
// IpfixS3Handler — type alias + IpfixHandler impl
// ---------------------------------------------------------------------------

/// `IpfixS3Handler` is a thin alias for the generic `ParquetWriterHandle<IpfixSink>`.
pub type IpfixS3Handler = crate::forwarding::buffered_writer::ParquetWriterHandle<IpfixSink>;

#[async_trait::async_trait]
impl crate::ipfix::listener::IpfixHandler
    for crate::forwarding::buffered_writer::ParquetWriterHandle<IpfixSink>
{
    async fn handle_flows(&self, flows: Vec<FlowRecord>, source: std::net::SocketAddr) {
        let count = flows.len() as u64;
        match self.try_send(flows) {
            Ok(()) => {}
            Err(_dropped) => {
                // parquet_s3_dropped{source="ipfix"} is already incremented by try_send;
                // just warn here.
                tracing::warn!(
                    "IPFIX S3 channel full; dropped {} flows from {}",
                    count,
                    source
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// MultiIpfixHandler — fan-out to multiple destinations
// ---------------------------------------------------------------------------

/// Fans out each flow batch to every configured handler. Used only when both
/// `.s3` and `.local` persistence resolve to a live handler for the same
/// run, so each destination keeps its own independent buffer, flush policy,
/// backpressure, and hard cap (no shared state between destinations).
pub struct MultiIpfixHandler(pub Vec<std::sync::Arc<dyn crate::ipfix::listener::IpfixHandler>>);

#[async_trait::async_trait]
impl crate::ipfix::listener::IpfixHandler for MultiIpfixHandler {
    async fn handle_flows(&self, flows: Vec<FlowRecord>, source: std::net::SocketAddr) {
        for handler in &self.0 {
            handler.handle_flows(flows.clone(), source).await;
        }
    }
}

// ---------------------------------------------------------------------------
// ipfix_start / ipfix_local_start — convenience constructors
// ---------------------------------------------------------------------------

/// Construct an `IpfixS3Handler` (i.e. `ParquetWriterHandle<IpfixSink>`) from an
/// `IpfixS3Config` and a pre-built `S3Sink`.
///
/// Returns `(handler, writer_task_handle)`. The caller should retain the `JoinHandle`
/// and await it during graceful shutdown, after all `Arc<dyn IpfixHandler>` references
/// have been dropped so the channel closes and the final flush fires.
pub fn ipfix_start(
    cfg: &IpfixS3Config,
    s3: std::sync::Arc<crate::forwarding::s3_sink::S3Sink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
) -> (IpfixS3Handler, tokio::task::JoinHandle<()>) {
    crate::forwarding::buffered_writer::start_writer::<IpfixSink>(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        cfg.flush_threshold_bytes,
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        1, // IPFIX is single-partition
        s3,
        source_stats,
    )
}

/// Construct an `IpfixS3Handler` from an `IpfixLocalConfig` and a pre-built
/// `LocalDiskSink`. Structurally identical to `ipfix_start`, writing to local
/// disk instead of S3 — same `IpfixSink` adapter, same buffering/flush/cap
/// machinery, same S3-key-shaped relative path layout on disk.
pub fn ipfix_local_start(
    cfg: &crate::config::IpfixLocalConfig,
    sink: std::sync::Arc<crate::forwarding::local_sink::LocalDiskSink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
) -> (IpfixS3Handler, tokio::task::JoinHandle<()>) {
    crate::forwarding::buffered_writer::start_writer::<IpfixSink>(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        cfg.flush_threshold_bytes,
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        1, // IPFIX is single-partition
        sink,
        source_stats,
    )
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib forwarding::ipfix_s3:: -- --nocapture`
Expected: PASS — the 3 new tests, plus every pre-existing test in this file (in particular `writer_push_accumulates_and_bounded_under_outage`, `handler_overflow_increments_dropped_counter`, `channel_capacity_parameter_is_wired`, which must be unaffected by the `ipfix_start` migration to `start_writer`).

- [ ] **Step 5: Commit**

```bash
git add src/forwarding/ipfix_s3.rs
git commit -m "feat(forwarding): add ipfix_local_start + MultiIpfixHandler

ipfix_start now calls the shared start_writer<IpfixSink> directly instead
of inlining BufferedWriterConfig/FlushPolicy construction — no new
build_ipfix_handle wrapper, per the prior hoist's intent. MultiIpfixHandler
fans out Vec<FlowRecord> batches to both destinations when .s3 and .local
are both configured. Not yet wired into main.rs."
```

---

### Task 3: Wire `main.rs`'s IPFIX block to support `.s3` + `.local` fan-out

**Files:**
- Modify: `src/main.rs:154-193` (the entire `if config.ipfix.enabled { ... }` block)

**Interfaces:**
- Consumes: `ipfix_local_start`, `MultiIpfixHandler` (Task 2), `IpfixConfig.local` (Task 1), `crate::forwarding::local_sink::LocalDiskSink::new` (already used identically by the Zeek/Suricata blocks).
- Produces: nothing new for later tasks.

- [ ] **Step 1: Replace the IPFIX block**

In `src/main.rs`, replace this entire block (lines 154-193):

```rust
    // -----------------------------------------------------------------------
    // Start IPFIX listener if enabled
    // -----------------------------------------------------------------------
    if config.ipfix.enabled {
        let ipfix_config_clone = config.clone();
        let ipfix_shutdown_rx = shutdown_rx.clone();

        let ipfix_handler: Arc<dyn ipfix::listener::IpfixHandler> =
            if let Some(s3_cfg) = ipfix_config_clone.ipfix.s3.as_ref() {
                match forwarding::s3_sink::S3Sink::from_connection(&s3_cfg.connection).await {
                    Ok(sink) => {
                        let (handler, writer_handle) = forwarding::ipfix_s3::ipfix_start(
                            s3_cfg,
                            Arc::new(sink),
                            source_stats.clone(),
                        );
                        writer_handles.push(writer_handle);
                        Arc::new(handler)
                    }
                    Err(e) => {
                        error!(
                            "Failed to create S3Sink for IPFIX persistence, \
                                 falling back to DefaultIpfixHandler: {e}"
                        );
                        Arc::new(ipfix::listener::DefaultIpfixHandler)
                    }
                }
            } else {
                Arc::new(ipfix::listener::DefaultIpfixHandler)
            };

        let listener_config = ipfix::listener::IpfixListenerConfig {
            udp_port: ipfix_config_clone.ipfix.udp_port,
            bind_address: ipfix_config_clone.ipfix.bind_address.clone(),
        };
        let handle = tokio::spawn(async move {
            let listener = ipfix::listener::IpfixListener::new(listener_config, ipfix_handler);
            if let Err(e) = listener.start_with_shutdown(ipfix_shutdown_rx).await {
                error!("IPFIX listener error: {}", e);
            }
        });
        listener_handles.push(handle);
    }
```

with this:

```rust
    // -----------------------------------------------------------------------
    // Start IPFIX listener if enabled
    // -----------------------------------------------------------------------
    if config.ipfix.enabled {
        let ipfix_config_clone = config.clone();
        let ipfix_shutdown_rx = shutdown_rx.clone();

        let mut ipfix_handlers: Vec<Arc<dyn ipfix::listener::IpfixHandler>> = Vec::new();

        if let Some(s3_cfg) = ipfix_config_clone.ipfix.s3.as_ref() {
            match forwarding::s3_sink::S3Sink::from_connection(&s3_cfg.connection).await {
                Ok(sink) => {
                    let (handler, writer_handle) = forwarding::ipfix_s3::ipfix_start(
                        s3_cfg,
                        Arc::new(sink),
                        source_stats.clone(),
                    );
                    writer_handles.push(writer_handle);
                    ipfix_handlers.push(Arc::new(handler));
                }
                Err(e) => {
                    error!(
                        "Failed to create S3Sink for IPFIX persistence, \
                             skipping S3 target: {e}"
                    );
                }
            }
        }

        if let Some(local_cfg) = ipfix_config_clone.ipfix.local.as_ref() {
            match forwarding::local_sink::LocalDiskSink::new(local_cfg.directory.clone()).await {
                Ok(sink) => {
                    let (handler, writer_handle) = forwarding::ipfix_s3::ipfix_local_start(
                        local_cfg,
                        Arc::new(sink),
                        source_stats.clone(),
                    );
                    writer_handles.push(writer_handle);
                    ipfix_handlers.push(Arc::new(handler));
                }
                Err(e) => {
                    error!(
                        "Failed to create LocalDiskSink for IPFIX persistence, \
                             skipping local target: {e}"
                    );
                }
            }
        }

        let ipfix_handler: Arc<dyn ipfix::listener::IpfixHandler> = match ipfix_handlers.len() {
            0 => Arc::new(ipfix::listener::DefaultIpfixHandler),
            1 => ipfix_handlers.into_iter().next().unwrap(),
            _ => Arc::new(forwarding::ipfix_s3::MultiIpfixHandler(ipfix_handlers)),
        };

        let listener_config = ipfix::listener::IpfixListenerConfig {
            udp_port: ipfix_config_clone.ipfix.udp_port,
            bind_address: ipfix_config_clone.ipfix.bind_address.clone(),
        };
        let handle = tokio::spawn(async move {
            let listener = ipfix::listener::IpfixListener::new(listener_config, ipfix_handler);
            if let Err(e) = listener.start_with_shutdown(ipfix_shutdown_rx).await {
                error!("IPFIX listener error: {}", e);
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

- [ ] **Step 4: Commit**

```bash
git add src/main.rs
git commit -m "feat(main): wire ipfix.local alongside ipfix.s3, fan out via MultiIpfixHandler when both configured

Mirrors the existing Zeek/Suricata blocks' Vec<Arc<dyn Handler>> +
match-on-length pattern exactly."
```

---

### Task 4: Add `tests/ipfix_local_integration.rs` — real Parquet round-trip

**Files:**
- Create: `tests/ipfix_local_integration.rs`

**Why this satisfies the integration-test tier:** Drives the real `ipfix_local_start` → `LocalDiskSink` → real Parquet-file-on-disk path, then reads the file back with a real Parquet reader — no mocks. Needs no external service, so it runs unconditionally in CI, matching `tests/zeek_local_integration.rs` and `tests/suricata_local_integration.rs`.

**Interfaces:**
- Consumes: `logthing::config::IpfixLocalConfig` (Task 1), `logthing::forwarding::local_sink::LocalDiskSink`, `logthing::forwarding::ipfix_s3::ipfix_local_start` (Task 2), `logthing::ipfix::FlowRecord`, `logthing::ipfix::listener::IpfixHandler`.

- [ ] **Step 1: Write the test**

Create `tests/ipfix_local_integration.rs`:

```rust
//! Integration test: FlowRecord batches → ipfix_local_start → real Parquet
//! files on local disk, read back with a real Parquet reader.
//!
//! Unlike `ipfix_s3_integration.rs` (gated on a running MinIO), this test
//! needs no external service — local disk is always available — so it runs
//! unconditionally in CI.

use logthing::config::IpfixLocalConfig;
use logthing::forwarding::local_sink::LocalDiskSink;
use logthing::forwarding::ipfix_s3::ipfix_local_start;
use logthing::ipfix::FlowRecord;
use logthing::ipfix::listener::IpfixHandler;
use std::sync::Arc;

fn make_flow_record(src_addr: &str, octet_count: u64) -> FlowRecord {
    FlowRecord {
        observation_domain_id: 1,
        template_id: 256,
        protocol_version: 10,
        exporter: "10.0.0.1".parse().unwrap(),
        export_time: chrono::Utc::now(),
        src_addr: Some(src_addr.parse().unwrap()),
        dst_addr: Some("192.168.1.1".parse().unwrap()),
        src_port: Some(1234),
        dst_port: Some(80),
        ip_protocol: Some(6),
        octet_delta_count: Some(octet_count),
        packet_delta_count: Some(10),
        flow_start: None,
        flow_end: None,
        tcp_flags: Some(0x02),
        input_interface: Some(1),
        output_interface: Some(2),
        extra: serde_json::json!({}),
    }
}

#[tokio::test]
async fn ipfix_flows_appear_as_parquet_on_local_disk() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sink = Arc::new(
        LocalDiskSink::new(dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new"),
    );
    let cfg = IpfixLocalConfig {
        directory: dir.path().to_path_buf(),
        prefix: "ipfix".to_string(),
        max_buffer_rows: 1, // flush immediately on first push
        flush_threshold_bytes: 1,
        flush_interval_secs: 3600,
        channel_capacity: 256,
    };

    let (handler, _writer_task) = ipfix_local_start(
        &cfg,
        sink,
        Arc::new(logthing::stats::SourceHourlyStats::new()),
    );

    let src: std::net::SocketAddr = "127.0.0.1:4739".parse().unwrap();
    let flows = vec![
        make_flow_record("10.1.2.3", 1024),
        make_flow_record("10.1.2.4", 2048),
    ];
    handler.handle_flows(flows, src).await;

    // Give the background task time to flush.
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    let ipfix_dir = dir.path().join("ipfix");
    assert!(ipfix_dir.is_dir(), "expected {ipfix_dir:?} to exist");

    let parquet_files: Vec<_> = walk_all_files(&ipfix_dir)
        .into_iter()
        .filter(|p| p.extension().is_some_and(|ext| ext == "parquet"))
        .collect();
    assert!(
        !parquet_files.is_empty(),
        "expected at least one Parquet file under {ipfix_dir:?}"
    );

    let file_path = &parquet_files[0];
    let bytes = std::fs::read(file_path).expect("read parquet file");

    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    let builder = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(bytes))
        .expect("parquet builder");
    let schema = builder.schema().clone();
    for col in ["observation_domain_id", "exporter", "src_addr", "octet_delta_count", "extra"] {
        assert!(
            schema.field_with_name(col).is_ok(),
            "expected column '{col}' in flow_record_schema"
        );
    }

    let mut reader = builder.build().expect("parquet reader");
    let rb = reader.next().expect("at least one batch").expect("batch ok");
    assert_eq!(rb.num_rows(), 2);

    use arrow::array::StringArray;
    let src_addr_col = rb
        .column_by_name("src_addr")
        .unwrap()
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    assert_eq!(src_addr_col.value(0), "10.1.2.3");
    assert_eq!(src_addr_col.value(1), "10.1.2.4");

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

Run: `cargo test --test ipfix_local_integration -- --nocapture`
Expected: PASS — `test ipfix_flows_appear_as_parquet_on_local_disk ... ok`.

- [ ] **Step 3: Run the full test suite, fmt, and clippy**

Run: `cargo test --quiet` — expected: PASS, 0 failures.
Run: `cargo fmt --all -- --check` — expected: no output.
Run: `cargo clippy --all-targets --quiet -- -D warnings` — expected: no output.

- [ ] **Step 4: Commit**

```bash
git add tests/ipfix_local_integration.rs
git commit -m "test(ipfix): integration test proving real Parquet round-trip through LocalDiskSink

Mirrors tests/suricata_local_integration.rs's pattern."
```

---

### Task 5: Add e2e local-disk verifier for IPFIX

**Files:**
- Create: `tests/e2e/simulation-environment/ipfix-local-verifier/Dockerfile`
- Create: `tests/e2e/simulation-environment/ipfix-local-verifier/entrypoint.py`
- Modify: `tests/e2e/simulation-environment/docker-compose.yml` (add `ipfix-local-data` volume, mount it into `logthing`, add `ipfix-local-verifier` service)
- Modify: `tests/e2e/simulation-environment/config/logthing.toml` (add `[ipfix.local]` section)
- Modify: `tests/e2e/simulation-environment/run.sh` (add the `ipfix-local-verifier` invocation)

**Why this task exists for IPFIX but didn't for Suricata:** IPFIX already has full e2e docker-compose coverage (`ipfix-generator` + `ipfix-s3-verifier`), unlike Suricata (which had none, so its local-disk plan explicitly scoped e2e out as a pre-existing gap). Since the generator and volume-mount pattern already exist for IPFIX, adding a `.local` verifier is cheap and follows the exact precedent `zeek-local-verifier` already set.

- [ ] **Step 1: Add `[ipfix.local]` to the e2e config**

In `tests/e2e/simulation-environment/config/logthing.toml`, change:

```toml
[ipfix]
enabled = true
udp_port = 4739

[ipfix.s3]
endpoint   = "http://minio:9000"
bucket     = "ipfix-flows"
region     = "us-east-1"
access_key = "miniouser"
secret_key = "miniopassword"
prefix     = "ipfix"
flush_threshold_bytes = 1
flush_interval_secs   = 5
```

to:

```toml
[ipfix]
enabled = true
udp_port = 4739

[ipfix.s3]
endpoint   = "http://minio:9000"
bucket     = "ipfix-flows"
region     = "us-east-1"
access_key = "miniouser"
secret_key = "miniopassword"
prefix     = "ipfix"
flush_threshold_bytes = 1
flush_interval_secs   = 5

[ipfix.local]
directory             = "/var/log/ipfix-local"
prefix                = "ipfix"
flush_threshold_bytes = 1
flush_interval_secs   = 5
```

- [ ] **Step 2: Add the `ipfix-local-data` volume and mount it into `logthing`**

In `tests/e2e/simulation-environment/docker-compose.yml`, find the `logthing` service's `volumes:` block (near the top of the file):

```yaml
    volumes:
      - ./config/logthing.toml:/etc/logthing/config.toml:ro
      - zeek-local-data:/var/log/zeek-local
```

change to:

```yaml
    volumes:
      - ./config/logthing.toml:/etc/logthing/config.toml:ro
      - zeek-local-data:/var/log/zeek-local
      - ipfix-local-data:/var/log/ipfix-local
```

Find the `volumes:` top-level section at the bottom of the file:

```yaml
volumes:
  zeek-local-data:
```

change to:

```yaml
volumes:
  zeek-local-data:
  ipfix-local-data:
```

- [ ] **Step 3: Add the `ipfix-local-verifier` Dockerfile**

Create `tests/e2e/simulation-environment/ipfix-local-verifier/Dockerfile`:

```dockerfile
FROM python:3.12-slim

RUN pip install --no-cache-dir pyarrow

COPY ipfix-local-verifier/entrypoint.py /entrypoint.py

ENTRYPOINT ["python3", "/entrypoint.py"]
```

- [ ] **Step 4: Add the `ipfix-local-verifier` entrypoint script**

Create `tests/e2e/simulation-environment/ipfix-local-verifier/entrypoint.py`:

```python
#!/usr/bin/env python3
"""
IPFIX local-disk verifier for E2E testing.

Walks a local directory tree (shared volume with the `logthing` container)
for Parquet objects under ipfix/, downloads each, and validates schema and
row count. Mirrors ipfix-s3-verifier/entrypoint.py's checks, applied to the
local-disk target instead of MinIO.
"""

import glob
import os
import sys
import time

import pyarrow.parquet as pq

IPFIX_LOCAL_DIR = os.environ.get("IPFIX_LOCAL_DIR", "/var/log/ipfix-local")
TIMEOUT = int(os.environ.get("E2E_TIMEOUT_SECS", "60"))
MIN_ROWS = int(os.environ.get("EXPECTED_EVENT_TOTAL", "5"))

REQUIRED_COLUMNS = [
    "observation_domain_id",
    "template_id",
    "protocol_version",
    "exporter",
    "export_time",
    "src_addr",
    "dst_addr",
    "src_port",
    "dst_port",
    "ip_protocol",
    "octet_delta_count",
    "packet_delta_count",
    "flow_start",
    "flow_end",
    "tcp_flags",
    "input_interface",
    "output_interface",
    "extra",
]


def scan_dir():
    """Read every .parquet file under IPFIX_LOCAL_DIR/ipfix/**,
    return (total_rows, union_of_columns, file_count)."""
    pattern = os.path.join(IPFIX_LOCAL_DIR, "ipfix", "**", "*.parquet")
    files = glob.glob(pattern, recursive=True)
    total_rows = 0
    columns = set()
    for path in files:
        table = pq.read_table(path)
        total_rows += table.num_rows
        columns |= set(table.schema.names)
    return total_rows, columns, len(files)


def main():
    deadline = time.time() + TIMEOUT
    total_rows, columns, n = 0, set(), 0
    while time.time() < deadline:
        total_rows, columns, n = scan_dir()
        if total_rows >= MIN_ROWS:
            break
        time.sleep(3)

    missing = [c for c in REQUIRED_COLUMNS if c not in columns]
    if missing:
        print(
            f"ERROR: missing columns: {missing} (saw {sorted(columns)} across {n} file(s))",
            file=sys.stderr,
        )
        sys.exit(1)
    if total_rows < MIN_ROWS:
        print(
            f"ERROR: expected >= {MIN_ROWS} rows, got {total_rows} across {n} file(s) "
            f"within {TIMEOUT}s",
            file=sys.stderr,
        )
        sys.exit(1)

    print(
        f"OK: {total_rows} row(s) across {n} file(s), {len(columns)} column(s): "
        f"{sorted(columns)}"
    )
    print("IPFIX local-disk verifier succeeded")
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(0)


if __name__ == "__main__":
    main()
```

- [ ] **Step 5: Add the `ipfix-local-verifier` service to docker-compose**

In `tests/e2e/simulation-environment/docker-compose.yml`, immediately after the existing `ipfix-s3-verifier` service block (ends around line 328, right before `zeek-generator`), insert:

```yaml
  ipfix-local-verifier:
    build:
      context: .
      dockerfile: ipfix-local-verifier/Dockerfile
    environment:
      - IPFIX_LOCAL_DIR=/var/log/ipfix-local
      - EXPECTED_EVENT_TOTAL=5
      - E2E_TIMEOUT_SECS=60
    volumes:
      - ipfix-local-data:/var/log/ipfix-local:ro
    depends_on:
      - ipfix-generator
      - logthing
    networks:
      - e2e
```

- [ ] **Step 6: Add the invocation to `run.sh`**

In `tests/e2e/simulation-environment/run.sh`, find:

```bash
echo ""
echo "========================================"
echo "Running IPFIX E2E Tests"
echo "========================================"
docker compose -f "$COMPOSE_FILE" run --rm ipfix-generator
docker compose -f "$COMPOSE_FILE" run --rm ipfix-s3-verifier
echo "IPFIX E2E Tests Completed Successfully"
```

replace with:

```bash
echo ""
echo "========================================"
echo "Running IPFIX E2E Tests"
echo "========================================"
docker compose -f "$COMPOSE_FILE" run --rm ipfix-generator
docker compose -f "$COMPOSE_FILE" run --rm ipfix-s3-verifier
docker compose -f "$COMPOSE_FILE" run --rm ipfix-local-verifier
echo "IPFIX E2E Tests Completed Successfully"
```

- [ ] **Step 7: Verify the compose file is at least syntactically valid**

Run: `docker compose -f tests/e2e/simulation-environment/docker-compose.yml config --quiet`
Expected: no output (valid YAML/compose syntax). This does NOT run the e2e suite (that requires Docker infrastructure and takes significant time) — it only validates the compose file parses. Note explicitly in your report that the actual e2e run was not executed, matching how Task 2 of the prior `run.sh` fix was verified (syntax/placement, not full execution).

- [ ] **Step 8: Commit**

```bash
git add tests/e2e/simulation-environment/ipfix-local-verifier/ tests/e2e/simulation-environment/docker-compose.yml tests/e2e/simulation-environment/config/logthing.toml tests/e2e/simulation-environment/run.sh
git commit -m "test(e2e): add ipfix-local-verifier alongside existing ipfix-generator/s3-verifier

IPFIX already had full e2e docker-compose coverage, unlike Suricata (which
had none and explicitly deferred e2e as a pre-existing gap). Mirrors
zeek-local-verifier's pattern: walk a shared volume for Parquet files,
validate schema and row count."
```

---

## Post-plan note for the final whole-branch review

When the final reviewer looks at this branch as a whole, it should confirm:
1. `ipfix_s3.rs`'s migration of `ipfix_start` to `start_writer` did not change its observable behavior for existing callers — `writer_push_accumulates_and_bounded_under_outage`, `handler_overflow_increments_dropped_counter`, and `channel_capacity_parameter_is_wired` (all pre-existing tests) must still pass unmodified.
2. The `main.rs` IPFIX block now structurally matches the Zeek/Suricata blocks — same `Vec<Arc<dyn Handler>>` collection, same `match .len()` resolution, same per-branch error-handling (log-and-skip-that-target, not log-and-fall-back-to-Default).
3. `IpfixConfig`'s new `local` field does not change TOML-parsing behavior for existing `[ipfix]`/`[ipfix.s3]`-only configs.
4. No new `build_ipfix_handle` function was introduced anywhere — both `ipfix_start` and `ipfix_local_start` call `start_writer<IpfixSink>` directly.
