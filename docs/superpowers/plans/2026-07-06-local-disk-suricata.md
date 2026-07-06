# Suricata Local-Disk Persistence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `LocalDiskSink` support (currently Zeek-only) to Suricata, so `[suricata.local]` can persist EVE JSON records to local disk as Parquet, independently of or alongside `[suricata.s3]`.

**Architecture:** Mirror `src/forwarding/zeek_s3.rs`'s existing `.s3`/`.local` pattern exactly: extract a shared `build_suricata_handle` helper (config → `ParquetWriterHandle<SuricataSink>`) called by both `suricata_start` (S3) and a new `suricata_local_start` (local disk); add a `MultiSuricataHandler` fan-out wrapper for when both resolve simultaneously; wire `main.rs`'s Suricata block to build a `Vec<Arc<dyn SuricataHandler>>` the same way the Zeek block already does.

**Tech Stack:** Rust, tokio, arrow/parquet, existing `UploadSink`/`ParquetSink` traits — no new dependencies.

## Global Constraints

- `max_partitions` for Suricata is a hardcoded constant, `DEFAULT_MAX_SURICATA_PARTITIONS = 256` — do not make it configurable; this matches the existing S3-only behavior exactly (see `src/forwarding/suricata_s3.rs:139`).
- `SuricataLocalConfig`'s flush-policy fields (`prefix`, `flush_threshold_bytes`, `flush_interval_secs`, `channel_capacity`, `max_buffer_rows`) reuse the exact same default functions as `SuricataS3Config` (`default_suricata_s3_prefix`, `default_suricata_flush_bytes`, `default_suricata_flush_secs`, `default_suricata_channel_capacity`, `default_suricata_max_buffer_rows`) — do not write new default functions or new default values.
- No new Cargo dependencies. No new Cargo features.
- Follow `src/forwarding/zeek_s3.rs`'s exact naming convention: `build_suricata_handle` (not `make_...`/`create_...`), `suricata_local_start` (not `local_suricata_start`), `MultiSuricataHandler` (not `SuricataMultiHandler`).
- `SuricataConfig.local` field type is `Option<SuricataLocalConfig>`, default `None`, independent of `s3` — both may be configured simultaneously.
- Every new test function name must be distinct from existing ones in the same file (the file already has `suricata_start_wires_handler_and_join_handle` — do not shadow it).

---

### Task 1: Hoist `unused_s3_connection_placeholder` into a shared location

**Files:**
- Modify: `src/forwarding/buffered_writer.rs` (add the function after `BufferedWriterConfig`, around line 136)
- Modify: `src/forwarding/zeek_s3.rs:180-194` (delete the private copy, use the shared one)
- Test: no new test file — existing Zeek tests (`zeek_local_start_wires_handler_and_join_handle` et al.) already exercise this function indirectly; this task must not break them.

**Why first:** `suricata_local_start` (Task 4) needs this same helper. Rather than adding a second private copy in `suricata_s3.rs`, hoist it once so both Zeek and Suricata call the same `pub(crate)` function. This is a pure refactor — no behavior change.

**Interfaces:**
- Produces: `pub(crate) fn unused_s3_connection_placeholder() -> crate::config::S3ConnectionConfig` in `src/forwarding/buffered_writer.rs`, callable from any sibling module as `crate::forwarding::buffered_writer::unused_s3_connection_placeholder()`.

- [ ] **Step 1: Add the shared function to `buffered_writer.rs`**

Insert immediately after the `BufferedWriterConfig` struct's closing brace (after line 136, before the `// PartitionBuffer` section comment at line 138):

```rust
/// `BufferedWriterConfig.connection` is never read by the generic writer once
/// a pre-built sink is supplied — only `prefix`/`max_buffer_rows`/etc. are used
/// in `push`/`flush_partition`/`drop_oldest_to_cap`. For a local-disk-only
/// pipeline there is no S3 connection to report, so this fills the field with
/// harmless placeholder values rather than changing its required type (which
/// would ripple into every other source's `BufferedWriterConfig` literal).
pub(crate) fn unused_s3_connection_placeholder() -> crate::config::S3ConnectionConfig {
    crate::config::S3ConnectionConfig {
        endpoint: String::new(),
        bucket: String::new(),
        region: String::new(),
        access_key: String::new(),
        secret_key: String::new(),
    }
}
```

- [ ] **Step 2: Remove the private copy from `zeek_s3.rs` and use the shared one**

In `src/forwarding/zeek_s3.rs`, delete lines 180-194 (the doc comment and `fn unused_s3_connection_placeholder` block) entirely — from the `/// \`BufferedWriterConfig.connection\` is never read...` comment through the closing `}` of the function.

Then in `build_zeek_handle` (around line 216-217), change:

```rust
    let bwc = BufferedWriterConfig {
        connection: unused_s3_connection_placeholder(),
```

to:

```rust
    let bwc = BufferedWriterConfig {
        connection: crate::forwarding::buffered_writer::unused_s3_connection_placeholder(),
```

- [ ] **Step 3: Build and run the existing Zeek test suite to confirm no regression**

Run: `cargo test --lib forwarding::zeek_s3:: -- --nocapture`
Expected: all existing tests in `zeek_s3.rs` still pass (in particular `zeek_local_start_wires_handler_and_join_handle`, `zeek_start_wires_handler_and_join_handle`, `multi_zeek_handler_fans_out_to_every_inner_handler`).

- [ ] **Step 4: Commit**

```bash
git add src/forwarding/buffered_writer.rs src/forwarding/zeek_s3.rs
git commit -m "refactor(forwarding): hoist unused_s3_connection_placeholder to buffered_writer

Suricata's upcoming local-disk support needs the same placeholder Zeek's
local-disk path already uses; share one pub(crate) copy instead of a
second private one."
```

---

### Task 2: Fix the pre-existing gap — `zeek-local-verifier` is never invoked in `run.sh`

**Files:**
- Modify: `tests/e2e/simulation-environment/run.sh`

**Why:** While reading the e2e harness to plan Suricata's local-disk test coverage, we found `zeek-local-verifier` is defined in `docker-compose.yml` (confirmed: `tests/e2e/simulation-environment/docker-compose.yml:361-374`, service exists, depends on `zeek-generator` and `logthing`, mounts the `zeek-local-data` volume read-only) but is never `docker compose run --rm`'d anywhere in `run.sh` — so Zeek's "local persists alongside s3" e2e check has never actually executed. This is a one-line, zero-risk fix, unrelated to Suricata itself but discovered in the course of this work — fixing it now rather than filing it and forgetting it.

**Interfaces:**
- Consumes: the existing `zeek-local-verifier` docker-compose service (unmodified).
- Produces: nothing new — this task only adds an invocation line.

- [ ] **Step 1: Add the missing invocation**

In `tests/e2e/simulation-environment/run.sh`, find this block:

```bash
echo ""
echo "========================================"
echo "Running Zeek NDJSON E2E Tests"
echo "========================================"
docker compose -f "$COMPOSE_FILE" run --rm zeek-generator
docker compose -f "$COMPOSE_FILE" run --rm zeek-s3-verifier
echo "Zeek E2E Tests Completed Successfully"
```

Replace it with:

```bash
echo ""
echo "========================================"
echo "Running Zeek NDJSON E2E Tests"
echo "========================================"
docker compose -f "$COMPOSE_FILE" run --rm zeek-generator
docker compose -f "$COMPOSE_FILE" run --rm zeek-s3-verifier
docker compose -f "$COMPOSE_FILE" run --rm zeek-local-verifier
echo "Zeek E2E Tests Completed Successfully"
```

- [ ] **Step 2: Confirm the service depends on containers already running by this point in the script**

Read `tests/e2e/simulation-environment/docker-compose.yml`'s `zeek-local-verifier` service definition (lines 361-374) and confirm its `depends_on: [zeek-generator, logthing]` are both already started earlier in `run.sh` (`logthing` via `up -d logthing` near the top of the script, `zeek-generator` via the `run --rm zeek-generator` line directly above the new line you just added) — no further changes needed if so; this is a verification-only step, not a code change.

- [ ] **Step 3: Commit**

```bash
git add tests/e2e/simulation-environment/run.sh
git commit -m "fix(e2e): actually invoke zeek-local-verifier in run.sh

The service has existed in docker-compose.yml since the local-disk output
target landed, but nothing ever ran it — Zeek's local-alongside-s3 e2e
check has never executed. Found while planning Suricata's equivalent
local-disk support."
```

(This task does not have a Rust build/test step — it only touches a shell script. Running the full e2e suite to verify requires Docker and MinIO and is outside the scope of a single task's verification; the next full e2e run — whenever one is next executed — will be the first real confirmation this line works. Note this honestly in the task's self-review; do not claim it was verified end-to-end if it wasn't.)

---

### Task 3: Add `SuricataLocalConfig` to `src/config/mod.rs`

**Files:**
- Modify: `src/config/mod.rs` (add `SuricataLocalConfig` struct after `SuricataS3Config`, currently ending at line 425; add `local` field to `SuricataConfig` at lines 358-371 and its `Default` impl at lines 373-382)
- Test: same file's `#[cfg(test)] mod tests` block (existing tests start around line 1000+; add new tests near `default_suricata_config_disabled_on_port_47761` at line 1246 and `suricata_s3_flat_toml_deserializes_correctly` at line 1258)

**Interfaces:**
- Consumes: `default_suricata_s3_prefix`, `default_suricata_flush_bytes`, `default_suricata_flush_secs`, `default_suricata_channel_capacity`, `default_suricata_max_buffer_rows` (all already exist at lines 411-425).
- Produces: `pub struct SuricataLocalConfig { pub directory: PathBuf, pub prefix: String, pub flush_threshold_bytes: usize, pub flush_interval_secs: u64, pub channel_capacity: usize, pub max_buffer_rows: usize }`, and `SuricataConfig.local: Option<SuricataLocalConfig>` — both consumed by Task 4 (`suricata_s3.rs`) and Task 5 (`main.rs`).

- [ ] **Step 1: Write the failing tests**

Add these four tests inside the existing `#[cfg(test)] mod tests { ... }` block in `src/config/mod.rs`, placed directly after the existing `suricata_s3_flat_toml_deserializes_correctly` test (find it by searching for that exact function name — it's right after `default_suricata_config_disabled_on_port_47761` at line 1246):

```rust
    #[test]
    fn suricata_local_absent_gives_none() {
        let cfg = Config::default();
        assert!(
            cfg.suricata.local.is_none(),
            "absent [suricata.local] must deserialize to None"
        );
    }

    #[test]
    fn suricata_local_config_deserializes_from_toml() {
        let toml_str = r#"
directory = "/var/log/logthing/suricata"
prefix = "suricata"
flush_threshold_bytes = 52428800
flush_interval_secs = 300
channel_capacity = 512
max_buffer_rows = 50000
"#;
        let cfg: SuricataLocalConfig = toml::from_str(toml_str).expect("deserialize");
        assert_eq!(
            cfg.directory,
            std::path::PathBuf::from("/var/log/logthing/suricata")
        );
        assert_eq!(cfg.prefix, "suricata");
        assert_eq!(cfg.flush_threshold_bytes, 52_428_800);
        assert_eq!(cfg.flush_interval_secs, 300);
        assert_eq!(cfg.channel_capacity, 512);
        assert_eq!(cfg.max_buffer_rows, 50_000);
    }

    #[test]
    fn suricata_local_config_defaults_apply_when_only_directory_given() {
        let toml_str = r#"directory = "/data/suricata""#;
        let cfg: SuricataLocalConfig = toml::from_str(toml_str).expect("deserialize");
        assert_eq!(cfg.prefix, "suricata");
        assert_eq!(cfg.flush_threshold_bytes, 100 * 1024 * 1024);
        assert_eq!(cfg.flush_interval_secs, 900);
        assert_eq!(cfg.channel_capacity, 256);
        assert_eq!(cfg.max_buffer_rows, 100_000);
    }

    #[test]
    fn suricata_s3_and_local_can_both_be_configured_simultaneously() {
        let toml_str = r#"
[suricata]
enabled = true

[suricata.s3]
endpoint = "http://minio:9000"
bucket = "b"
region = "us-east-1"
access_key = "k"
secret_key = "s"

[suricata.local]
directory = "/data/suricata"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("deserialize");
        assert!(
            cfg.suricata.s3.is_some(),
            "s3 must deserialize when both present"
        );
        assert!(
            cfg.suricata.local.is_some(),
            "local must deserialize when both present"
        );
    }
```

- [ ] **Step 2: Run tests to verify they fail (struct doesn't exist yet)**

Run: `cargo test --lib config::tests::suricata_local -- --nocapture`
Expected: FAIL with a compile error — `SuricataLocalConfig` is not defined and `SuricataConfig` has no field `local`.

- [ ] **Step 3: Add `SuricataLocalConfig` and wire it into `SuricataConfig`**

In `src/config/mod.rs`, change the `SuricataConfig` struct (lines 358-371) from:

```rust
/// Configuration for the Suricata EVE JSON TCP listener.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SuricataConfig {
    #[serde(default = "default_suricata_enabled")]
    pub enabled: bool,

    #[serde(default = "default_suricata_tcp_port")]
    pub tcp_port: u16,

    #[serde(default = "default_suricata_bind_address")]
    pub bind_address: String,

    /// Optional S3 persistence. Absent from TOML → `None` → no persistence.
    #[serde(default)]
    pub s3: Option<SuricataS3Config>,
}

impl Default for SuricataConfig {
    fn default() -> Self {
        Self {
            enabled: default_suricata_enabled(),
            tcp_port: default_suricata_tcp_port(),
            bind_address: default_suricata_bind_address(),
            s3: None,
        }
    }
}
```

to:

```rust
/// Configuration for the Suricata EVE JSON TCP listener.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SuricataConfig {
    #[serde(default = "default_suricata_enabled")]
    pub enabled: bool,

    #[serde(default = "default_suricata_tcp_port")]
    pub tcp_port: u16,

    #[serde(default = "default_suricata_bind_address")]
    pub bind_address: String,

    /// Optional S3 persistence. Absent from TOML → `None` → no persistence.
    #[serde(default)]
    pub s3: Option<SuricataS3Config>,

    /// Optional local-disk persistence. Absent from TOML → `None` → no
    /// persistence. Independent of `s3` — both may be configured
    /// simultaneously, in which case records are written to both.
    #[serde(default)]
    pub local: Option<SuricataLocalConfig>,
}

impl Default for SuricataConfig {
    fn default() -> Self {
        Self {
            enabled: default_suricata_enabled(),
            tcp_port: default_suricata_tcp_port(),
            bind_address: default_suricata_bind_address(),
            s3: None,
            local: None,
        }
    }
}
```

Then, immediately after the existing `fn default_suricata_max_buffer_rows() -> usize { 100_000 }` (line 423-425), before the `/// Per-source S3 persistence config for WEF` comment (line 427), insert:

```rust

/// Per-source local-disk persistence config for the Suricata listener.
/// Mirrors `SuricataS3Config`'s flush-policy shape (reusing the same
/// default functions), swapping the S3 connection for a root directory.
/// Independent of `s3`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SuricataLocalConfig {
    /// Root directory Parquet files are written under (created if missing).
    pub directory: PathBuf,
    /// Key prefix, slash-free (default: `"suricata"` — same default as `suricata.s3`).
    #[serde(default = "default_suricata_s3_prefix")]
    pub prefix: String,
    /// Flush when estimated buffer bytes exceeds this (default: 100 MiB).
    #[serde(default = "default_suricata_flush_bytes")]
    pub flush_threshold_bytes: usize,
    /// Flush after this many seconds regardless of buffer size (default: 900).
    #[serde(default = "default_suricata_flush_secs")]
    pub flush_interval_secs: u64,
    /// Bounded channel capacity (default: 256).
    #[serde(default = "default_suricata_channel_capacity")]
    pub channel_capacity: usize,
    /// Maximum buffered rows before hard cap kicks in (default: 100_000).
    #[serde(default = "default_suricata_max_buffer_rows")]
    pub max_buffer_rows: usize,
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib config:: -- --nocapture`
Expected: PASS — all four new tests, plus every existing `config::tests::*` test (in particular `default_suricata_config_disabled_on_port_47761` and `suricata_s3_flat_toml_deserializes_correctly`, which must be unaffected).

- [ ] **Step 5: Commit**

```bash
git add src/config/mod.rs
git commit -m "feat(config): add SuricataLocalConfig, SuricataConfig.local

Mirrors ZeekConfig.local's shape exactly: independent Option field,
reuses the existing suricata.s3 default functions for its flush-policy
fields. Not yet wired to any writer — that's the next task."
```

---

### Task 4: Refactor `suricata_s3.rs` — extract `build_suricata_handle`, add `suricata_local_start` and `MultiSuricataHandler`

**Files:**
- Modify: `src/forwarding/suricata_s3.rs` (refactor `suricata_start` at lines 129-156; add new code after it, before the `// Tests` section at line 158)
- Test: same file's `#[cfg(test)] mod tests` block (starts line 162)

**Interfaces:**
- Consumes: `SuricataLocalConfig` (Task 3), `crate::forwarding::buffered_writer::unused_s3_connection_placeholder` (Task 1), `crate::forwarding::buffered_writer::UploadSink`, `crate::forwarding::local_sink::LocalDiskSink`, `crate::suricata::listener::SuricataHandler` trait (`async fn handle_record(&self, record: SuricataRecord, source: SocketAddr)`, `src/suricata/listener.rs:38-40`).
- Produces: `pub fn suricata_local_start(cfg: &SuricataLocalConfig, sink: Arc<LocalDiskSink>, source_stats: Arc<SourceHourlyStats>) -> (SuricataS3Handler, JoinHandle<()>)` and `pub struct MultiSuricataHandler(pub Vec<Arc<dyn SuricataHandler>>)` — both consumed by Task 5 (`main.rs`).

- [ ] **Step 1: Write the failing tests**

Add these tests inside the existing `#[cfg(test)] mod tests { ... }` block in `src/forwarding/suricata_s3.rs`, placed directly after the existing `suricata_sink_reports_into_shared_source_hourly_stats` test (the last test in the file, ending at line 503, right before the file's closing `}` at line 504):

```rust

    // -- suricata_local_start wires handler and join handle --

    #[tokio::test]
    async fn suricata_local_start_wires_handler_and_join_handle() {
        use crate::config::SuricataLocalConfig;
        use crate::forwarding::local_sink::LocalDiskSink;
        use crate::suricata::listener::SuricataHandler;
        use std::net::SocketAddr;

        let dir = tempfile::tempdir().unwrap();
        let sink = Arc::new(
            LocalDiskSink::new(dir.path().to_path_buf())
                .await
                .expect("LocalDiskSink::new"),
        );
        let cfg = SuricataLocalConfig {
            directory: dir.path().to_path_buf(),
            prefix: "suricata".to_string(),
            flush_threshold_bytes: 1, // flush on first push
            flush_interval_secs: 3600,
            channel_capacity: 256,
            max_buffer_rows: 100_000,
        };
        let (handler, join_handle) = suricata_local_start(
            &cfg,
            sink,
            std::sync::Arc::new(crate::stats::SourceHourlyStats::new()),
        );

        let src: SocketAddr = "127.0.0.1:47761".parse().unwrap();
        handler
            .handle_record(make_alert_record("10.0.0.1"), src)
            .await;

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        drop(handler);
        tokio::time::timeout(std::time::Duration::from_secs(5), join_handle)
            .await
            .expect("writer task must exit within 5s")
            .expect("writer task must not panic");

        let alert_dir = dir.path().join("suricata/alert");
        let found = std::fs::read_dir(&alert_dir)
            .expect("suricata/alert directory must exist")
            .count();
        assert!(
            found >= 1,
            "expected at least one Parquet file under {alert_dir:?}"
        );
    }

    // -- MultiSuricataHandler tests --

    #[tokio::test]
    async fn multi_suricata_handler_fans_out_to_every_inner_handler() {
        use crate::suricata::listener::SuricataHandler;
        use std::net::SocketAddr;
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct CountingHandler(Arc<AtomicUsize>);
        #[async_trait::async_trait]
        impl SuricataHandler for CountingHandler {
            async fn handle_record(&self, _record: SuricataRecord, _source: SocketAddr) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let count_a = Arc::new(AtomicUsize::new(0));
        let count_b = Arc::new(AtomicUsize::new(0));
        let multi = MultiSuricataHandler(vec![
            Arc::new(CountingHandler(count_a.clone())),
            Arc::new(CountingHandler(count_b.clone())),
        ]);

        let src: SocketAddr = "127.0.0.1:47761".parse().unwrap();
        multi
            .handle_record(make_alert_record("Fan1"), src)
            .await;

        assert_eq!(
            count_a.load(Ordering::SeqCst),
            1,
            "handler A must receive the record"
        );
        assert_eq!(
            count_b.load(Ordering::SeqCst),
            1,
            "handler B must receive the record"
        );
    }

    #[tokio::test]
    #[allow(clippy::mutable_key_type)]
    async fn multi_suricata_handler_survives_one_inner_handler_dropping() {
        use crate::config::SuricataS3Config;
        use crate::suricata::listener::SuricataHandler;
        use metrics::set_default_local_recorder;
        use metrics_util::CompositeKey;
        use metrics_util::MetricKind;
        use metrics_util::debugging::DebuggingRecorder;
        use std::net::SocketAddr;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let sink = unreachable_sink().await;
        let cfg = SuricataS3Config {
            connection: S3ConnectionConfig {
                endpoint: "http://127.0.0.1:1".to_string(),
                bucket: "test-bucket".to_string(),
                region: "us-east-1".to_string(),
                access_key: "AKIATEST".to_string(),
                secret_key: "SECRETTEST".to_string(),
            },
            prefix: "suricata".to_string(),
            flush_threshold_bytes: usize::MAX,
            flush_interval_secs: 3600,
            channel_capacity: 1,
            max_buffer_rows: 1,
        };
        let (struggling_handler, _jh) = suricata_start(
            &cfg,
            sink,
            std::sync::Arc::new(crate::stats::SourceHourlyStats::new()),
        );

        use std::sync::atomic::{AtomicUsize, Ordering};
        struct CountingHandler(Arc<AtomicUsize>);
        #[async_trait::async_trait]
        impl SuricataHandler for CountingHandler {
            async fn handle_record(&self, _record: SuricataRecord, _source: SocketAddr) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let healthy_count = Arc::new(AtomicUsize::new(0));
        let multi = MultiSuricataHandler(vec![
            Arc::new(struggling_handler),
            Arc::new(CountingHandler(healthy_count.clone())),
        ]);

        let src: SocketAddr = "127.0.0.1:47761".parse().unwrap();
        for i in 0..20 {
            multi
                .handle_record(make_alert_record(&format!("{i}.0.0.1")), src)
                .await;
        }

        assert_eq!(
            healthy_count.load(Ordering::SeqCst),
            20,
            "the healthy handler must receive every record even if the struggling one drops some"
        );

        let snapshot = snapshotter.snapshot();
        let map = snapshot.into_hashmap();
        let key = CompositeKey::new(
            MetricKind::Counter,
            metrics::Key::from_parts(
                "parquet_s3_dropped",
                vec![
                    metrics::Label::new("source", "suricata"),
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
            "the struggling handler must actually have dropped at least one record \
             for this test to prove handler isolation (dropped={dropped})"
        );
    }
```

- [ ] **Step 2: Run tests to verify they fail (functions don't exist yet)**

Run: `cargo test --lib forwarding::suricata_s3::tests::suricata_local_start_wires -- --nocapture`
Expected: FAIL with a compile error — `suricata_local_start` and `MultiSuricataHandler` are not defined.

- [ ] **Step 3: Refactor `suricata_start` into a shared `build_suricata_handle`, and add `suricata_local_start` + `MultiSuricataHandler`**

In `src/forwarding/suricata_s3.rs`, replace the entire block from the `// SuricataS3Handler — type alias + SuricataHandler impl` section comment (line 97) through the end of `suricata_start` (line 156) — i.e. replace this:

```rust
// ---------------------------------------------------------------------------
// SuricataS3Handler — type alias + SuricataHandler impl
// ---------------------------------------------------------------------------

/// `SuricataS3Handler` is a thin alias for the generic `ParquetWriterHandle<SuricataSink>`.
pub type SuricataS3Handler = crate::forwarding::buffered_writer::ParquetWriterHandle<SuricataSink>;

#[async_trait::async_trait]
impl crate::suricata::listener::SuricataHandler
    for crate::forwarding::buffered_writer::ParquetWriterHandle<SuricataSink>
{
    async fn handle_record(&self, record: SuricataRecord, source: std::net::SocketAddr) {
        match self.try_send(record) {
            Ok(()) => {}
            Err(_dropped) => {
                // parquet_s3_dropped{source="suricata"} is already incremented by try_send.
                tracing::warn!("Suricata S3 channel full; dropped 1 record from {}", source);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// suricata_start — convenience constructor
// ---------------------------------------------------------------------------

/// Construct a `SuricataS3Handler` (i.e. `ParquetWriterHandle<SuricataSink>`) from a
/// `SuricataS3Config` and a pre-built `S3Sink`.
///
/// Returns `(handler, writer_task_handle)`. The caller should retain the `JoinHandle`
/// and await it during graceful shutdown, after all `Arc<dyn SuricataHandler>` references
/// have been dropped so the channel closes and the final flush fires.
pub fn suricata_start(
    cfg: &SuricataS3Config,
    s3: std::sync::Arc<crate::forwarding::s3_sink::S3Sink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
) -> (SuricataS3Handler, tokio::task::JoinHandle<()>) {
    use crate::forwarding::buffered_writer::{
        BufferedWriterConfig, FlushPolicy, ParquetWriterHandle,
    };

    /// Replaces the old per-source streams constant.
    const DEFAULT_MAX_SURICATA_PARTITIONS: usize = 256;

    let bwc = BufferedWriterConfig {
        connection: cfg.connection.clone(),
        prefix: cfg.prefix.clone(),
        max_buffer_rows: cfg.max_buffer_rows,
        flush_threshold_bytes: cfg.flush_threshold_bytes,
        flush_interval_secs: cfg.flush_interval_secs,
        channel_capacity: cfg.channel_capacity,
        max_partitions: DEFAULT_MAX_SURICATA_PARTITIONS,
    };
    let policy = FlushPolicy {
        max_rows: cfg.max_buffer_rows,
        max_bytes: cfg.flush_threshold_bytes,
        interval: std::time::Duration::from_secs(cfg.flush_interval_secs),
    };
    ParquetWriterHandle::start_with_stats(SuricataSink, s3, bwc, policy, source_stats)
}
```

with this:

```rust
// ---------------------------------------------------------------------------
// SuricataS3Handler — type alias + SuricataHandler impl
// ---------------------------------------------------------------------------

/// `SuricataS3Handler` is a thin alias for the generic `ParquetWriterHandle<SuricataSink>`.
pub type SuricataS3Handler = crate::forwarding::buffered_writer::ParquetWriterHandle<SuricataSink>;

#[async_trait::async_trait]
impl crate::suricata::listener::SuricataHandler
    for crate::forwarding::buffered_writer::ParquetWriterHandle<SuricataSink>
{
    async fn handle_record(&self, record: SuricataRecord, source: std::net::SocketAddr) {
        match self.try_send(record) {
            Ok(()) => {}
            Err(_dropped) => {
                // parquet_s3_dropped{source="suricata"} is already incremented by try_send.
                tracing::warn!("Suricata S3 channel full; dropped 1 record from {}", source);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// MultiSuricataHandler — fan-out to multiple destinations
// ---------------------------------------------------------------------------

/// Fans out each record to every configured handler. Used only when both
/// `.s3` and `.local` persistence resolve to a live handler for the same
/// run, so each destination keeps its own independent buffer, flush policy,
/// backpressure, and hard cap (no shared state between destinations).
pub struct MultiSuricataHandler(
    pub Vec<std::sync::Arc<dyn crate::suricata::listener::SuricataHandler>>,
);

#[async_trait::async_trait]
impl crate::suricata::listener::SuricataHandler for MultiSuricataHandler {
    async fn handle_record(&self, record: SuricataRecord, source: std::net::SocketAddr) {
        for handler in &self.0 {
            handler.handle_record(record.clone(), source).await;
        }
    }
}

// ---------------------------------------------------------------------------
// suricata_start / suricata_local_start — convenience constructors
// ---------------------------------------------------------------------------

/// Replaces the old per-source streams constant.
const DEFAULT_MAX_SURICATA_PARTITIONS: usize = 256;

/// Shared by `suricata_start` (S3) and `suricata_local_start` (local disk):
/// builds a `SuricataS3Handler` from flush-policy fields, a pre-built,
/// already-typed `Arc<dyn UploadSink>`, and the shared `SourceHourlyStats`
/// every source writer feeds into.
fn build_suricata_handle(
    prefix: String,
    max_buffer_rows: usize,
    flush_threshold_bytes: usize,
    flush_interval_secs: u64,
    channel_capacity: usize,
    sink: std::sync::Arc<dyn crate::forwarding::buffered_writer::UploadSink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
) -> (SuricataS3Handler, tokio::task::JoinHandle<()>) {
    use crate::forwarding::buffered_writer::{
        BufferedWriterConfig, FlushPolicy, ParquetWriterHandle,
    };

    let bwc = BufferedWriterConfig {
        connection: crate::forwarding::buffered_writer::unused_s3_connection_placeholder(),
        prefix,
        max_buffer_rows,
        flush_threshold_bytes,
        flush_interval_secs,
        channel_capacity,
        max_partitions: DEFAULT_MAX_SURICATA_PARTITIONS,
    };
    let policy = FlushPolicy {
        max_rows: max_buffer_rows,
        max_bytes: flush_threshold_bytes,
        interval: std::time::Duration::from_secs(flush_interval_secs),
    };
    ParquetWriterHandle::start_with_stats(SuricataSink, sink, bwc, policy, source_stats)
}

/// Construct a `SuricataS3Handler` (i.e. `ParquetWriterHandle<SuricataSink>`) from a
/// `SuricataS3Config` and a pre-built `S3Sink`.
///
/// Returns `(handler, writer_task_handle)`. The caller should retain the `JoinHandle`
/// and await it during graceful shutdown, after all `Arc<dyn SuricataHandler>` references
/// have been dropped so the channel closes and the final flush fires.
pub fn suricata_start(
    cfg: &SuricataS3Config,
    s3: std::sync::Arc<crate::forwarding::s3_sink::S3Sink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
) -> (SuricataS3Handler, tokio::task::JoinHandle<()>) {
    build_suricata_handle(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        cfg.flush_threshold_bytes,
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        s3,
        source_stats,
    )
}

/// Construct a `SuricataS3Handler` from a `SuricataLocalConfig` and a
/// pre-built `LocalDiskSink`. Structurally identical to `suricata_start`,
/// writing to local disk instead of S3 — same `SuricataSink` adapter, same
/// buffering/flush/cap machinery, same S3-key-shaped relative path layout
/// on disk.
pub fn suricata_local_start(
    cfg: &crate::config::SuricataLocalConfig,
    sink: std::sync::Arc<crate::forwarding::local_sink::LocalDiskSink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
) -> (SuricataS3Handler, tokio::task::JoinHandle<()>) {
    build_suricata_handle(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        cfg.flush_threshold_bytes,
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        sink,
        source_stats,
    )
}
```

Note: `cfg.connection.clone()` (the old `suricata_start` used the caller-supplied `SuricataS3Config.connection` directly) is now replaced by `unused_s3_connection_placeholder()` inside `build_suricata_handle` for *both* `suricata_start` and `suricata_local_start`. This is correct and matches Zeek's identical behavior — the field is dead once a pre-built sink is supplied (see the doc comment on `unused_s3_connection_placeholder` from Task 1), so it's fine for the shared helper to always use the placeholder rather than threading the S3-only config's real connection through.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib forwarding::suricata_s3:: -- --nocapture`
Expected: PASS — the 3 new tests, plus every pre-existing test in this file (in particular `suricata_start_wires_handler_and_join_handle` and `handler_overflow_increments_dropped_counter`, which must be unaffected by the refactor).

- [ ] **Step 5: Commit**

```bash
git add src/forwarding/suricata_s3.rs
git commit -m "feat(forwarding): add suricata_local_start + MultiSuricataHandler

Extracts build_suricata_handle (shared by suricata_start and the new
suricata_local_start) exactly mirroring zeek_s3.rs's build_zeek_handle
pattern. MultiSuricataHandler fans out to both destinations when .s3 and
.local are both configured. Not yet wired into main.rs."
```

---

### Task 5: Wire `main.rs`'s Suricata block to support `.s3` + `.local` fan-out

**Files:**
- Modify: `src/main.rs:263-306` (the entire `if config.suricata.enabled { ... }` block)

**Interfaces:**
- Consumes: `suricata_local_start`, `MultiSuricataHandler` (Task 4), `SuricataConfig.local` (Task 3), `crate::forwarding::local_sink::LocalDiskSink::new` (already used identically by the Zeek block at `main.rs:225`).
- Produces: nothing new for later tasks — this is the final wiring point for this plan.

- [ ] **Step 1: Replace the Suricata block**

In `src/main.rs`, replace this entire block (lines 263-306):

```rust
    // -----------------------------------------------------------------------
    // Start Suricata listener if enabled
    // -----------------------------------------------------------------------
    if config.suricata.enabled {
        let suricata_config_clone = config.clone();
        let suricata_shutdown_rx = shutdown_rx.clone();

        let suricata_handler: Arc<dyn suricata::listener::SuricataHandler> =
            if let Some(s3_cfg) = suricata_config_clone.suricata.s3.as_ref() {
                match forwarding::s3_sink::S3Sink::from_connection(&s3_cfg.connection).await {
                    Ok(sink) => {
                        let (handler, writer_handle) = forwarding::suricata_s3::suricata_start(
                            s3_cfg,
                            Arc::new(sink),
                            source_stats.clone(),
                        );
                        writer_handles.push(writer_handle);
                        Arc::new(handler)
                    }
                    Err(e) => {
                        error!(
                            "Failed to create S3Sink for Suricata persistence, \
                                 falling back to DefaultSuricataHandler: {e}"
                        );
                        Arc::new(suricata::listener::DefaultSuricataHandler)
                    }
                }
            } else {
                Arc::new(suricata::listener::DefaultSuricataHandler)
            };

        let listener_config = suricata::listener::SuricataListenerConfig {
            tcp_port: suricata_config_clone.suricata.tcp_port,
            bind_address: suricata_config_clone.suricata.bind_address.clone(),
        };
        let handle = tokio::spawn(async move {
            let listener =
                suricata::listener::SuricataListener::new(listener_config, suricata_handler);
            if let Err(e) = listener.start_with_shutdown(suricata_shutdown_rx).await {
                error!("Suricata listener error: {}", e);
            }
        });
        listener_handles.push(handle);
    }
```

with this:

```rust
    // -----------------------------------------------------------------------
    // Start Suricata listener if enabled
    // -----------------------------------------------------------------------
    if config.suricata.enabled {
        let suricata_config_clone = config.clone();
        let suricata_shutdown_rx = shutdown_rx.clone();

        let mut suricata_handlers: Vec<Arc<dyn suricata::listener::SuricataHandler>> = Vec::new();

        if let Some(s3_cfg) = suricata_config_clone.suricata.s3.as_ref() {
            match forwarding::s3_sink::S3Sink::from_connection(&s3_cfg.connection).await {
                Ok(sink) => {
                    let (handler, writer_handle) = forwarding::suricata_s3::suricata_start(
                        s3_cfg,
                        Arc::new(sink),
                        source_stats.clone(),
                    );
                    writer_handles.push(writer_handle);
                    suricata_handlers.push(Arc::new(handler));
                }
                Err(e) => {
                    error!(
                        "Failed to create S3Sink for Suricata persistence, \
                             skipping S3 target: {e}"
                    );
                }
            }
        }

        if let Some(local_cfg) = suricata_config_clone.suricata.local.as_ref() {
            match forwarding::local_sink::LocalDiskSink::new(local_cfg.directory.clone()).await {
                Ok(sink) => {
                    let (handler, writer_handle) = forwarding::suricata_s3::suricata_local_start(
                        local_cfg,
                        Arc::new(sink),
                        source_stats.clone(),
                    );
                    writer_handles.push(writer_handle);
                    suricata_handlers.push(Arc::new(handler));
                }
                Err(e) => {
                    error!(
                        "Failed to create LocalDiskSink for Suricata persistence, \
                             skipping local target: {e}"
                    );
                }
            }
        }

        let suricata_handler: Arc<dyn suricata::listener::SuricataHandler> =
            match suricata_handlers.len() {
                0 => Arc::new(suricata::listener::DefaultSuricataHandler),
                1 => suricata_handlers.into_iter().next().unwrap(),
                _ => Arc::new(forwarding::suricata_s3::MultiSuricataHandler(
                    suricata_handlers,
                )),
            };

        let listener_config = suricata::listener::SuricataListenerConfig {
            tcp_port: suricata_config_clone.suricata.tcp_port,
            bind_address: suricata_config_clone.suricata.bind_address.clone(),
        };
        let handle = tokio::spawn(async move {
            let listener =
                suricata::listener::SuricataListener::new(listener_config, suricata_handler);
            if let Err(e) = listener.start_with_shutdown(suricata_shutdown_rx).await {
                error!("Suricata listener error: {}", e);
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
Expected: PASS, same pass count as before this task plus the tests added in Tasks 3 and 4 (no regressions — `main.rs` has no `#[cfg(test)]` module of its own, so this step's purpose is to confirm the binary crate still compiles and links against every source module correctly).

- [ ] **Step 4: Commit**

```bash
git add src/main.rs
git commit -m "feat(main): wire suricata.local alongside suricata.s3, fan out via MultiSuricataHandler when both configured

Mirrors the existing Zeek block's Vec<Arc<dyn Handler>> + match-on-length
pattern exactly."
```

---

### Task 6: Add `tests/suricata_local_integration.rs` — real Parquet round-trip

**Files:**
- Create: `tests/suricata_local_integration.rs`

**Why this satisfies the integration-test tier:** This test drives the real `suricata_local_start` → `LocalDiskSink` → real Parquet-file-on-disk path, then reads the file back with a real Parquet reader — no mocks. It needs no external service (unlike `tests/suricata_s3_integration.rs`, which is gated on a running MinIO), so it runs unconditionally in CI, exactly like `tests/zeek_local_integration.rs` already does for Zeek.

Note honestly: this repo currently has **no end-to-end (docker-compose simulation-environment) test coverage for Suricata at all** — no `suricata-generator`, no `suricata-s3-verifier` service exists in `tests/e2e/simulation-environment/docker-compose.yml` (confirmed by grep — Suricata does not appear anywhere in that file), unlike Zeek, IPFIX, syslog, and WEF, which all have generator+verifier pairs there. Building that full e2e harness from scratch (a new EVE-JSON-generating container, a new verifier container, new docker-compose services) is a separate, materially larger effort than "add local-disk support to an existing S3-only source," and is out of scope for this plan. This task's Rust-level integration test is the most rigorous verification level this plan delivers for Suricata; full e2e docker-based coverage remains a pre-existing gap for Suricata generally (predating this change), not something this feature is expected to fix as a side effect.

**Interfaces:**
- Consumes: `logthing::config::SuricataLocalConfig` (Task 3), `logthing::forwarding::local_sink::LocalDiskSink`, `logthing::forwarding::suricata_s3::suricata_local_start` (Task 4), `logthing::suricata::SuricataRecord`, `logthing::suricata::listener::SuricataHandler`.

- [ ] **Step 1: Write the test**

Create `tests/suricata_local_integration.rs`:

```rust
//! Integration test: SuricataRecord → suricata_local_start → real Parquet
//! files on local disk, read back with a real Parquet reader.
//!
//! Unlike `suricata_s3_integration.rs` (gated on a running MinIO), this test
//! needs no external service — local disk is always available — so it runs
//! unconditionally in CI.

use logthing::config::SuricataLocalConfig;
use logthing::forwarding::local_sink::LocalDiskSink;
use logthing::forwarding::suricata_s3::suricata_local_start;
use logthing::suricata::SuricataRecord;
use logthing::suricata::listener::SuricataHandler;
use std::sync::Arc;

fn make_alert_record(src_ip: &str) -> SuricataRecord {
    SuricataRecord {
        event_type: "alert".to_string(),
        fields: serde_json::json!({
            "event_type": "alert",
            "src_ip": src_ip,
            "dest_ip": "1.2.3.4",
            "alert": {"signature": "ET TEST"}
        }),
        received_at: chrono::Utc::now(),
    }
}

fn make_flow_record() -> SuricataRecord {
    SuricataRecord {
        event_type: "flow".to_string(),
        fields: serde_json::json!({
            "event_type": "flow",
            "src_ip": "10.0.0.1",
            "dest_ip": "8.8.8.8",
            "flow": {"bytes_toserver": 512, "bytes_toclient": 4096}
        }),
        received_at: chrono::Utc::now(),
    }
}

#[tokio::test]
async fn suricata_records_appear_as_parquet_on_local_disk() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sink = Arc::new(
        LocalDiskSink::new(dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new"),
    );
    let cfg = SuricataLocalConfig {
        directory: dir.path().to_path_buf(),
        prefix: "suricata".to_string(),
        max_buffer_rows: 1, // flush immediately on first record per partition
        flush_threshold_bytes: 1,
        flush_interval_secs: 3600,
        channel_capacity: 256,
    };

    let (handler, _writer_task) = suricata_local_start(
        &cfg,
        sink,
        Arc::new(logthing::stats::SourceHourlyStats::new()),
    );

    let src: std::net::SocketAddr = "127.0.0.1:47761".parse().unwrap();
    handler
        .handle_record(make_alert_record("192.168.1.1"), src)
        .await;
    handler.handle_record(make_flow_record(), src).await;

    // Give the background task time to flush (max_buffer_rows=1 and
    // flush_threshold_bytes=1 both trigger flush on the first push per partition).
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // --- Verify the `alert` record under suricata/alert/ ---
    {
        let alert_dir = dir.path().join("suricata/alert");
        assert!(alert_dir.is_dir(), "expected {alert_dir:?} to exist");
        let parquet_files: Vec<_> = walk_all_files(&alert_dir)
            .into_iter()
            .filter(|p| p.extension().is_some_and(|ext| ext == "parquet"))
            .collect();
        assert!(
            !parquet_files.is_empty(),
            "expected at least one Parquet file under {alert_dir:?}"
        );

        let file_path = &parquet_files[0];
        let bytes = std::fs::read(file_path).expect("read parquet file");

        use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
        let builder = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(bytes))
            .expect("parquet builder for alert");
        let schema = builder.schema().clone();
        for col in ["event_type", "received_at", "src_ip", "payload"] {
            assert!(
                schema.field_with_name(col).is_ok(),
                "expected column '{col}' in envelope schema"
            );
        }

        let mut reader = builder.build().expect("parquet reader for alert");
        let rb = reader
            .next()
            .expect("at least one batch")
            .expect("batch ok");
        assert_eq!(rb.num_rows(), 1);

        use arrow::array::StringArray;
        let src_ip = rb
            .column_by_name("src_ip")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(src_ip.value(0), "192.168.1.1");
    }

    // --- Verify the `flow` record under suricata/flow/ ---
    {
        let flow_dir = dir.path().join("suricata/flow");
        assert!(flow_dir.is_dir(), "expected {flow_dir:?} to exist");
        let parquet_files: Vec<_> = walk_all_files(&flow_dir)
            .into_iter()
            .filter(|p| p.extension().is_some_and(|ext| ext == "parquet"))
            .collect();
        assert!(
            !parquet_files.is_empty(),
            "expected at least one Parquet file under {flow_dir:?}"
        );

        let file_path = &parquet_files[0];
        let bytes = std::fs::read(file_path).expect("read parquet file");

        use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
        let builder = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(bytes))
            .expect("parquet builder for flow");
        let mut reader = builder.build().expect("parquet reader for flow");
        let rb = reader
            .next()
            .expect("at least one batch")
            .expect("batch ok");
        assert_eq!(rb.num_rows(), 1);

        use arrow::array::StringArray;
        let event_type = rb
            .column_by_name("event_type")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(event_type.value(0), "flow");
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

- [ ] **Step 2: Run the test to verify it fails first (sanity check the harness), then passes**

Run: `cargo test --test suricata_local_integration -- --nocapture`

First expected outcome before Task 3/4/5 land (if run out of order): compile error, `SuricataLocalConfig`/`suricata_local_start` not found. Since this task runs *after* Tasks 3-5 in this plan's sequence, the actual expected outcome when you run this is:

Expected: PASS — `test suricata_records_appear_as_parquet_on_local_disk ... ok`.

- [ ] **Step 3: Run the full test suite one more time to confirm the whole plan's changes are consistent together**

Run: `cargo test --quiet`
Expected: PASS, 0 failures, across every test binary (lib tests, every `tests/*.rs` integration file, all doctests).

- [ ] **Step 4: Run fmt and clippy to confirm CI gates pass**

Run: `cargo fmt --all -- --check`
Expected: no output (already formatted — write the code above matching existing style, but run this to confirm).

Run: `cargo clippy --all-targets --quiet -- -D warnings`
Expected: no output (no warnings).

- [ ] **Step 5: Commit**

```bash
git add tests/suricata_local_integration.rs
git commit -m "test(suricata): integration test proving real Parquet round-trip through LocalDiskSink

Mirrors tests/zeek_local_integration.rs's pattern. Note: Suricata has no
e2e (docker-compose simulation-environment) coverage at all yet, for
either .s3 or .local — that's a pre-existing gap, out of scope here."
```

---

## Post-plan note for the final whole-branch review

When the final reviewer looks at this branch as a whole, it should confirm:
1. `suricata_s3.rs`'s refactor (Task 4) did not change `suricata_start`'s observable behavior for existing callers — `suricata_start_wires_handler_and_join_handle` and `handler_overflow_increments_dropped_counter` (both pre-existing tests) must still pass unmodified.
2. The `main.rs` Suricata block (Task 5) now structurally matches the Zeek block (lines 198-261) — same `Vec<Arc<dyn Handler>>` collection, same `match .len()` resolution, same error-handling shape per branch (log-and-skip-that-target, not log-and-fall-back-to-Default, since falling back to Default would silently disable the *other* configured target too).
3. `SuricataConfig`'s new `local` field does not change TOML-parsing behavior for existing `[suricata]`/`[suricata.s3]`-only configs — the four new config tests plus the pre-existing `default_suricata_config_disabled_on_port_47761` and `suricata_s3_flat_toml_deserializes_correctly` tests together cover this.
