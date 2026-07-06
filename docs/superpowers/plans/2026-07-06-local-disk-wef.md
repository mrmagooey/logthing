# WEF Local-Disk Persistence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `LocalDiskSink` support to WEF (Windows Event Forwarding), so `[wef.local]` can persist Windows events to local disk as Parquet, independently of or alongside `[wef.s3]`. This is the last of the six ingestion sources getting this treatment (Zeek, Suricata, IPFIX, sFlow, syslog, HEC/generic are already merged to master).

**Architecture:** Like HEC/generic, WEF is structurally different from Zeek/Suricata/IPFIX/sFlow/syslog: there is no `Handler` trait and no long-lived listener to inject a trait object into. Persistence is reached from a single call site, `process_single_event` in `src/server/mod.rs`, which reads a concrete `Option<ParquetWriterHandle<WefSink>>` field (`parquet_s3_sender`) directly off `AppState`. This plan adds a **sibling** field, `parquet_local_sender`, to `AppState` — no new trait, no `Vec<Arc<dyn Handler>>`, no fan-out wrapper (matching the architecture review's guidance for HEC/generic, which applies identically here since WEF has the same "concrete Option field checked at a request-processing site" shape, not a listener-injected trait object).

Unlike HEC/generic (which needed a shared `dispatch_generic_record` helper because it had 3+1 call sites), WEF has exactly ONE call site, so the two-target dispatch is written inline directly in `process_single_event` — no helper function needed. Also unlike HEC/generic's `GenericRecord` (which required `.clone()` of a `serde_json::Value`-bearing struct per extra target), WEF's channel item type is `Arc<WindowsEvent>` — cloning it for a second target is a cheap `Arc::clone`, not a data clone, so there is no perf-cost tradeoff to note here.

WEF already has substantial existing e2e (docker-compose) infrastructure — `wef-generator`, the generic `s3-verifier` (pointed at the `wef-events` MinIO bucket), and `parsing-validator` — unlike Suricata/sFlow/syslog/HEC/generic, which had none and so skipped an e2e task. This plan therefore DOES add e2e coverage (Task 5), mirroring the `ipfix-local-verifier`/`zeek-local-verifier` precedent (both of which also had rich pre-existing e2e infra before their own local-disk plans).

**Tech Stack:** Rust, tokio, arrow/parquet, existing `UploadSink`/`ParquetSink`/`start_writer<S>` — no new dependencies. Task 5 adds a Python (pyarrow) verifier container, matching the existing `*-local-verifier` pattern — no new Rust dependencies either way.

## Global Constraints

- `WefLocalConfig` mirrors `WefS3Config`'s flush-policy shape (swapping the S3 connection for a root directory), reusing the exact same default functions: `default_wef_flush_bytes`, `default_wef_flush_secs`, `default_wef_channel_capacity`, `default_wef_max_buffer_rows`. `WefLocalConfig`'s `prefix` field has NO default function reused from `WefS3Config` (which defaults its `prefix` via bare `#[serde(default)]` to `""`, preserving the legacy `event_type=<id>/year=…` root layout) — mirror that exact behavior: `#[serde(default)]` with no explicit default function, defaulting to an empty string.
- `wef_start` and the new `wef_local_start` must both call `crate::forwarding::buffered_writer::start_writer::<WefSink>(...)` directly — do NOT write a new `build_wef_handle` wrapper function. `max_partitions` is the literal `0` (meaning "unlimited" — confirmed at `src/forwarding/buffered_writer.rs:264`, `max_partitions == 0` bypasses the cap check) at both call sites, matching `wef_start`'s existing behavior (EventIDs are bounded in practice, so no partition cap is needed).
- `WefSink` must gain `#[derive(Default)]` (required by `start_writer<S: ParquetSink + Default>`'s bound). It currently has no derives at all — do not add `Clone` or anything else not required.
- Do **NOT** introduce any `MultiWefHandler`-style trait-object fan-out wrapper, and do NOT add a shared dispatch helper function — WEF has exactly one call site (`process_single_event`), so the two-target dispatch is written inline there directly (unlike HEC/generic's `dispatch_generic_record`, which existed to avoid tripling 3 call sites' worth of duplicated code — that rationale doesn't apply here).
- Adding a field to `AppState` breaks every existing struct-literal construction site in the workspace that doesn't use `..Default::default()`. There are exactly 3 such sites (much fewer than HEC/generic's `IngestState`, which had 7): the real construction in `Server::new` (`src/server/mod.rs`), and two test helpers (`src/server/mod.rs`'s `build_state_with_config`, and `tests/otlp_e2e.rs`'s `build_app_state`). All three are fixed in Task 3 alongside the real wiring (no separate "trivial placeholder" sub-step is needed here, unlike HEC/generic's Task 3, because the blast radius is small enough to handle in one pass).
- `Server`'s `wef_worker_handle: Option<JoinHandle<()>>` field must become `wef_worker_handles: Vec<JoinHandle<()>>` (WEF can now have up to 2 writer tasks — S3 and local — both of which must be awaited at shutdown), exactly mirroring the `hec_worker_handle` → `hec_worker_handles` change already merged for HEC/generic. `take_wef_worker_handle()` becomes `take_wef_worker_handles() -> Vec<JoinHandle<()>>` (via `std::mem::take`). `main.rs`'s shutdown sequence extends `all_writer_handles` with the returned `Vec` instead of the current `if let Some(wef_handle) = wef_worker_handle { all_writer_handles.push(wef_handle); }` pattern.
- No new Cargo dependencies. No new Cargo features.
- This plan DOES add e2e (docker-compose simulation-environment) coverage, per the rationale above — a `wef-local-verifier` service (Dockerfile + `entrypoint.py`, mirroring `ipfix-local-verifier`/`zeek-local-verifier`) that walks a local directory for Parquet files under `event_type=*/` and validates row count + the 5-column WEF schema. This is added to the docker-compose "Standard E2E Tests" section (where `wef-generator`/`s3-verifier` already run), not a new named section.
- Every new test function name must be distinct from existing ones in the same file.
- **Rustfmt note:** this plan series has repeatedly hit rustfmt line-wrap surprises when a snippet was copied verbatim without actually running it through `rustfmt` first (IPFIX, and this same session's HEC Task 1). Every Rust code block below has been pre-verified against a real `rustfmt --edition 2024` run at its exact nesting depth — copy it verbatim, and still run `cargo fmt --all -- --check` as directed in each task's steps to confirm.

---

### Task 1: Add `WefLocalConfig` to `src/config/mod.rs`

**Files:**
- Modify: `src/config/mod.rs` (add `WefLocalConfig` struct after `WefS3Config`'s default functions, currently ending at line 508; add `local` field to `WefConfig` at lines 511-516, which currently has no explicit `impl Default` — it derives `Default` via `#[derive(..., Default, ...)]`, so the derived impl picks up the new field automatically as long as `Option<WefLocalConfig>` implements `Default`, which it does via `None`)
- Test: same file's `#[cfg(test)] mod tests` block

**Interfaces:**
- Consumes: `default_wef_flush_bytes`, `default_wef_flush_secs`, `default_wef_channel_capacity`, `default_wef_max_buffer_rows` (all already exist at lines 497-508).
- Produces: `pub struct WefLocalConfig { pub directory: PathBuf, pub prefix: String, pub flush_threshold_bytes: usize, pub flush_interval_secs: u64, pub channel_capacity: usize, pub max_buffer_rows: usize }`, and `WefConfig.local: Option<WefLocalConfig>` — both consumed by Task 2 (`parquet_s3.rs`) and Task 3 (`server/mod.rs`).

- [ ] **Step 1: Write the failing tests**

Find the existing WEF config tests (search for a test name containing `wef` near the HEC/syslog test groups) and insert these three tests directly after the last `wef_s3_*`/`wef_*` test in the existing `#[cfg(test)] mod tests { ... }` block in `src/config/mod.rs`:

```rust
    #[test]
    fn wef_local_absent_gives_none() {
        let cfg = Config::default();
        assert!(
            cfg.wef.local.is_none(),
            "absent [wef.local] must deserialize to None"
        );
    }

    #[test]
    fn wef_local_config_deserializes_from_toml() {
        let toml_str = r#"
directory = "/var/log/logthing/wef"
prefix = "wef"
flush_threshold_bytes = 52428800
flush_interval_secs = 300
channel_capacity = 512
max_buffer_rows = 50000
"#;
        let cfg: WefLocalConfig = toml::from_str(toml_str).expect("deserialize");
        assert_eq!(cfg.directory, std::path::PathBuf::from("/var/log/logthing/wef"));
        assert_eq!(cfg.prefix, "wef");
        assert_eq!(cfg.flush_threshold_bytes, 52_428_800);
        assert_eq!(cfg.flush_interval_secs, 300);
        assert_eq!(cfg.channel_capacity, 512);
        assert_eq!(cfg.max_buffer_rows, 50_000);
    }

    #[test]
    fn wef_local_config_defaults_apply_when_only_directory_given() {
        let toml_str = r#"directory = "/data/wef""#;
        let cfg: WefLocalConfig = toml::from_str(toml_str).expect("deserialize");
        assert_eq!(cfg.prefix, "", "prefix defaults to empty, preserving legacy layout");
        assert_eq!(cfg.flush_threshold_bytes, 100 * 1024 * 1024);
        assert_eq!(cfg.flush_interval_secs, 900);
        assert_eq!(cfg.channel_capacity, 10_000);
        assert_eq!(cfg.max_buffer_rows, 100_000);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --quiet wef_local`
Expected: FAIL with "cannot find type `WefLocalConfig`" / "no field `local` on type `WefConfig`"

- [ ] **Step 3: Add `WefLocalConfig` struct and wire `WefConfig.local`**

Add this struct directly after `default_wef_max_buffer_rows` (currently ending at line 508):

```rust
/// Per-source local-disk persistence config for WEF (Windows Event Forwarding).
/// Mirrors `WefS3Config`'s flush-policy shape (reusing the same default
/// functions), swapping the S3 connection for a root directory. Independent
/// of `s3`. `prefix` defaults to empty (bare `#[serde(default)]`, no default
/// function), preserving the same `event_type=<id>/year=…` root layout as
/// `WefS3Config`'s empty-prefix default.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WefLocalConfig {
    /// Root directory Parquet files are written under (created if missing).
    pub directory: PathBuf,
    /// Key prefix, slash-free. Default: `""` (empty) — preserves the
    /// `event_type=<id>/year=…` root layout, same as `WefS3Config`.
    #[serde(default)]
    pub prefix: String,
    /// Flush when estimated buffer bytes exceeds this (default: 100 MiB).
    #[serde(default = "default_wef_flush_bytes")]
    pub flush_threshold_bytes: usize,
    /// Flush after this many seconds regardless (default: 900).
    #[serde(default = "default_wef_flush_secs")]
    pub flush_interval_secs: u64,
    /// Bounded channel capacity (default: 10_000).
    #[serde(default = "default_wef_channel_capacity")]
    pub channel_capacity: usize,
    /// Maximum buffered rows before hard cap (default: 100_000).
    #[serde(default = "default_wef_max_buffer_rows")]
    pub max_buffer_rows: usize,
}
```

Then modify `WefConfig` (lines 511-516) to add the `local` field, directly after the existing `s3` field:

```rust
    /// Optional local-disk persistence. Absent from TOML → `None` → no
    /// local persistence. Independent of `s3` — both may be configured
    /// simultaneously, in which case events are written to both.
    #[serde(default)]
    pub local: Option<WefLocalConfig>,
```

`WefConfig` already derives `Default` (`#[derive(Debug, Clone, Default, Deserialize, Serialize)]`) — no manual `impl Default` to update; the derive picks up `local: None` automatically since `Option<T>: Default` for any `T`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --quiet wef_local`
Expected: PASS, 3 tests ok

- [ ] **Step 5: Verify fmt and full config test suite**

Run: `cargo fmt --all -- --check`
Expected: no output (clean)

Run: `cargo test --quiet --lib config::`
Expected: all config tests pass, 0 failed

- [ ] **Step 6: Commit**

```bash
git add src/config/mod.rs
git commit -m "feat(config): add WefLocalConfig, WefConfig.local"
```

---

### Task 2: `src/forwarding/parquet_s3.rs` — migrate to `start_writer`, add `wef_local_start`

**Files:**
- Modify: `src/forwarding/parquet_s3.rs`
- Test: same file's `#[cfg(test)] mod tests` block

**Interfaces:**
- Consumes: `WefLocalConfig` (Task 1), `crate::forwarding::buffered_writer::start_writer::<S>` (existing, `pub(crate)`), `crate::forwarding::local_sink::LocalDiskSink` (existing).
- Produces: `wef_local_start(cfg: &WefLocalConfig, sink: Arc<LocalDiskSink>, source_stats: Arc<SourceHourlyStats>) -> (ParquetWriterHandle<WefSink>, JoinHandle<()>)` — consumed by Task 3 (`server/mod.rs`).

- [ ] **Step 1: Write the failing test**

Add this test to the existing `#[cfg(test)] mod tests { ... }` block in `src/forwarding/parquet_s3.rs`, directly after `wef_start_spawns_and_exits_cleanly`:

```rust
    #[tokio::test]
    async fn wef_local_start_spawns_and_exits_cleanly() {
        use crate::config::WefLocalConfig;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let sink = Arc::new(
            crate::forwarding::local_sink::LocalDiskSink::new(dir.path().to_path_buf())
                .await
                .expect("constructs"),
        );
        let cfg = WefLocalConfig {
            directory: dir.path().to_path_buf(),
            prefix: "".to_string(),
            flush_threshold_bytes: usize::MAX,
            flush_interval_secs: 3600,
            channel_capacity: 256,
            max_buffer_rows: 100_000,
        };

        let (handle, jh) = wef_local_start(
            &cfg,
            sink,
            std::sync::Arc::new(crate::stats::SourceHourlyStats::new()),
        );

        let event = make_parsed_event(4624);
        assert!(handle.try_send(event).is_ok());

        drop(handle);
        tokio::time::timeout(std::time::Duration::from_secs(5), jh)
            .await
            .expect("writer must exit within 5s")
            .expect("writer must not panic");
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --quiet --lib parquet_s3::tests::wef_local_start_spawns_and_exits_cleanly`
Expected: FAIL with "cannot find function `wef_local_start`"

- [ ] **Step 3: Add `#[derive(Default)]` to `WefSink`, migrate `wef_start`, add `wef_local_start`**

Change:

```rust
pub struct WefSink;
```

to:

```rust
#[derive(Default)]
pub struct WefSink;
```

Replace the entire `wef_start` function body with a call to `start_writer`:

```rust
/// Construct a `ParquetWriterHandle<WefSink>` from a `WefS3Config` and a pre-built `S3Sink`.
///
/// Returns `(handle, writer_task_handle)`. The caller must retain the `JoinHandle` and
/// await it during graceful shutdown. When `AppState` drops its `ParquetWriterHandle<WefSink>`,
/// the channel closes, the background task flushes, and the `JoinHandle` completes.
pub fn wef_start(
    cfg: &WefS3Config,
    s3: Arc<crate::forwarding::s3_sink::S3Sink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
) -> (
    crate::forwarding::buffered_writer::ParquetWriterHandle<WefSink>,
    tokio::task::JoinHandle<()>,
) {
    crate::forwarding::buffered_writer::start_writer::<WefSink>(
        cfg.prefix.clone(), // "" for behavior-preserving empty-prefix layout
        cfg.max_buffer_rows,
        cfg.flush_threshold_bytes,
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        0, // unlimited partitions — EventIDs are bounded in practice
        s3,
        source_stats,
    )
}

/// Construct a `ParquetWriterHandle<WefSink>` from a `WefLocalConfig` and a
/// pre-built `LocalDiskSink`. Structurally identical to `wef_start`, writing
/// to local disk instead of S3 — same `WefSink` adapter, same
/// buffering/flush/cap machinery, same S3-key-shaped relative path layout
/// on disk.
pub fn wef_local_start(
    cfg: &crate::config::WefLocalConfig,
    sink: Arc<crate::forwarding::local_sink::LocalDiskSink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
) -> (
    crate::forwarding::buffered_writer::ParquetWriterHandle<WefSink>,
    tokio::task::JoinHandle<()>,
) {
    crate::forwarding::buffered_writer::start_writer::<WefSink>(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        cfg.flush_threshold_bytes,
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        0,
        sink,
        source_stats,
    )
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --quiet --lib parquet_s3::`
Expected: PASS, all parquet_s3 tests ok (existing + 1 new)

- [ ] **Step 5: Verify fmt and clippy**

Run: `cargo fmt --all -- --check`
Expected: no output (clean)

Run: `CC=/usr/bin/gcc CXX=/usr/bin/g++ cargo clippy --all-targets --quiet -- -D warnings`
Expected: no output (clean)

- [ ] **Step 6: Commit**

```bash
git add src/forwarding/parquet_s3.rs
git commit -m "feat(forwarding): add wef_local_start, migrate wef_start to start_writer"
```

---

### Task 3: Wire `[wef.local]` into `AppState`/`Server` in `src/server/mod.rs`; plural worker handles; `main.rs` follow-on

**Files:**
- Modify: `src/server/mod.rs` (`AppState` struct at lines 44-55; `Server` struct at lines 57-67; `Server::new`'s WEF block at lines 173-207; `take_wef_worker_handle` around lines 249-255; `process_single_event`'s dispatch block at lines 663-676; test helper `build_state_with_config` around line 736)
- Modify: `tests/otlp_e2e.rs` (test helper `build_app_state` around line 81, trivial literal fix)
- Modify: `src/main.rs` (lines 471, 567-568)

**Interfaces:**
- Consumes: `WefLocalConfig`, `wef_local_start` (Task 1/2), `LocalDiskSink::new` (existing).
- Produces: real `[wef.local]` wiring; no new public interfaces for later tasks.

- [ ] **Step 1: Add `parquet_local_sender` to `AppState`**

Modify the `AppState` struct (lines 44-55):

```rust
pub struct AppState {
    pub config: Arc<RwLock<Config>>,
    pub throughput: Arc<ThroughputStats>,
    pub forwarder: Forwarder,
    pub parser: WefParser,
    pub event_parser: Option<GenericEventParser>,
    pub parquet_s3_sender: Option<
        crate::forwarding::buffered_writer::ParquetWriterHandle<
            crate::forwarding::parquet_s3::WefSink,
        >,
    >,
    /// Local-disk counterpart to `parquet_s3_sender`. `None` when `[wef.local]`
    /// is absent or construction failed. Independent of `parquet_s3_sender` —
    /// both may be `Some` simultaneously.
    pub parquet_local_sender: Option<
        crate::forwarding::buffered_writer::ParquetWriterHandle<
            crate::forwarding::parquet_s3::WefSink,
        >,
    >,
}
```

- [ ] **Step 2: Change `Server`'s `wef_worker_handle` field to a `Vec`**

Modify the `Server` struct (lines 57-67):

```rust
pub struct Server {
    config: Config,
    state: Arc<AppState>,
    /// JoinHandles for the WEF→S3 and WEF→local Parquet worker tasks (0, 1, or 2
    /// present depending on how many of `[wef.s3]` / `[wef.local]` are configured
    /// and construct successfully). Awaited during graceful shutdown so buffered
    /// data is flushed before exit.
    wef_worker_handles: Vec<tokio::task::JoinHandle<()>>,
    /// Shared extension state for HEC / NDJSON ingest routes.
    ingest_state: IngestState,
    /// JoinHandles for the HEC→S3 and HEC→local Parquet worker tasks (0, 1, or 2
    /// present depending on how many of `[hec.s3]` / `[hec.local]` are configured
    /// and construct successfully). Awaited during graceful shutdown.
    hec_worker_handles: Vec<tokio::task::JoinHandle<()>>,
}
```

Modify `take_wef_worker_handle` (around lines 249-255):

```rust
    /// Take the WEF persistence workers' JoinHandles for awaiting at shutdown.
    ///
    /// Must be called BEFORE `run`/`run_tls`; after the server consumes `self`
    /// the handles are no longer accessible. Returns 0, 1, or 2 handles
    /// depending on how many of `[wef.s3]` / `[wef.local]` constructed
    /// successfully.
    pub fn take_wef_worker_handles(&mut self) -> Vec<tokio::task::JoinHandle<()>> {
        std::mem::take(&mut self.wef_worker_handles)
    }
```

- [ ] **Step 3: Replace `Server::new`'s WEF block with independent-attempt wiring**

Replace the block currently building `(parquet_s3_sender, wef_worker_handle)` (lines 173-198) and the subsequent `AppState { ... }` construction (lines 200-207), and the trailing `Ok(Self { ... wef_worker_handle, ... })` field:

```rust
        // Initialize WEF→S3 and WEF→local Parquet forwarders via the generic
        // buffered writer. Each target is attempted independently — a failed
        // S3Sink construction does not prevent a healthy `.local` construction
        // from still populating `parquet_local_sender`, and vice versa.
        let mut wef_worker_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();
        let mut parquet_s3_sender = None;
        let mut parquet_local_sender = None;

        if let Some(wef_s3_cfg) = config.wef.s3.as_ref() {
            match crate::forwarding::s3_sink::S3Sink::from_connection(&wef_s3_cfg.connection).await
            {
                Ok(sink) => {
                    info!("Initialized WEF Parquet S3 forwarder (generic buffered writer)");
                    let (handle, join_handle) = crate::forwarding::parquet_s3::wef_start(
                        wef_s3_cfg,
                        Arc::new(sink),
                        source_stats.clone(),
                    );
                    wef_worker_handles.push(join_handle);
                    parquet_s3_sender = Some(handle);
                }
                Err(e) => {
                    error!("Failed to create S3Sink for WEF persistence, skipping S3 target: {e}");
                }
            }
        }

        if let Some(wef_local_cfg) = config.wef.local.as_ref() {
            match crate::forwarding::local_sink::LocalDiskSink::new(wef_local_cfg.directory.clone())
                .await
            {
                Ok(sink) => {
                    info!("Initialized WEF Parquet local-disk forwarder");
                    let (handle, join_handle) = crate::forwarding::parquet_s3::wef_local_start(
                        wef_local_cfg,
                        Arc::new(sink),
                        source_stats.clone(),
                    );
                    wef_worker_handles.push(join_handle);
                    parquet_local_sender = Some(handle);
                }
                Err(e) => {
                    error!(
                        "Failed to create LocalDiskSink for WEF persistence, skipping local target: {e}"
                    );
                }
            }
        }

        let state = Arc::new(AppState {
            config: Arc::clone(&shared_config),
            throughput,
            forwarder,
            parser: WefParser::new(),
            event_parser,
            parquet_s3_sender,
            parquet_local_sender,
        });
```

And in the `Ok(Self { ... })` construction further down (which also sets `ingest_state,` and `hec_worker_handles,`), replace `wef_worker_handle,` with `wef_worker_handles,`.

- [ ] **Step 4: Update `process_single_event`'s dispatch block**

Replace the existing dispatch block (currently lines 663-676):

```rust
    // Send to Parquet S3 and/or local-disk via channel (non-blocking, independent
    // per target — a full/closed channel on one does not affect the other).
    if let Some(ref sender) = state.parquet_s3_sender
        && let Err(e) = sender.try_send(event.clone())
    {
        match e {
            tokio::sync::mpsc::error::TrySendError::Full(_) => {
                warn!("WEF Parquet S3 channel full, dropping event");
            }
            tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                error!("WEF Parquet S3 channel closed");
            }
        }
    }
    if let Some(ref sender) = state.parquet_local_sender
        && let Err(e) = sender.try_send(event.clone())
    {
        match e {
            tokio::sync::mpsc::error::TrySendError::Full(_) => {
                warn!("WEF Parquet local channel full, dropping event");
            }
            tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                error!("WEF Parquet local channel closed");
            }
        }
    }
```

Note: `event: Arc<WindowsEvent>` — `event.clone()` is a cheap `Arc::clone`, not a data clone, so cloning it once per target (as the pre-existing code already did for the forwarder call above this block) has no meaningful cost.

- [ ] **Step 5: Fix the two test-helper `AppState` literals**

In `src/server/mod.rs`'s `build_state_with_config` (around line 736-748):

```rust
    async fn build_state_with_config(config: Config) -> Arc<AppState> {
        let forwarder = Forwarder::new(config.forwarding.destinations.clone())
            .initialize()
            .await;
        Arc::new(AppState {
            config: Arc::new(RwLock::new(config)),
            throughput: Arc::new(ThroughputStats::new()),
            forwarder,
            parser: WefParser::new(),
            event_parser: None,
            parquet_s3_sender: None,
            parquet_local_sender: None,
        })
    }
```

In `tests/otlp_e2e.rs`'s `build_app_state` (around line 81-100):

```rust
    async fn build_app_state(bearer_token: Option<String>) -> Arc<AppState> {
        let config = Config {
            otlp: OtlpConfig {
                enabled: true,
                bearer_token,
            },
            ..Default::default()
        };
        let forwarder = Forwarder::new(config.forwarding.destinations.clone())
            .initialize()
            .await;
        Arc::new(AppState {
            config: Arc::new(RwLock::new(config)),
            throughput: Arc::new(ThroughputStats::new()),
            forwarder,
            parser: WefParser::new(),
            event_parser: None,
            parquet_s3_sender: None,
            parquet_local_sender: None,
        })
    }
```

- [ ] **Step 6: Update `src/main.rs`'s shutdown wiring**

Replace line 471:

```rust
    let wef_worker_handles = server.take_wef_worker_handles();
```

Replace the `all_writer_handles` block (currently lines 566-570):

```rust
    let mut all_writer_handles = writer_handles;
    all_writer_handles.extend(wef_worker_handles);
    all_writer_handles.extend(hec_worker_handles);
```

- [ ] **Step 7: Build and run the full test suite**

Run: `CC=/usr/bin/gcc CXX=/usr/bin/g++ cargo build --quiet`
Expected: builds cleanly, no errors

Run: `CC=/usr/bin/gcc CXX=/usr/bin/g++ cargo test --quiet`
Expected: all tests pass, 0 failed

- [ ] **Step 8: Verify fmt and clippy**

Run: `cargo fmt --all -- --check`
Expected: no output (clean)

Run: `CC=/usr/bin/gcc CXX=/usr/bin/g++ cargo clippy --all-targets --quiet -- -D warnings`
Expected: no output (clean)

- [ ] **Step 9: Commit**

```bash
git add src/server/mod.rs src/main.rs tests/otlp_e2e.rs
git commit -m "feat(server): wire wef.local construction, dispatch, plural wef worker handles"
```

---

### Task 4: End-to-end integration test — real Parquet round-trip through `LocalDiskSink`

**Files:**
- Create: `tests/wef_local_integration.rs`

**Interfaces:**
- Consumes: `WefLocalConfig` (Task 1), `wef_local_start` (Task 2), `LocalDiskSink::new`, `WindowsEvent`, `ParsedEvent`.
- Produces: nothing consumed by later tasks except Task 5's docker-based verification, which is independent (Rust-level vs. container-level).

- [ ] **Step 1: Write the integration test**

```rust
//! End-to-end integration test: WEF events pushed through `wef_local_start`
//! land as real, readable Parquet files on local disk.

use bytes::Bytes;
use logthing::config::WefLocalConfig;
use logthing::forwarding::local_sink::LocalDiskSink;
use logthing::forwarding::parquet_s3::wef_local_start;
use logthing::models::{EventLevel, ParsedEvent, WindowsEvent};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use std::path::Path;
use std::sync::Arc;

fn walk_all_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            walk_all_files(&path, out);
        } else {
            out.push(path);
        }
    }
}

fn make_parsed_event(host: &str, event_id: u32) -> Arc<WindowsEvent> {
    let parsed = ParsedEvent {
        provider: "Security".into(),
        event_id,
        level: EventLevel::Information,
        task: 0,
        opcode: 0,
        keywords: 0,
        time_created: chrono::Utc::now(),
        event_record_id: 1,
        process_id: None,
        thread_id: None,
        channel: "Security".into(),
        computer: "HOST".into(),
        security_user_id: None,
        message: None,
        data: None,
    };
    Arc::new(WindowsEvent::new(host.into(), "<Event/>".into()).with_parsed(parsed))
}

#[tokio::test]
async fn wef_events_appear_as_parquet_on_local_disk() {
    let tmp = tempfile::tempdir().unwrap();
    let sink = Arc::new(
        LocalDiskSink::new(tmp.path().to_path_buf())
            .await
            .expect("LocalDiskSink constructs"),
    );

    let cfg = WefLocalConfig {
        directory: tmp.path().to_path_buf(),
        prefix: "".to_string(),
        flush_threshold_bytes: usize::MAX,
        flush_interval_secs: 3600,
        channel_capacity: 256,
        max_buffer_rows: 100_000,
    };

    let (handle, join_handle) = wef_local_start(
        &cfg,
        sink,
        Arc::new(logthing::stats::SourceHourlyStats::new()),
    );

    let event1 = make_parsed_event("host-a", 4624);
    let event2 = make_parsed_event("host-b", 4624);

    handle.try_send(event1).expect("send event1");
    handle.try_send(event2).expect("send event2");

    // Drop the handle to close the channel and trigger the shutdown flush.
    drop(handle);
    tokio::time::timeout(std::time::Duration::from_secs(5), join_handle)
        .await
        .expect("writer task must exit within 5s")
        .expect("writer task must not panic");

    // Find every file under the tempdir; there must be no leftover .tmp- files.
    let mut all_files = Vec::new();
    walk_all_files(tmp.path(), &mut all_files);
    assert!(
        !all_files
            .iter()
            .any(|p| p.file_name().unwrap().to_string_lossy().contains(".tmp-")),
        "no leftover .tmp- files should remain after flush: {all_files:?}"
    );

    let parquet_files: Vec<_> = all_files
        .iter()
        .filter(|p| p.extension().is_some_and(|e| e == "parquet"))
        .collect();
    assert_eq!(
        parquet_files.len(),
        1,
        "expected exactly 1 Parquet file (both events share event_id 4624); found {parquet_files:?}"
    );

    // Empty prefix must preserve the legacy event_type=<id>/year=… root layout.
    let rel_path = parquet_files[0]
        .strip_prefix(tmp.path())
        .unwrap()
        .to_string_lossy();
    assert!(
        rel_path.starts_with("event_type=4624/"),
        "path must start with event_type=4624/, got {rel_path}"
    );

    let raw = std::fs::read(parquet_files[0]).unwrap();
    let buf = Bytes::from(raw);
    let builder = ParquetRecordBatchReaderBuilder::try_new(buf).unwrap();
    let schema = builder.schema().clone();
    assert_eq!(schema.fields().len(), 5);

    let mut reader = builder.build().unwrap();
    let rb = reader
        .next()
        .expect("at least one record batch")
        .expect("record batch reads without error");
    assert_eq!(rb.num_rows(), 2);

    use arrow::array::{Array, StringArray, UInt32Array};
    let event_ids = rb
        .column_by_name("event_id")
        .unwrap()
        .as_any()
        .downcast_ref::<UInt32Array>()
        .unwrap();
    assert_eq!(event_ids.value(0), 4624);
    assert_eq!(event_ids.value(1), 4624);

    let hosts = rb
        .column_by_name("source_host")
        .unwrap()
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    assert_eq!(hosts.value(0), "host-a");
    assert_eq!(hosts.value(1), "host-b");
    assert!(!hosts.is_null(0));
}
```

- [ ] **Step 2: Run the test to verify it passes**

Run: `CC=/usr/bin/gcc CXX=/usr/bin/g++ cargo test --quiet --test wef_local_integration -- --nocapture`
Expected: PASS, 1 passed

- [ ] **Step 3: Verify fmt and clippy**

Run: `cargo fmt --all -- --check`
Expected: no output (clean)

Run: `CC=/usr/bin/gcc CXX=/usr/bin/g++ cargo clippy --all-targets --quiet -- -D warnings`
Expected: no output (clean)

- [ ] **Step 4: Run the full workspace test suite one last time**

Run: `CC=/usr/bin/gcc CXX=/usr/bin/g++ cargo test --quiet`
Expected: all tests pass, 0 failed

- [ ] **Step 5: Commit**

```bash
git add tests/wef_local_integration.rs
git commit -m "test(wef): integration test proving real Parquet round-trip through LocalDiskSink"
```

---

### Task 5: e2e docker-compose coverage — `wef-local-verifier`

**Files:**
- Create: `tests/e2e/simulation-environment/wef-local-verifier/Dockerfile`
- Create: `tests/e2e/simulation-environment/wef-local-verifier/entrypoint.py`
- Modify: `tests/e2e/simulation-environment/docker-compose.yml` (add `wef-local-data` volume; add `[wef.local]` mount to the `logthing` service; add `wef-local-verifier` service)
- Modify: `tests/e2e/simulation-environment/config/logthing.toml` (add `[wef.local]` block after the existing `[wef.s3]` block, currently ending at line 77)
- Modify: `tests/e2e/simulation-environment/run.sh` (invoke `wef-local-verifier` in the "Standard E2E Tests" section, alongside the existing `s3-verifier` call)

**Interfaces:**
- Consumes: nothing from earlier Rust-level tasks directly (this is container-level verification, independent of Task 4's Rust test) — it exercises the built `logthing:e2e` image's real `[wef.local]` config support from Tasks 1-3.
- Produces: nothing consumed by later tasks — this is the last task in the plan.

- [ ] **Step 1: Create the verifier Dockerfile**

Mirror `tests/e2e/simulation-environment/ipfix-local-verifier/Dockerfile` exactly, substituting the directory name:

```dockerfile
FROM python:3.12-slim

RUN pip install --no-cache-dir pyarrow

COPY wef-local-verifier/entrypoint.py /entrypoint.py

ENTRYPOINT ["python3", "/entrypoint.py"]
```

- [ ] **Step 2: Create the verifier entrypoint script**

Mirror `tests/e2e/simulation-environment/ipfix-local-verifier/entrypoint.py`'s structure, adapted to WEF's 5-column schema and `event_type=<id>/` path layout (not a fixed `ipfix/` prefix — WEF's empty prefix means files land directly under `event_type=<id>/year=…`, so the glob pattern is `event_type=*/**/*.parquet`, not `wef/**/*.parquet`):

```python
#!/usr/bin/env python3
"""
WEF local-disk verifier for E2E testing.

Walks a local directory tree (shared volume with the `logthing` container)
for Parquet objects under event_type=*/, downloads each, and validates
schema and row count. Mirrors ipfix-local-verifier/entrypoint.py's checks,
applied to WEF's empty-prefix event_type=<id>/year=… layout instead of a
fixed source-name prefix.
"""

import glob
import os
import sys
import time

import pyarrow.parquet as pq

WEF_LOCAL_DIR = os.environ.get("WEF_LOCAL_DIR", "/var/log/wef-local")
TIMEOUT = int(os.environ.get("E2E_TIMEOUT_SECS", "60"))
MIN_ROWS = int(os.environ.get("EXPECTED_EVENT_TOTAL", "5"))

REQUIRED_COLUMNS = [
    "event_id",
    "timestamp",
    "source_host",
    "subscription_id",
    "event_data",
]


def scan_dir():
    """Read every .parquet file under WEF_LOCAL_DIR/event_type=*/**,
    return (total_rows, union_of_columns, file_count)."""
    pattern = os.path.join(WEF_LOCAL_DIR, "event_type=*", "**", "*.parquet")
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
    print("WEF local-disk verifier succeeded")
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(0)


if __name__ == "__main__":
    main()
```

- [ ] **Step 3: Wire the volume, mount, and service into `docker-compose.yml`**

Add `wef-local-data:` to the `volumes:` section (currently lines 397-399, alongside `zeek-local-data`/`ipfix-local-data`):

```yaml
volumes:
  zeek-local-data:
  ipfix-local-data:
  wef-local-data:
```

Add the `wef-local-data` mount to the `logthing` service's `volumes:` list (currently lines 12-15):

```yaml
    volumes:
      - ./config/logthing.toml:/etc/logthing/config.toml:ro
      - zeek-local-data:/var/log/zeek-local
      - ipfix-local-data:/var/log/ipfix-local
      - wef-local-data:/var/log/wef-local
```

Add the `wef-local-verifier` service, directly after the existing `s3-verifier` service block (currently ending at line 106):

```yaml
  wef-local-verifier:
    build:
      context: .
      dockerfile: wef-local-verifier/Dockerfile
    environment:
      - WEF_LOCAL_DIR=/var/log/wef-local
      - EXPECTED_EVENT_TOTAL=50
      - E2E_TIMEOUT_SECS=60
    volumes:
      - wef-local-data:/var/log/wef-local:ro
    depends_on:
      - wef-generator
      - logthing
    networks:
      - e2e
```

- [ ] **Step 4: Add `[wef.local]` to the e2e config**

Add directly after the existing `[wef.s3]` block (currently ending at line 77) in `tests/e2e/simulation-environment/config/logthing.toml`:

```toml
[wef.local]
directory             = "/var/log/wef-local"
flush_threshold_bytes = 1
flush_interval_secs   = 5
```

- [ ] **Step 5: Invoke the verifier in `run.sh`**

In the "Standard E2E Tests" section (currently lines 24-27), directly after the existing `s3-verifier` invocation:

```bash
docker compose -f "$COMPOSE_FILE" run --rm wef-generator
docker compose -f "$COMPOSE_FILE" run --rm syslog-generator
docker compose -f "$COMPOSE_FILE" run --rm s3-verifier
docker compose -f "$COMPOSE_FILE" run --rm wef-local-verifier
```

- [ ] **Step 6: Validate the compose file syntax**

Run: `docker compose -f tests/e2e/simulation-environment/docker-compose.yml config --quiet`
Expected: no output, exit code 0 (confirms valid YAML + service graph, without actually starting containers)

- [ ] **Step 7: Commit**

```bash
git add tests/e2e/simulation-environment/wef-local-verifier/ \
        tests/e2e/simulation-environment/docker-compose.yml \
        tests/e2e/simulation-environment/config/logthing.toml \
        tests/e2e/simulation-environment/run.sh
git commit -m "test(e2e): add wef-local-verifier docker-compose coverage for [wef.local]"
```

---

## Post-Plan Checklist (for the final whole-branch review)

1. `config.wef.local` absent from TOML still deserializes to `None`, and all pre-existing WEF config tests still pass unmodified.
2. `Server::new`'s WEF block independently attempts `.s3` and `.local`, logging-and-skipping each on its own failure — neither failure prevents the other target from constructing.
3. No `MultiWefHandler`-style trait-object wrapper introduced anywhere — `AppState` has exactly two concrete sibling `Option<ParquetWriterHandle<WefSink>>` fields, and `process_single_event` dispatches to both inline (no shared helper function, unlike HEC/generic, since there's only one call site).
4. `wef_worker_handles` is a `Vec` everywhere (Server struct, `take_wef_worker_handles`, `main.rs`), correctly bundling 0, 1, or 2 handles into the shutdown-flush deadline alongside `writer_handles` and `hec_worker_handles`.
5. No `build_wef_handle` wrapper introduced anywhere.
6. The e2e `wef-local-verifier` actually exercises the real `logthing:e2e` binary's `[wef.local]` support end-to-end (not just the Rust-level Task 4 test, which calls `wef_local_start` directly, bypassing HTTP/WEF-protocol ingestion entirely).
7. `cargo fmt --all -- --check` and `cargo clippy --all-targets --quiet -- -D warnings` both clean across the whole branch diff.
