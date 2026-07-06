# HEC/Generic Local-Disk Persistence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `LocalDiskSink` support to the HEC/generic ingest routes (`/services/collector/event`, `/services/collector/raw`, `/ingest`, and — when the `otlp` feature is enabled — `/v1/logs`), so `[hec.local]` can persist records to local disk as Parquet, independently of or alongside `[hec.s3]`.

**Architecture:** HEC/generic is structurally different from Zeek/Suricata/IPFIX/sFlow/syslog: there is no `Handler` trait and no long-lived listener to inject a trait object into. Instead, `IngestState` (an Axum `Extension`, cloned into every request) holds a concrete `Option<GenericS3Handler>` field (`generic_s3`) that each of 4 HTTP handler functions checks directly. This was confirmed correct and deliberate by a prior architecture review (`docs/superpowers/specs/2026-07-06-hec-wef-architecture-review.md`), which explicitly rejected introducing a `MultiHandler`-style trait-object fan-out wrapper for this source. This plan follows that guidance: add a **sibling** `Option<GenericS3Handler>` field, `generic_local`, to `IngestState`, and dispatch to both fields independently at each of the 4 call sites (no new trait, no `Vec<Arc<dyn Handler>>`).

**Tech Stack:** Rust, tokio, arrow/parquet, axum, existing `UploadSink`/`ParquetSink`/`start_writer<S>` — no new dependencies.

## Global Constraints

- `GenericLocalConfig` mirrors `HecS3Config`'s flush-policy shape (swapping the S3 connection for a root directory), reusing the exact same default functions: `default_hec_s3_prefix`, `default_hec_flush_bytes`, `default_hec_flush_secs`, `default_hec_channel_capacity`, `default_hec_max_buffer_rows`. Unlike `SyslogLocalConfig`, `GenericLocalConfig` DOES have a `flush_threshold_bytes` field — `HecS3Config` already has one, so keep parity with it.
- `hec_start` and the new `hec_local_start` must both call `crate::forwarding::buffered_writer::start_writer::<GenericSink>(...)` directly — do NOT write a new `build_hec_handle` wrapper function. `max_partitions` stays a function parameter (not read from config inside the function), matching `hec_start`'s existing signature.
- `GenericSink` must gain `#[derive(Default)]` alongside its existing `#[derive(Clone)]` (required by `start_writer<S: ParquetSink + Default>`'s bound).
- Do **NOT** introduce any `MultiGenericHandler`/`MultiHecHandler`-style trait-object fan-out wrapper. `IngestState` gets a second concrete field, `generic_local: Option<GenericS3Handler>` (same handle type as `generic_s3` — both are `ParquetWriterHandle<GenericSink>` under the hood, just constructed from different sinks). Dispatch to both fields independently, in a plain function, not via a trait object collection. This is a deliberate, reviewed divergence from the Zeek/Suricata/IPFIX/sFlow/syslog pattern, not an oversight.
- Adding a field to `IngestState` breaks every existing struct-literal construction site in the workspace (Rust does not default-fill un-listed fields without `..Default::default()`). There are 7 such sites across 5 files — enumerated per-task below. Every one must be updated in the task that changes the struct, or the workspace will not compile between tasks.
- `Server`'s `hec_worker_handle: Option<JoinHandle<()>>` field must become `hec_worker_handles: Vec<JoinHandle<()>>` (HEC can now have up to 2 writer tasks — S3 and local — both of which must be awaited at shutdown). `take_hec_worker_handle()` becomes `take_hec_worker_handles() -> Vec<JoinHandle<()>>`. `main.rs`'s shutdown sequence extends `all_writer_handles` with the returned `Vec` instead of pushing a single `Option`.
- The OTLP handler (`handle_otlp_logs`, `#[cfg(feature = "otlp")]` in `src/server/mod.rs`) is a 4th call site that must also dispatch to `generic_local`, alongside the 3 in `src/ingest/handlers.rs`. It does NOT increment the `hec_events_dropped` metric on drop today (only `warn!`/`error!` logs) — preserve that existing asymmetry; do not add a new metric there.
- No new Cargo dependencies. No new Cargo features.
- This plan does NOT add e2e (docker-compose simulation-environment) coverage — matching the precedent set for Suricata, sFlow, and syslog (all merged without e2e; confirmed no `hec`/`splunk` service exists anywhere in `tests/e2e/simulation-environment/docker-compose.yml`). The existing Rust-level e2e-style tests `tests/hec_e2e.rs` and `tests/otlp_e2e.rs` (full-router, real-HTTP, no S3/local backing — validate HTTP behavior only) remain in scope only for the trivial one-line `IngestState` literal fix; they are not expanded with new test cases by this plan.
- Every new test function name must be distinct from existing ones in the same file.
- **Rustfmt note:** a prior plan in this series (IPFIX) shipped test snippets that weren't themselves rustfmt-clean, which slipped through both implementation and per-task review and was only caught at the final whole-branch review. Every code block below has been pre-verified against a real `rustfmt` run at its exact nesting depth — copy it verbatim, and still run `cargo fmt --all -- --check` as directed in each task's steps to confirm.

---

### Task 1: Add `GenericLocalConfig` to `src/config/mod.rs`

**Files:**
- Modify: `src/config/mod.rs` (add `GenericLocalConfig` struct after `HecS3Config`'s default functions, currently ending at line 555; add `local` field to `HecConfig` at lines 557-573 and its `Default` impl at lines 582-590)
- Test: same file's `#[cfg(test)] mod tests` block

**Interfaces:**
- Consumes: `default_hec_s3_prefix`, `default_hec_flush_bytes`, `default_hec_flush_secs`, `default_hec_channel_capacity`, `default_hec_max_buffer_rows` (all already exist at lines 541-555).
- Produces: `pub struct GenericLocalConfig { pub directory: PathBuf, pub prefix: String, pub flush_threshold_bytes: usize, pub flush_interval_secs: u64, pub channel_capacity: usize, pub max_buffer_rows: usize }`, and `HecConfig.local: Option<GenericLocalConfig>` — both consumed by Task 2 (`generic_s3.rs`) and Task 4 (`server/mod.rs`).

- [ ] **Step 1: Write the failing tests**

Find the existing HEC config tests (search for a test name containing `hec` near the syslog/IPFIX test groups) and insert these three tests directly after the last `hec_s3_*` test in the existing `#[cfg(test)] mod tests { ... }` block in `src/config/mod.rs`:

```rust
    #[test]
    fn hec_local_absent_gives_none() {
        let cfg = Config::default();
        assert!(
            cfg.hec.local.is_none(),
            "absent [hec.local] must deserialize to None"
        );
    }

    #[test]
    fn hec_local_config_deserializes_from_toml() {
        let toml_str = r#"
directory = "/var/log/logthing/hec"
prefix = "hec"
flush_threshold_bytes = 52428800
flush_interval_secs = 300
channel_capacity = 512
max_buffer_rows = 50000
"#;
        let cfg: GenericLocalConfig = toml::from_str(toml_str).expect("deserialize");
        assert_eq!(cfg.directory, std::path::PathBuf::from("/var/log/logthing/hec"));
        assert_eq!(cfg.prefix, "hec");
        assert_eq!(cfg.flush_threshold_bytes, 52_428_800);
        assert_eq!(cfg.flush_interval_secs, 300);
        assert_eq!(cfg.channel_capacity, 512);
        assert_eq!(cfg.max_buffer_rows, 50_000);
    }

    #[test]
    fn hec_local_config_defaults_apply_when_only_directory_given() {
        let toml_str = r#"directory = "/data/hec""#;
        let cfg: GenericLocalConfig = toml::from_str(toml_str).expect("deserialize");
        assert_eq!(cfg.prefix, "hec");
        assert_eq!(cfg.flush_threshold_bytes, 100 * 1024 * 1024);
        assert_eq!(cfg.flush_interval_secs, 900);
        assert_eq!(cfg.channel_capacity, 256);
        assert_eq!(cfg.max_buffer_rows, 100_000);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --quiet hec_local`
Expected: FAIL with "cannot find type `GenericLocalConfig`" / "no field `local` on type `HecConfig`"

- [ ] **Step 3: Add `GenericLocalConfig` struct and wire `HecConfig.local`**

Add this struct directly after `default_hec_max_buffer_rows` (currently ending at line 555):

```rust
/// Per-source local-disk persistence config for HEC/generic ingest.
/// Mirrors `HecS3Config`'s flush-policy shape (reusing the same default
/// functions), swapping the S3 connection for a root directory.
/// Independent of `s3`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GenericLocalConfig {
    /// Root directory Parquet files are written under (created if missing).
    pub directory: PathBuf,
    /// Key prefix, slash-free (default: `"hec"` — same default as `hec.s3`).
    #[serde(default = "default_hec_s3_prefix")]
    pub prefix: String,
    /// Flush when estimated buffer bytes exceeds this (default: 100 MiB).
    #[serde(default = "default_hec_flush_bytes")]
    pub flush_threshold_bytes: usize,
    /// Flush after this many seconds regardless of buffer size (default: 900).
    #[serde(default = "default_hec_flush_secs")]
    pub flush_interval_secs: u64,
    /// Bounded channel capacity (default: 256).
    #[serde(default = "default_hec_channel_capacity")]
    pub channel_capacity: usize,
    /// Maximum buffered rows before hard cap kicks in (default: 100_000).
    #[serde(default = "default_hec_max_buffer_rows")]
    pub max_buffer_rows: usize,
}
```

Then modify `HecConfig` (lines 557-573) to add the `local` field, directly after the existing `s3` field:

```rust
    /// Optional local-disk persistence. `None` → not persisted to local disk.
    /// Independent of `s3` — both may be configured simultaneously, in which
    /// case records are written to both.
    #[serde(default)]
    pub local: Option<GenericLocalConfig>,
```

Then modify `impl Default for HecConfig` (lines 582-590) to add `local: None,` directly after `s3: None,`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --quiet hec_local`
Expected: PASS, 3 tests ok

- [ ] **Step 5: Verify fmt and full config test suite**

Run: `cargo fmt --all -- --check`
Expected: no output (clean)

Run: `cargo test --quiet --lib config::`
Expected: all config tests pass, 0 failed

- [ ] **Step 6: Commit**

```bash
git add src/config/mod.rs
git commit -m "feat(config): add GenericLocalConfig, HecConfig.local"
```

---

### Task 2: `src/forwarding/generic_s3.rs` — migrate to `start_writer`, add `hec_local_start`

**Files:**
- Modify: `src/forwarding/generic_s3.rs`
- Test: same file's `#[cfg(test)] mod tests` block

**Interfaces:**
- Consumes: `GenericLocalConfig` (Task 1), `crate::forwarding::buffered_writer::start_writer::<S>` (existing, `pub(crate)`), `crate::forwarding::local_sink::LocalDiskSink` (existing).
- Produces: `hec_local_start(cfg: &GenericLocalConfig, sink: Arc<LocalDiskSink>, max_partitions: usize, source_stats: Arc<SourceHourlyStats>) -> (GenericS3Handler, JoinHandle<()>)` — consumed by Task 4 (`server/mod.rs`).

- [ ] **Step 1: Write the failing test**

Add this test to the existing `#[cfg(test)] mod tests { ... }` block in `src/forwarding/generic_s3.rs`, directly after `hec_start_wires_handler_and_join_handle`:

```rust
    #[tokio::test]
    async fn hec_local_start_wires_handler_and_join_handle() {
        use crate::config::GenericLocalConfig;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let sink = Arc::new(
            crate::forwarding::local_sink::LocalDiskSink::new(dir.path().to_path_buf())
                .await
                .expect("constructs"),
        );
        let cfg = GenericLocalConfig {
            directory: dir.path().to_path_buf(),
            prefix: "hec".to_string(),
            flush_threshold_bytes: usize::MAX,
            flush_interval_secs: 3600,
            channel_capacity: 256,
            max_buffer_rows: 100_000,
        };

        let (handler, join_handle) = hec_local_start(
            &cfg,
            sink,
            64,
            std::sync::Arc::new(crate::stats::SourceHourlyStats::new()),
        );
        handler
            .try_send(make_record("access_log"))
            .expect("send ok");
        drop(handler);
        tokio::time::timeout(std::time::Duration::from_secs(5), join_handle)
            .await
            .expect("writer exits within 5s")
            .expect("writer does not panic");
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --quiet --lib generic_s3::tests::hec_local_start_wires_handler_and_join_handle`
Expected: FAIL with "cannot find function `hec_local_start`"

- [ ] **Step 3: Add `#[derive(Default)]` to `GenericSink`, migrate `hec_start`, add `hec_local_start`**

Change:

```rust
#[derive(Clone)]
pub struct GenericSink;
```

to:

```rust
#[derive(Clone, Default)]
pub struct GenericSink;
```

Replace the entire `hec_start` function body with a call to `start_writer`:

```rust
/// Construct a `GenericS3Handler` from a `HecS3Config`, a pre-built `S3Sink`,
/// and the maximum distinct sourcetype partition count.
///
/// Returns `(handler, writer_join_handle)`.  The caller retains the `JoinHandle`
/// and awaits it during graceful shutdown after all `GenericS3Handler` clones
/// have been dropped (closing the channel and triggering the final flush).
pub fn hec_start(
    cfg: &HecS3Config,
    s3: Arc<crate::forwarding::s3_sink::S3Sink>,
    max_partitions: usize,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
) -> (GenericS3Handler, tokio::task::JoinHandle<()>) {
    crate::forwarding::buffered_writer::start_writer::<GenericSink>(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        cfg.flush_threshold_bytes,
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        max_partitions,
        s3,
        source_stats,
    )
}

/// Construct a `GenericS3Handler` from a `GenericLocalConfig` and a pre-built
/// `LocalDiskSink`. Structurally identical to `hec_start`, writing to local
/// disk instead of S3 — same `GenericSink` adapter, same buffering/flush/cap
/// machinery, same S3-key-shaped relative path layout on disk.
pub fn hec_local_start(
    cfg: &crate::config::GenericLocalConfig,
    sink: Arc<crate::forwarding::local_sink::LocalDiskSink>,
    max_partitions: usize,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
) -> (GenericS3Handler, tokio::task::JoinHandle<()>) {
    crate::forwarding::buffered_writer::start_writer::<GenericSink>(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        cfg.flush_threshold_bytes,
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        max_partitions,
        sink,
        source_stats,
    )
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --quiet --lib generic_s3::`
Expected: PASS, all generic_s3 tests ok (existing + 1 new)

- [ ] **Step 5: Verify fmt and clippy**

Run: `cargo fmt --all -- --check`
Expected: no output (clean)

Run: `CC=/usr/bin/gcc CXX=/usr/bin/g++ cargo clippy --all-targets --quiet -- -D warnings`
Expected: no output (clean)

- [ ] **Step 6: Commit**

```bash
git add src/forwarding/generic_s3.rs
git commit -m "feat(forwarding): add hec_local_start, migrate hec_start to start_writer"
```

---

### Task 3: Add `generic_local` to `IngestState`; dispatch in the 3 HEC/NDJSON handlers

**Files:**
- Modify: `src/ingest/mod.rs` (struct at lines 46-52; its own test literal at line 127)
- Modify: `src/ingest/handlers.rs` (extract a shared dispatch helper; update 3 call sites at lines 94-108, 143-155, 190-204; its own test literal at line 221)
- Modify (trivial, keep workspace compiling — real local wiring comes in Task 4): `src/server/mod.rs` (3 literals: the real construction at line ~221, and 2 test literals at lines 1747 and 2082), `tests/hec_e2e.rs` (line 29), `tests/otlp_e2e.rs` (line 109)

**Interfaces:**
- Consumes: `GenericS3Handler` (existing type alias for `ParquetWriterHandle<GenericSink>`, same type used for both S3 and local — no new type needed).
- Produces: `IngestState.generic_local: Option<GenericS3Handler>`, a private `dispatch_generic_record(ingest: &IngestState, record: GenericRecord, context: &str)` helper in `src/ingest/handlers.rs` — the helper is consumed by Task 4's OTLP-handler change only as a reference pattern (OTLP lives in a different module and cannot call a private function in `ingest::handlers`, so it duplicates the same two-target dispatch inline; Task 4 has the exact code).

- [ ] **Step 1: Add the `generic_local` field to `IngestState`**

Modify `src/ingest/mod.rs`'s `IngestState` struct (lines 46-52):

```rust
#[derive(Clone, Default)]
pub struct IngestState {
    /// Generic S3 handler for HEC / NDJSON ingest routes.
    /// `None` when `[hec.s3]` is absent or construction failed.
    pub generic_s3: Option<GenericS3Handler>,
    /// Generic local-disk handler for HEC / NDJSON ingest routes.
    /// `None` when `[hec.local]` is absent or construction failed.
    /// Independent of `generic_s3` — both may be `Some` simultaneously.
    pub generic_local: Option<GenericS3Handler>,
}
```

Update the two existing tests in `src/ingest/mod.rs` that construct `IngestState` literally (around line 127 and its neighbor `ingest_state_is_clone` test):

```rust
    #[test]
    fn ingest_state_default_has_no_handlers() {
        let state = IngestState::default();
        assert!(state.generic_s3.is_none());
        assert!(state.generic_local.is_none());
    }

    #[test]
    fn ingest_state_is_clone() {
        let state = IngestState {
            generic_s3: None,
            generic_local: None,
        };
        let cloned = state.clone();
        assert!(cloned.generic_s3.is_none());
        assert!(cloned.generic_local.is_none());
    }
```

- [ ] **Step 2: Extract a shared dispatch helper and update the 3 handlers in `src/ingest/handlers.rs`**

Add this private helper directly above `handle_hec_event` (after the `hec_parse_error` function, before the `// POST /services/collector/event` section comment):

```rust
// ---------------------------------------------------------------------------
// Shared dispatch — try both persistence targets independently
// ---------------------------------------------------------------------------

/// Try-send one record to every configured HEC/generic persistence target
/// (`.s3` and/or `.local`), independently. A full/closed channel on one
/// target does not affect delivery to the other — each is attempted and
/// logged separately. `context` is a short phrase describing what was
/// dropped (e.g. `"1 record"`, `"raw record"`), reused in both targets' log
/// lines to match the wording already used for the S3-only path.
///
/// HEC/generic has no `Handler` trait to abstract a fan-out over (unlike
/// Zeek/Suricata/IPFIX/sFlow/syslog) — `IngestState` holds concrete sibling
/// `Option<GenericS3Handler>` fields instead, per the architecture review's
/// explicit rejection of a `MultiHandler`-style wrapper for this source.
fn dispatch_generic_record(
    ingest: &IngestState,
    record: crate::ingest::GenericRecord,
    context: &str,
) {
    if let Some(ref handler) = ingest.generic_s3
        && let Err(e) = handler.try_send(record.clone())
    {
        metrics::counter!("hec_events_dropped").increment(1);
        match e {
            tokio::sync::mpsc::error::TrySendError::Full(_) => {
                tracing::warn!("HEC S3 channel full; dropped {context}");
            }
            tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                tracing::error!("HEC S3 channel closed; dropped {context}");
            }
        }
    }
    if let Some(ref handler) = ingest.generic_local
        && let Err(e) = handler.try_send(record)
    {
        metrics::counter!("hec_events_dropped").increment(1);
        match e {
            tokio::sync::mpsc::error::TrySendError::Full(_) => {
                tracing::warn!("HEC local channel full; dropped {context}");
            }
            tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                tracing::error!("HEC local channel closed; dropped {context}");
            }
        }
    }
}
```

Replace `handle_hec_event`'s dispatch block (lines 94-108):

```rust
    if let Some(ref handler) = ingest.generic_s3 {
        for rec in records {
            if let Err(e) = handler.try_send(rec) {
                metrics::counter!("hec_events_dropped").increment(1);
                match e {
                    tokio::sync::mpsc::error::TrySendError::Full(_) => {
                        tracing::warn!("HEC S3 channel full; dropped 1 record");
                    }
                    tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                        tracing::error!("HEC S3 channel closed; dropped 1 record");
                    }
                }
            }
        }
    }
```

with:

```rust
    for rec in records {
        dispatch_generic_record(&ingest, rec, "1 record");
    }
```

Replace `handle_hec_raw`'s dispatch block (lines 143-155):

```rust
    if let Some(ref handler) = ingest.generic_s3
        && let Err(e) = handler.try_send(record)
    {
        metrics::counter!("hec_events_dropped").increment(1);
        match e {
            tokio::sync::mpsc::error::TrySendError::Full(_) => {
                tracing::warn!("HEC S3 channel full; dropped raw record");
            }
            tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                tracing::error!("HEC S3 channel closed; dropped raw record");
            }
        }
    }
```

with:

```rust
    dispatch_generic_record(&ingest, record, "raw record");
```

Replace `handle_ndjson`'s dispatch block (lines 190-204):

```rust
    if let Some(ref handler) = ingest.generic_s3 {
        for rec in records {
            if let Err(e) = handler.try_send(rec) {
                metrics::counter!("hec_events_dropped").increment(1);
                match e {
                    tokio::sync::mpsc::error::TrySendError::Full(_) => {
                        tracing::warn!("HEC S3 channel full; dropped 1 NDJSON record");
                    }
                    tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                        tracing::error!("HEC S3 channel closed; dropped 1 NDJSON record");
                    }
                }
            }
        }
    }
```

with:

```rust
    for rec in records {
        dispatch_generic_record(&ingest, rec, "1 NDJSON record");
    }
```

- [ ] **Step 3: Update the remaining `IngestState` literal-construction sites so the workspace compiles**

In `src/ingest/handlers.rs`'s test module (line 221):

```rust
        let ingest_state = IngestState {
            generic_s3: None,
            generic_local: None,
        };
```

In `src/server/mod.rs`, update the real construction (inside the `if config.hec.enabled { ... }` block, currently around line 221) and the two test literals (currently around lines 1747 and 2082) — for THIS task, only append `generic_local: None,` to each so the crate compiles; Task 4 replaces the real construction with actual local-disk wiring:

```rust
        // (test literal, e.g. around line 1747 and 2082)
        let ingest_state = IngestState {
            generic_s3: None,
            generic_local: None,
        };
```

For the real construction inside `Server::new` (currently `IngestState { generic_s3: Some(handler) }` / `IngestState::default()` branches around lines 220-238), append `generic_local: None,` to the `Some(handler)` arm and leave the `IngestState::default()` arms as-is (already covers the new field via `#[derive(Default)]`):

```rust
                        (
                            IngestState {
                                generic_s3: Some(handler),
                                generic_local: None,
                            },
                            Some(join_handle),
                        )
```

In `tests/hec_e2e.rs` (line 29) and `tests/otlp_e2e.rs` (line 109):

```rust
    let ingest_state = IngestState {
        generic_s3: None,
        generic_local: None,
    };
```

- [ ] **Step 4: Run the full workspace build and test suite**

Run: `CC=/usr/bin/gcc CXX=/usr/bin/g++ cargo build --quiet`
Expected: builds cleanly, no errors

Run: `CC=/usr/bin/gcc CXX=/usr/bin/g++ cargo test --quiet`
Expected: all tests pass, 0 failed

- [ ] **Step 5: Verify fmt and clippy**

Run: `cargo fmt --all -- --check`
Expected: no output (clean)

Run: `CC=/usr/bin/gcc CXX=/usr/bin/g++ cargo clippy --all-targets --quiet -- -D warnings`
Expected: no output (clean)

- [ ] **Step 6: Commit**

```bash
git add src/ingest/mod.rs src/ingest/handlers.rs src/server/mod.rs tests/hec_e2e.rs tests/otlp_e2e.rs
git commit -m "feat(ingest): add IngestState.generic_local, dispatch in HEC/NDJSON handlers"
```

---

### Task 4: Wire real `[hec.local]` construction in `src/server/mod.rs`; OTLP dispatch; plural worker handles

**Files:**
- Modify: `src/server/mod.rs` (`Server` struct at lines 57-67; `Server::new`'s HEC block, now holding `generic_local: None` placeholders from Task 3, around lines 207-245; `take_hec_worker_handle` at lines 257-263; the OTLP handler's dispatch block at lines 2620-2636; the test at lines 2003-2018)
- Modify: `src/main.rs` (lines 471-472, 566-572)

**Interfaces:**
- Consumes: `GenericLocalConfig`, `hec_local_start` (Task 1/2), `LocalDiskSink::new` (existing), `IngestState.generic_local` (Task 3).
- Produces: real `[hec.local]` wiring; no new public interfaces for later tasks (last task touching HEC persistence wiring).

- [ ] **Step 1: Change `Server`'s `hec_worker_handle` field to a `Vec`**

Modify the `Server` struct (lines 57-67):

```rust
pub struct Server {
    config: Config,
    state: Arc<AppState>,
    /// JoinHandle for the WEF→S3 Parquet worker task, if one was started.
    /// Awaited during graceful shutdown so buffered data is flushed before exit.
    wef_worker_handle: Option<tokio::task::JoinHandle<()>>,
    /// Shared extension state for HEC / NDJSON ingest routes.
    ingest_state: IngestState,
    /// JoinHandles for the HEC→S3 and HEC→local Parquet worker tasks (0, 1, or 2
    /// present depending on how many of `[hec.s3]` / `[hec.local]` are configured
    /// and construct successfully). Awaited during graceful shutdown.
    hec_worker_handles: Vec<tokio::task::JoinHandle<()>>,
}
```

Modify `take_hec_worker_handle` (lines 257-263):

```rust
    /// Take the HEC persistence workers' JoinHandles for awaiting at shutdown.
    ///
    /// Must be called BEFORE `run`/`run_tls`; after the server consumes `self`
    /// the handles are no longer accessible. Returns 0, 1, or 2 handles
    /// depending on how many of `[hec.s3]` / `[hec.local]` constructed
    /// successfully.
    pub fn take_hec_worker_handles(&mut self) -> Vec<tokio::task::JoinHandle<()>> {
        std::mem::take(&mut self.hec_worker_handles)
    }
```

- [ ] **Step 2: Replace the HEC block in `Server::new` with independent-attempt wiring**

Replace the entire block built in Task 3 (the `if config.hec.enabled { ... }` section that currently produces `(ingest_state, hec_worker_handle)`, together with the trailing `Ok(Self { ... })` fields `hec_worker_handle,`) with:

```rust
        // --- Build IngestState for HEC / NDJSON ingest routes ---
        let mut hec_worker_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();
        let mut generic_s3_handler = None;
        let mut generic_local_handler = None;

        if config.hec.enabled {
            if let Some(s3_cfg) = config.hec.s3.as_ref() {
                match crate::forwarding::s3_sink::S3Sink::from_connection(&s3_cfg.connection).await
                {
                    Ok(sink) => {
                        info!("Initialized HEC Parquet S3 forwarder");
                        let (handler, join_handle) = crate::forwarding::generic_s3::hec_start(
                            s3_cfg,
                            Arc::new(sink),
                            config.hec.max_sourcetype_partitions,
                            source_stats.clone(),
                        );
                        hec_worker_handles.push(join_handle);
                        generic_s3_handler = Some(handler);
                    }
                    Err(e) => {
                        error!("Failed to create S3Sink for HEC ingest, skipping S3 target: {e}");
                    }
                }
            }

            if let Some(local_cfg) = config.hec.local.as_ref() {
                match crate::forwarding::local_sink::LocalDiskSink::new(local_cfg.directory.clone())
                    .await
                {
                    Ok(sink) => {
                        info!("Initialized HEC Parquet local-disk forwarder");
                        let (handler, join_handle) = crate::forwarding::generic_s3::hec_local_start(
                            local_cfg,
                            Arc::new(sink),
                            config.hec.max_sourcetype_partitions,
                            source_stats.clone(),
                        );
                        hec_worker_handles.push(join_handle);
                        generic_local_handler = Some(handler);
                    }
                    Err(e) => {
                        error!(
                            "Failed to create LocalDiskSink for HEC ingest, skipping local target: {e}"
                        );
                    }
                }
            }
        }

        let ingest_state = IngestState {
            generic_s3: generic_s3_handler,
            generic_local: generic_local_handler,
        };
```

And in the `Ok(Self { ... })` construction, replace `hec_worker_handle,` with `hec_worker_handles,`.

- [ ] **Step 3: Add the `generic_local` dispatch branch to the OTLP handler**

Replace the OTLP handler's dispatch block (currently around lines 2620-2636):

```rust
    if let Some(ref handler) = ingest.generic_s3 {
        for record in records {
            if let Err(e) = handler.try_send(record) {
                match e {
                    tokio::sync::mpsc::error::TrySendError::Full(_) => {
                        warn!("OTLP generic_s3 channel full, dropping record");
                    }
                    tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                        error!("OTLP generic_s3 channel closed");
                    }
                }
            }
        }
    }
```

with:

```rust
    for record in records {
        if let Some(ref handler) = ingest.generic_s3
            && let Err(e) = handler.try_send(record.clone())
        {
            match e {
                tokio::sync::mpsc::error::TrySendError::Full(_) => {
                    warn!("OTLP generic_s3 channel full, dropping record");
                }
                tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                    error!("OTLP generic_s3 channel closed");
                }
            }
        }
        if let Some(ref handler) = ingest.generic_local
            && let Err(e) = handler.try_send(record)
        {
            match e {
                tokio::sync::mpsc::error::TrySendError::Full(_) => {
                    warn!("OTLP generic_local channel full, dropping record");
                }
                tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                    error!("OTLP generic_local channel closed");
                }
            }
        }
    }
```

Note: the previous code moved `records` into `for record in records` once; the replacement still consumes `records` exactly once (single loop), calling `.clone()` only for the `generic_s3` branch so the original `record` remains available for the `generic_local` branch afterward.

- [ ] **Step 4: Update the existing `take_hec_worker_handle` test (around lines 2003-2018)**

```rust
    #[tokio::test]
    async fn server_take_hec_worker_handles_returns_empty_when_hec_disabled() {
        let mut server = Server::new(
            Config::default(),
            Arc::new(RwLock::new(Config::default())),
            Arc::new(ThroughputStats::new()),
            std::sync::Arc::new(crate::stats::SourceHourlyStats::new()),
        )
        .await
        .unwrap();
        let handles = server.take_hec_worker_handles();
        assert!(
            handles.is_empty(),
            "hec worker handles must be empty when hec.enabled=false"
        );
    }
```

- [ ] **Step 5: Update `src/main.rs`'s shutdown wiring**

Replace lines 471-472:

```rust
    let wef_worker_handle = server.take_wef_worker_handle();
    let hec_worker_handles = server.take_hec_worker_handles();
```

Replace the `all_writer_handles` block (currently lines 566-572):

```rust
    let mut all_writer_handles = writer_handles;
    if let Some(wef_handle) = wef_worker_handle {
        all_writer_handles.push(wef_handle);
    }
    all_writer_handles.extend(hec_worker_handles);
```

- [ ] **Step 6: Build and run the full test suite**

Run: `CC=/usr/bin/gcc CXX=/usr/bin/g++ cargo build --quiet`
Expected: builds cleanly, no errors

Run: `CC=/usr/bin/gcc CXX=/usr/bin/g++ cargo test --quiet`
Expected: all tests pass, 0 failed

- [ ] **Step 7: Verify fmt and clippy**

Run: `cargo fmt --all -- --check`
Expected: no output (clean)

Run: `CC=/usr/bin/gcc CXX=/usr/bin/g++ cargo clippy --all-targets --quiet -- -D warnings`
Expected: no output (clean)

- [ ] **Step 8: Commit**

```bash
git add src/server/mod.rs src/main.rs
git commit -m "feat(server): wire hec.local construction, OTLP dispatch, plural hec worker handles"
```

---

### Task 5: End-to-end integration test — real Parquet round-trip through `LocalDiskSink`

**Files:**
- Create: `tests/hec_local_integration.rs`

**Interfaces:**
- Consumes: `GenericLocalConfig` (Task 1), `hec_local_start` (Task 2), `LocalDiskSink::new`, `GenericRecord`.
- Produces: nothing consumed by later tasks — this is the last task in the plan.

- [ ] **Step 1: Write the integration test**

```rust
//! End-to-end integration test: HEC/generic records pushed through
//! `hec_local_start` land as real, readable Parquet files on local disk.

use bytes::Bytes;
use logthing::config::GenericLocalConfig;
use logthing::forwarding::generic_s3::hec_local_start;
use logthing::forwarding::local_sink::LocalDiskSink;
use logthing::ingest::GenericRecord;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use std::path::Path;

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

#[tokio::test]
async fn hec_records_appear_as_parquet_on_local_disk() {
    let tmp = tempfile::tempdir().unwrap();
    let sink = std::sync::Arc::new(
        LocalDiskSink::new(tmp.path().to_path_buf())
            .await
            .expect("LocalDiskSink constructs"),
    );

    let cfg = GenericLocalConfig {
        directory: tmp.path().to_path_buf(),
        prefix: "hec".to_string(),
        flush_threshold_bytes: usize::MAX,
        flush_interval_secs: 3600,
        channel_capacity: 256,
        max_buffer_rows: 100_000,
    };

    let (handler, join_handle) = hec_local_start(
        &cfg,
        sink,
        64,
        std::sync::Arc::new(logthing::stats::SourceHourlyStats::new()),
    );

    let rec1 = GenericRecord {
        sourcetype: "access_log".to_string(),
        host: Some("host-a".to_string()),
        time: Some(chrono::Utc::now()),
        fields: serde_json::json!({"action": "login", "user": "alice"}),
        received_at: chrono::Utc::now(),
    };
    let rec2 = GenericRecord {
        sourcetype: "access_log".to_string(),
        host: Some("host-b".to_string()),
        time: None,
        fields: serde_json::json!({"action": "logout", "user": "bob"}),
        received_at: chrono::Utc::now(),
    };

    handler.try_send(rec1).expect("send rec1");
    handler.try_send(rec2).expect("send rec2");

    // Drop the handler to close the channel and trigger the shutdown flush.
    drop(handler);
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
        "expected exactly 1 Parquet file (both records share sourcetype 'access_log'); found {parquet_files:?}"
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

    use arrow::array::{Array, StringArray};
    let hosts = rb
        .column_by_name("host")
        .unwrap()
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    assert_eq!(hosts.value(0), "host-a");
    assert_eq!(hosts.value(1), "host-b");

    let fields_col = rb
        .column_by_name("fields")
        .unwrap()
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(fields_col.value(0)).expect("fields must be valid JSON");
    assert_eq!(parsed["user"], "alice");
}
```

- [ ] **Step 2: Run the test to verify it passes**

Run: `CC=/usr/bin/gcc CXX=/usr/bin/g++ cargo test --quiet --test hec_local_integration -- --nocapture`
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
git add tests/hec_local_integration.rs
git commit -m "test(hec): integration test proving real Parquet round-trip through LocalDiskSink"
```

---

## Post-Plan Checklist (for the final whole-branch review)

1. `config.hec.local` absent from TOML still deserializes to `None`, and all pre-existing HEC config tests still pass unmodified.
2. `Server::new`'s HEC block independently attempts `.s3` and `.local`, logging-and-skipping each on its own failure — neither failure prevents the other target from constructing.
3. No `MultiGenericHandler`/`MultiHecHandler`-style trait-object wrapper introduced anywhere — `IngestState` has exactly two concrete sibling `Option<GenericS3Handler>` fields.
4. All 4 real dispatch call sites (`handle_hec_event`, `handle_hec_raw`, `handle_ndjson`, `handle_otlp_logs`) send to both `generic_s3` and `generic_local` independently — a failure on one target does not skip the other.
5. `hec_worker_handles` is a `Vec` everywhere (Server struct, `take_hec_worker_handles`, `main.rs`), correctly bundling 0, 1, or 2 handles into the shutdown-flush deadline alongside `writer_handles` and the WEF handle.
6. No `build_hec_handle`/`build_generic_handle` wrapper introduced anywhere.
7. `cargo fmt --all -- --check` and `cargo clippy --all-targets --quiet -- -D warnings` both clean across the whole branch diff.
