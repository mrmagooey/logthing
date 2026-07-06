# Syslog Local-Disk Persistence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `LocalDiskSink` support to syslog, so `[syslog.local]` can persist raw syslog messages to local disk as Parquet, independently of or alongside `[syslog.s3]`. Structured (payload-parsed) syslog persistence (`[syslog.structured_s3]`) is explicitly OUT of scope — it is a separate follow-on, not touched by this plan.

**Architecture:** Mirror the IPFIX/Suricata/sFlow pattern already merged to master: `syslog_start` currently inlines `BufferedWriterConfig`/`FlushPolicy` construction directly (unlike IPFIX/Suricata/sFlow, which already call the shared `start_writer` helper) — migrate it to call `crate::forwarding::buffered_writer::start_writer::<SyslogSink>` directly (no new `build_syslog_handle` wrapper), add a new `syslog_local_start`, and add a `MultiSyslogHandler` fan-out wrapper. Syslog has one added wrinkle the other four sources don't: `syslog::listener::PayloadDispatchingHandler<H>` already wraps the S3 persistence handler to additionally run payload dispatch (CEF/LEEF/auditd/DHCP/RADIUS/web_access/DNS) and forward matched records to the structured sink. That decorator must keep wrapping the *combined* persistence handler, not be replaced by it: build `MultiSyslogHandler` (or reuse the single handler directly when only one persistence target is configured) first, at the *persistence* layer, then pass that as `PayloadDispatchingHandler`'s `inner`. To keep `PayloadDispatchingHandler<H: SyslogHandler>`'s generic parameter concrete (avoiding a `?Sized` relaxation to accept `Arc<dyn SyslogHandler>` as `H`), this plan always constructs `MultiSyslogHandler` when at least one persistence target succeeds — even for exactly one target — rather than the 3-arm `0/1/many` match IPFIX/sFlow/Suricata use. This is a deliberate, documented divergence from those three siblings, not an oversight.

**Tech Stack:** Rust, tokio, arrow/parquet, existing `UploadSink`/`ParquetSink`/`start_writer<S>` — no new dependencies.

## Global Constraints

- `SyslogLocalConfig`'s flush-policy fields reuse the exact same default functions as `SyslogS3Config` (`default_syslog_s3_prefix`, `default_syslog_s3_max_rows`, `default_syslog_s3_flush_interval_secs`, `default_syslog_s3_channel_capacity`). Unlike Suricata/IPFIX/sFlow's local configs, `SyslogLocalConfig` has **no** `flush_threshold_bytes` field — `SyslogS3Config` doesn't have one either (syslog uses row-count + age triggers only; `syslog_start` hardcodes `flush_threshold_bytes: usize::MAX`). Do not add a byte-threshold field or default function that doesn't already exist.
- `syslog_start` and the new `syslog_local_start` must both call `crate::forwarding::buffered_writer::start_writer::<SyslogSink>(...)` directly with `flush_threshold_bytes = usize::MAX` and `max_partitions = 1` — do NOT write a new `build_syslog_handle` wrapper function.
- `SyslogSink` must gain `#[derive(Default)]` (required by `start_writer<S: ParquetSink + Default>`'s bound), matching `SuricataSink`/`SflowSink`/`IpfixSink`.
- `MultiSyslogHandler`'s record type is a single `SyslogMessage` (not a batch — syslog's `SyslogHandler::handle_message` takes one message at a time, unlike IPFIX/sFlow's `Vec`-based batch handlers) — cloning the message once per destination via `message.clone()` (`SyslogMessage` already derives `Clone`).
- Do **not** modify `syslog::listener::PayloadDispatchingHandler`'s generic bound (`H: SyslogHandler`) or its `inner: Arc<H>` field type. `main.rs`'s wiring must produce a concrete `Arc<MultiSyslogHandler>` (or the bare `Arc<SyslogS3Handler>` when only one persistence target is configured and you choose to skip the Multi wrapper for that one case — either is acceptable, but the safest, simplest, uniform choice that requires zero code branching is: always build `MultiSyslogHandler` once syslog_handlers is non-empty, regardless of length) to hand to `PayloadDispatchingHandler { inner: ..., ... }` as `H`.
- `DefaultSyslogHandler` (used when **no** persistence target — neither `.s3` nor `.local` — is configured) is unaffected by this plan: it keeps handling DNS-log parsing and its own internal payload dispatch exactly as today. `PayloadDispatchingHandler` must only wrap the persistence handler(s); it is never layered on top of `DefaultSyslogHandler`. This preserves the pre-existing, documented "S3 persistence and DNS-log parsing are mutually exclusive" behavior — now generalized to "any persistence (s3 and/or local) and DNS-log parsing are mutually exclusive" — unchanged in spirit, just extended to cover `.local` the same way `.s3` already worked.
- No new Cargo dependencies. No new Cargo features.
- This plan does NOT add e2e (docker-compose simulation-environment) coverage — matching the precedent set for Suricata and sFlow (both already merged without e2e). The existing e2e `config/logthing.toml` has a `[syslog.s3]` block verified generically by `s3-verifier`, but there is no per-source `syslog-s3-verifier`/`syslog-local-verifier` pair to extend, and adding one is out of scope here. The Rust-level integration test in Task 4 is the most rigorous verification level this plan delivers.
- Structured syslog persistence (`StructuredS3Handler`, `[syslog.structured_s3]`) is completely out of scope. Do not add `[syslog.structured_local]` or any local-disk equivalent for structured records — that is an explicit, separate follow-on task, not part of this plan.
- Every new test function name must be distinct from existing ones in the same file.
- **Rustfmt note:** a prior plan in this series (IPFIX) shipped test snippets that weren't themselves rustfmt-clean, which slipped through both implementation and per-task review and was only caught at the final whole-branch review. Every code block below has been pre-wrapped to match rustfmt's expected line-breaking — copy it verbatim, and still run `cargo fmt --all -- --check` as directed in each task's steps to confirm.

---

### Task 1: Add `SyslogLocalConfig` to `src/config/mod.rs`

**Files:**
- Modify: `src/config/mod.rs` (add `SyslogLocalConfig` struct after `SyslogS3Config`, currently ending at line 648; add `local` field to `SyslogConfig` at lines 179-207 and its `Default` impl at lines 821-833)
- Test: same file's `#[cfg(test)] mod tests` block, inserted directly after `syslog_s3_flat_toml_deserializes_correctly` (ending at line 1093)

**Interfaces:**
- Consumes: `default_syslog_s3_prefix`, `default_syslog_s3_max_rows`, `default_syslog_s3_flush_interval_secs`, `default_syslog_s3_channel_capacity` (all already exist at lines 637-648).
- Produces: `pub struct SyslogLocalConfig { pub directory: PathBuf, pub prefix: String, pub max_buffer_rows: usize, pub flush_interval_secs: u64, pub channel_capacity: usize }`, and `SyslogConfig.local: Option<SyslogLocalConfig>` — both consumed by Task 2 (`syslog_s3.rs`) and Task 3 (`main.rs`).

- [ ] **Step 1: Write the failing tests**

Insert these three tests directly after `syslog_s3_flat_toml_deserializes_correctly` (line 1093) in the existing `#[cfg(test)] mod tests { ... }` block in `src/config/mod.rs`:

```rust
    #[test]
    fn syslog_local_absent_gives_none() {
        let cfg = Config::default();
        assert!(
            cfg.syslog.local.is_none(),
            "absent [syslog.local] must deserialize to None"
        );
    }

    #[test]
    fn syslog_local_config_deserializes_from_toml() {
        let toml_str = r#"
directory = "/var/log/logthing/syslog"
prefix = "syslog"
max_buffer_rows = 5000
flush_interval_secs = 300
channel_capacity = 512
"#;
        let cfg: SyslogLocalConfig = toml::from_str(toml_str).expect("deserialize");
        assert_eq!(
            cfg.directory,
            std::path::PathBuf::from("/var/log/logthing/syslog")
        );
        assert_eq!(cfg.prefix, "syslog");
        assert_eq!(cfg.max_buffer_rows, 5_000);
        assert_eq!(cfg.flush_interval_secs, 300);
        assert_eq!(cfg.channel_capacity, 512);
    }

    #[test]
    fn syslog_local_config_defaults_apply_when_only_directory_given() {
        let toml_str = r#"directory = "/data/syslog""#;
        let cfg: SyslogLocalConfig = toml::from_str(toml_str).expect("deserialize");
        assert_eq!(cfg.prefix, "syslog");
        assert_eq!(cfg.max_buffer_rows, 10_000);
        assert_eq!(cfg.flush_interval_secs, 900);
        assert_eq!(cfg.channel_capacity, 4_096);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --quiet syslog_local`
Expected: FAIL with "cannot find type `SyslogLocalConfig`" / "no field `local` on type `SyslogConfig`"

- [ ] **Step 3: Add `SyslogLocalConfig` struct and wire `SyslogConfig.local`**

Add this struct directly after `SyslogS3Config`'s default functions (after `default_syslog_s3_channel_capacity`, currently ending at line 648):

```rust
/// Per-source local-disk persistence config for the syslog listener.
/// Mirrors `SyslogS3Config`'s flush-policy shape (reusing the same
/// default functions), swapping the S3 connection for a root directory.
/// Independent of `s3`. No `flush_threshold_bytes` field — syslog uses
/// row-count + age triggers only, same as `SyslogS3Config`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SyslogLocalConfig {
    /// Root directory Parquet files are written under (created if missing).
    pub directory: PathBuf,
    /// Key prefix, slash-free (default: `"syslog"` — same default as `syslog.s3`).
    #[serde(default = "default_syslog_s3_prefix")]
    pub prefix: String,
    /// Flush when row count reaches this threshold (default 10 000).
    #[serde(default = "default_syslog_s3_max_rows")]
    pub max_buffer_rows: usize,
    /// Flush after this many seconds regardless of row count (default 900).
    #[serde(default = "default_syslog_s3_flush_interval_secs")]
    pub flush_interval_secs: u64,
    /// Bounded channel capacity (default 4096).
    #[serde(default = "default_syslog_s3_channel_capacity")]
    pub channel_capacity: usize,
}
```

Then modify `SyslogConfig` (lines 179-207) to add the `local` field, directly after the existing `structured_s3` field:

```rust
    /// Optional local-disk persistence for raw syslog messages. Absent from
    /// TOML → `None` → no local persistence (backward compatible).
    /// Independent of `s3` — both may be configured simultaneously, in which
    /// case messages are written to both.
    #[serde(default)]
    pub local: Option<SyslogLocalConfig>,
```

Then modify `impl Default for SyslogConfig` (lines 821-833) to add `local: None,` directly after `structured_s3: None,`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --quiet syslog_local`
Expected: PASS, 3 tests ok

- [ ] **Step 5: Verify fmt and full config test suite**

Run: `cargo fmt --all -- --check`
Expected: no output (clean)

Run: `cargo test --quiet --lib config::`
Expected: all config tests pass, 0 failed

- [ ] **Step 6: Commit**

```bash
git add src/config/mod.rs
git commit -m "feat(config): add SyslogLocalConfig, SyslogConfig.local"
```

---

### Task 2: Refactor `src/forwarding/syslog_s3.rs` — migrate to `start_writer`, add `syslog_local_start` + `MultiSyslogHandler`

**Files:**
- Modify: `src/forwarding/syslog_s3.rs`
- Test: same file's `#[cfg(test)] mod tests` block

**Interfaces:**
- Consumes: `SyslogLocalConfig` (from Task 1), `crate::forwarding::buffered_writer::start_writer::<S>` (existing, `pub(crate)`, signature: `start_writer<S: ParquetSink + Default>(prefix: String, max_buffer_rows: usize, flush_threshold_bytes: usize, flush_interval_secs: u64, channel_capacity: usize, max_partitions: usize, sink: Arc<dyn UploadSink>, source_stats: Arc<SourceHourlyStats>) -> (ParquetWriterHandle<S>, JoinHandle<()>)`), `crate::forwarding::local_sink::LocalDiskSink` (existing).
- Produces: `syslog_local_start(cfg: &SyslogLocalConfig, sink: Arc<LocalDiskSink>, source_stats: Arc<SourceHourlyStats>) -> (SyslogS3Handler, JoinHandle<()>)`, `pub struct MultiSyslogHandler(pub Vec<Arc<dyn crate::syslog::listener::SyslogHandler>>)` implementing `SyslogHandler` — both consumed by Task 3 (`main.rs`).

- [ ] **Step 1: Write the failing tests**

Add these tests to the existing `#[cfg(test)] mod tests { ... }` block in `src/forwarding/syslog_s3.rs`, directly after `syslog_start_wires_handler_and_join_handle`:

```rust
    #[tokio::test]
    async fn syslog_local_start_wires_handler_and_join_handle() {
        use crate::syslog::listener::SyslogHandler as SyslogHandlerTrait;
        use std::net::SocketAddr;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let sink = Arc::new(
            crate::forwarding::local_sink::LocalDiskSink::new(dir.path().to_path_buf())
                .await
                .expect("constructs"),
        );
        let cfg = SyslogLocalConfig {
            directory: dir.path().to_path_buf(),
            prefix: "syslog".to_string(),
            max_buffer_rows: 10_000,
            flush_interval_secs: 3600,
            channel_capacity: 4096,
        };

        let (handler, join_handle) = syslog_local_start(
            &cfg,
            sink,
            std::sync::Arc::new(crate::stats::SourceHourlyStats::new()),
        );

        let src: SocketAddr = "127.0.0.1:5514".parse().unwrap();
        handler.handle_message(dummy_msg("hello"), src).await;

        drop(handler);

        tokio::time::timeout(std::time::Duration::from_secs(5), join_handle)
            .await
            .expect("writer task must exit within 5s")
            .expect("writer task must not panic");
    }

    #[tokio::test]
    async fn multi_syslog_handler_fans_out_to_every_inner_handler() {
        use crate::syslog::listener::SyslogHandler as SyslogHandlerTrait;
        use std::net::SocketAddr;
        use std::sync::Mutex;

        struct CountingHandler {
            count: Mutex<usize>,
        }

        #[async_trait::async_trait]
        impl SyslogHandlerTrait for CountingHandler {
            async fn handle_message(&self, _message: SyslogMessage, _source: SocketAddr) {
                *self.count.lock().unwrap() += 1;
            }
        }

        let h1 = Arc::new(CountingHandler {
            count: Mutex::new(0),
        });
        let h2 = Arc::new(CountingHandler {
            count: Mutex::new(0),
        });
        let multi = MultiSyslogHandler(vec![h1.clone(), h2.clone()]);

        let src: SocketAddr = "127.0.0.1:5514".parse().unwrap();
        multi.handle_message(dummy_msg("test"), src).await;

        assert_eq!(*h1.count.lock().unwrap(), 1);
        assert_eq!(*h2.count.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn multi_syslog_handler_survives_one_inner_handler_dropping() {
        use crate::syslog::listener::SyslogHandler as SyslogHandlerTrait;
        use std::net::SocketAddr;

        let sink = unreachable_sink().await;
        let cfg = SyslogS3Config {
            connection: crate::config::S3ConnectionConfig {
                endpoint: "http://127.0.0.1:1".to_string(),
                bucket: "test-bucket".to_string(),
                region: "us-east-1".to_string(),
                access_key: "AKIATEST".to_string(),
                secret_key: "SECRETTEST".to_string(),
            },
            prefix: "syslog".to_string(),
            max_buffer_rows: 10_000,
            flush_interval_secs: 3600,
            channel_capacity: 4096,
        };
        let (handler, join_handle) = syslog_start(
            &cfg,
            sink,
            std::sync::Arc::new(crate::stats::SourceHourlyStats::new()),
        );
        let live: Arc<dyn SyslogHandlerTrait> = Arc::new(handler);

        let multi = MultiSyslogHandler(vec![live.clone()]);
        let src: SocketAddr = "127.0.0.1:5514".parse().unwrap();
        multi.handle_message(dummy_msg("still works"), src).await;

        drop(live);
        drop(multi);
        tokio::time::timeout(std::time::Duration::from_secs(5), join_handle)
            .await
            .expect("writer task must exit within 5s")
            .expect("writer task must not panic");
    }
```

Add `tempfile` as a dev-dependency check: run `grep tempfile Cargo.toml` first — if it is already a dependency (used by the IPFIX/sFlow local integration tests), no `Cargo.toml` change is needed.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --quiet --lib syslog_s3::tests::syslog_local_start_wires_handler_and_join_handle syslog_s3::tests::multi_syslog_handler`
Expected: FAIL with "cannot find function `syslog_local_start`" / "cannot find struct `MultiSyslogHandler`"

- [ ] **Step 3: Add `#[derive(Default)]` to `SyslogSink`, migrate `syslog_start`, add `syslog_local_start` and `MultiSyslogHandler`**

Change:

```rust
pub struct SyslogSink;
```

to:

```rust
#[derive(Default)]
pub struct SyslogSink;
```

Replace the entire `syslog_start` function body with a call to `start_writer`:

```rust
/// Construct a `SyslogS3Handler` (i.e. `ParquetWriterHandle<SyslogSink>`) from a
/// `SyslogS3Config` and a pre-built `S3Sink`.
///
/// Returns `(handler, writer_task_handle)`. The caller should retain the `JoinHandle`
/// and await it during graceful shutdown, after all `Arc<dyn SyslogHandler>` references
/// have been dropped so the channel closes and the final flush fires.
pub fn syslog_start(
    cfg: &SyslogS3Config,
    s3: std::sync::Arc<crate::forwarding::s3_sink::S3Sink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
) -> (SyslogS3Handler, tokio::task::JoinHandle<()>) {
    crate::forwarding::buffered_writer::start_writer::<SyslogSink>(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        usize::MAX, // syslog uses row-count + age triggers only
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        1,
        s3,
        source_stats,
    )
}

/// Construct a `SyslogS3Handler` from a `SyslogLocalConfig` and a pre-built
/// `LocalDiskSink`. Structurally identical to `syslog_start`, writing to
/// local disk instead of S3 — same `SyslogSink` adapter, same
/// buffering/flush/cap machinery, same S3-key-shaped relative path layout
/// on disk.
pub fn syslog_local_start(
    cfg: &crate::config::SyslogLocalConfig,
    sink: std::sync::Arc<crate::forwarding::local_sink::LocalDiskSink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
) -> (SyslogS3Handler, tokio::task::JoinHandle<()>) {
    crate::forwarding::buffered_writer::start_writer::<SyslogSink>(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        usize::MAX, // syslog uses row-count + age triggers only
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        1,
        sink,
        source_stats,
    )
}

/// Fans out each message to every configured handler. Used only when at
/// least one of `.s3` / `.local` persistence resolves to a live handler for
/// this run — `main.rs` always wraps the resulting `MultiSyslogHandler` (or
/// the sole handler, if that's the only element) as the `inner` of a
/// `PayloadDispatchingHandler`, never in place of it. Each destination keeps
/// its own independent buffer, flush policy, backpressure, and hard cap (no
/// shared state between destinations).
pub struct MultiSyslogHandler(
    pub Vec<std::sync::Arc<dyn crate::syslog::listener::SyslogHandler>>,
);

#[async_trait::async_trait]
impl crate::syslog::listener::SyslogHandler for MultiSyslogHandler {
    async fn handle_message(&self, message: SyslogMessage, source: std::net::SocketAddr) {
        for handler in &self.0 {
            handler.handle_message(message.clone(), source).await;
        }
    }
}
```

Remove the old inline `BufferedWriterConfig`/`FlushPolicy` imports from `syslog_start` if no longer used elsewhere in the file (check: `syslog_sink_reports_into_shared_source_hourly_stats` test still uses them directly — keep the `use` import inside that test's local scope, it already has its own `use` statement).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --quiet --lib syslog_s3::`
Expected: PASS, all syslog_s3 tests ok (existing + 3 new)

- [ ] **Step 5: Verify fmt and clippy**

Run: `cargo fmt --all -- --check`
Expected: no output (clean)

Run: `CC=/usr/bin/gcc CXX=/usr/bin/g++ cargo clippy --all-targets --quiet -- -D warnings`
Expected: no output (clean)

- [ ] **Step 6: Commit**

```bash
git add src/forwarding/syslog_s3.rs
git commit -m "feat(forwarding): add syslog_local_start + MultiSyslogHandler, migrate syslog_start to start_writer"
```

---

### Task 3: Wire `[syslog.local]` in `src/main.rs`, preserving `PayloadDispatchingHandler` wrapping

**Files:**
- Modify: `src/main.rs` (syslog block, currently lines 67-149)

**Interfaces:**
- Consumes: `SyslogLocalConfig` (Task 1), `syslog_local_start`, `MultiSyslogHandler` (Task 2).
- Produces: updated runtime wiring; no new public interfaces for later tasks (this is the last task touching `main.rs` for syslog).

- [ ] **Step 1: Replace the syslog block in `src/main.rs`**

Replace the entire existing block (from `if config.syslog.enabled {` through its closing `}`, currently lines 67-149) with:

```rust
    if config.syslog.enabled {
        let config_clone = config.clone();
        let syslog_shutdown_rx = shutdown_rx.clone();

        // Build optional structured sink BEFORE building the primary handler.
        let structured_handle: Option<Arc<forwarding::structured_syslog_s3::StructuredS3Handler>> =
            if config_clone.syslog.parse_payloads {
                if let Some(ss3_cfg) = config_clone.syslog.structured_s3.as_ref() {
                    match forwarding::s3_sink::S3Sink::from_connection(&ss3_cfg.connection).await {
                        Ok(sink) => {
                            let (sh, wh) =
                                forwarding::structured_syslog_s3::structured_syslog_start(
                                    ss3_cfg,
                                    Arc::new(sink),
                                    source_stats.clone(),
                                );
                            writer_handles.push(wh);
                            Some(Arc::new(sh))
                        }
                        Err(e) => {
                            error!("Failed to create S3Sink for structured syslog: {e}");
                            None
                        }
                    }
                } else {
                    None
                }
            } else {
                None
            };

        // Independently attempt each raw-persistence target; each is
        // logged-and-skipped on its own failure (no fallback to
        // DefaultSyslogHandler just because one target failed while the
        // other succeeded).
        let mut syslog_handlers: Vec<Arc<dyn syslog::listener::SyslogHandler>> = Vec::new();

        if let Some(s3_cfg) = config_clone.syslog.s3.as_ref() {
            match forwarding::s3_sink::S3Sink::from_connection(&s3_cfg.connection).await {
                Ok(sink) => {
                    let (handler, writer_handle) = forwarding::syslog_s3::syslog_start(
                        s3_cfg,
                        Arc::new(sink),
                        source_stats.clone(),
                    );
                    writer_handles.push(writer_handle);
                    syslog_handlers.push(Arc::new(handler));
                }
                Err(e) => {
                    error!(
                        "Failed to create S3Sink for syslog persistence, \
                             skipping S3 target: {e}"
                    );
                }
            }
        }

        if let Some(local_cfg) = config_clone.syslog.local.as_ref() {
            match forwarding::local_sink::LocalDiskSink::new(local_cfg.directory.clone()).await {
                Ok(sink) => {
                    let (handler, writer_handle) = forwarding::syslog_s3::syslog_local_start(
                        local_cfg,
                        Arc::new(sink),
                        source_stats.clone(),
                    );
                    writer_handles.push(writer_handle);
                    syslog_handlers.push(Arc::new(handler));
                }
                Err(e) => {
                    error!(
                        "Failed to create LocalDiskSink for syslog persistence, \
                             skipping local target: {e}"
                    );
                }
            }
        }

        // If at least one persistence target came up, wrap the combined
        // persistence handler in PayloadDispatchingHandler (payload dispatch
        // + DNS-log parsing does NOT run in this branch — persistence and
        // DNS-log parsing remain mutually exclusive, as documented on
        // SyslogListener). Otherwise fall back to DefaultSyslogHandler,
        // which handles DNS-log parsing and payload dispatch itself.
        let syslog_handler: Arc<dyn syslog::listener::SyslogHandler> = if syslog_handlers.is_empty()
        {
            Arc::new(syslog::listener::DefaultSyslogHandler::new(
                config_clone.syslog.parse_dns,
                config_clone.syslog.parse_payloads,
                structured_handle,
            ))
        } else {
            // Do NOT annotate `combined` as `Arc<dyn SyslogHandler>` here — leave
            // it inferred as the concrete `Arc<MultiSyslogHandler>`.
            // `PayloadDispatchingHandler<H: SyslogHandler>` requires `H: Sized`
            // (implicit), so its `inner: Arc<H>` field cannot hold an unsized
            // `Arc<dyn SyslogHandler>` without relaxing that bound to `?Sized` —
            // which this plan's Global Constraints forbid touching. Keeping
            // `combined` concrete avoids that entirely.
            let combined = Arc::new(forwarding::syslog_s3::MultiSyslogHandler(syslog_handlers));
            Arc::new(syslog::listener::PayloadDispatchingHandler {
                inner: combined,
                parse_payloads: config_clone.syslog.parse_payloads,
                structured_handle,
            })
        };

        let syslog_config = syslog::listener::SyslogListenerConfig {
            udp_port: config_clone.syslog.udp_port,
            tcp_port: config_clone.syslog.tcp_port,
            bind_address: "0.0.0.0".to_string(),
            parse_dns_logs: config_clone.syslog.parse_dns,
        };
        let handle = tokio::spawn(async move {
            let listener = syslog::listener::SyslogListener::new(syslog_config, syslog_handler);
            if let Err(e) = listener.start_with_shutdown(syslog_shutdown_rx).await {
                error!("Syslog listener error: {}", e);
            }
        });
        listener_handles.push(handle);
    }
```

- [ ] **Step 2: Build and run the full test suite**

Run: `CC=/usr/bin/gcc CXX=/usr/bin/g++ cargo build --quiet`
Expected: builds cleanly, no errors

Run: `CC=/usr/bin/gcc CXX=/usr/bin/g++ cargo test --quiet`
Expected: all tests pass, 0 failed

- [ ] **Step 3: Verify fmt and clippy**

Run: `cargo fmt --all -- --check`
Expected: no output (clean)

Run: `CC=/usr/bin/gcc CXX=/usr/bin/g++ cargo clippy --all-targets --quiet -- -D warnings`
Expected: no output (clean)

- [ ] **Step 4: Commit**

```bash
git add src/main.rs
git commit -m "feat(main): wire syslog.local alongside syslog.s3, fan out via MultiSyslogHandler under PayloadDispatchingHandler"
```

---

### Task 4: End-to-end integration test — real Parquet round-trip through `LocalDiskSink`

**Files:**
- Create: `tests/syslog_local_integration.rs`

**Interfaces:**
- Consumes: `SyslogLocalConfig` (Task 1), `syslog_local_start` (Task 2), `LocalDiskSink::new`, `SyslogMessage`, `SyslogProtocol`.
- Produces: nothing consumed by later tasks — this is the last task in the plan.

- [ ] **Step 1: Write the integration test**

```rust
//! End-to-end integration test: syslog messages pushed through
//! `syslog_local_start` land as real, readable Parquet files on local disk.

use bytes::Bytes;
use logthing::config::SyslogLocalConfig;
use logthing::forwarding::local_sink::LocalDiskSink;
use logthing::forwarding::syslog_s3::syslog_local_start;
use logthing::syslog::listener::SyslogHandler;
use logthing::syslog::{SyslogMessage, SyslogProtocol};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use std::net::SocketAddr;
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
async fn syslog_messages_appear_as_parquet_on_local_disk() {
    let tmp = tempfile::tempdir().unwrap();
    let sink = std::sync::Arc::new(
        LocalDiskSink::new(tmp.path().to_path_buf())
            .await
            .expect("LocalDiskSink constructs"),
    );

    let cfg = SyslogLocalConfig {
        directory: tmp.path().to_path_buf(),
        prefix: "syslog".to_string(),
        max_buffer_rows: 10_000,
        flush_interval_secs: 3600,
        channel_capacity: 4096,
    };

    let (handler, join_handle) = syslog_local_start(
        &cfg,
        sink,
        std::sync::Arc::new(logthing::stats::SourceHourlyStats::new()),
    );

    let src: SocketAddr = "127.0.0.1:5514".parse().unwrap();
    let msg1 = SyslogMessage {
        priority: 34,
        severity: 2,
        facility: 4,
        timestamp: Some(chrono::Utc::now()),
        hostname: Some("host-a".to_string()),
        app_name: Some("sshd".to_string()),
        proc_id: None,
        msg_id: None,
        message: "authentication failure".to_string(),
        structured_data: None,
        protocol: SyslogProtocol::Rfc3164,
    };
    let msg2 = SyslogMessage {
        priority: 134,
        severity: 6,
        facility: 16,
        timestamp: Some(chrono::Utc::now()),
        hostname: Some("host-b".to_string()),
        app_name: Some("cron".to_string()),
        proc_id: Some("4321".to_string()),
        msg_id: None,
        message: "job completed".to_string(),
        structured_data: None,
        protocol: SyslogProtocol::Rfc5424,
    };

    handler.handle_message(msg1, src).await;
    handler.handle_message(msg2, src).await;

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
            .any(|p| p.file_name().unwrap().to_string_lossy().starts_with(".tmp-")),
        "no leftover .tmp- files should remain after flush: {all_files:?}"
    );

    let parquet_files: Vec<_> = all_files
        .iter()
        .filter(|p| p.extension().is_some_and(|e| e == "parquet"))
        .collect();
    assert_eq!(
        parquet_files.len(),
        1,
        "expected exactly 1 Parquet file (syslog has a single partition); found {parquet_files:?}"
    );

    let raw = std::fs::read(parquet_files[0]).unwrap();
    let buf = Bytes::from(raw);
    let builder = ParquetRecordBatchReaderBuilder::try_new(buf).unwrap();
    let schema = builder.schema().clone();
    assert_eq!(schema.fields().len(), 11);

    let mut reader = builder.build().unwrap();
    let rb = reader
        .next()
        .expect("at least one record batch")
        .expect("record batch reads without error");
    assert_eq!(rb.num_rows(), 2);

    use arrow::array::{Array, StringArray};
    let hostnames = rb
        .column(4)
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    assert_eq!(hostnames.value(0), "host-a");
    assert_eq!(hostnames.value(1), "host-b");
    assert!(!hostnames.is_null(0));
}
```

- [ ] **Step 2: Run the test to verify it passes**

Run: `CC=/usr/bin/gcc CXX=/usr/bin/g++ cargo test --quiet --test syslog_local_integration -- --nocapture`
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
git add tests/syslog_local_integration.rs
git commit -m "test(syslog): integration test proving real Parquet round-trip through LocalDiskSink"
```

---

## Post-Plan Checklist (for the final whole-branch review)

1. `config.syslog.local` absent from TOML still deserializes to `None`, and all pre-existing syslog config tests still pass unmodified.
2. `main.rs`'s syslog block independently attempts `.s3` and `.local`, logging-and-skipping each on its own failure — neither failure causes a fallback to `DefaultSyslogHandler` when the other target is configured and healthy.
3. `DefaultSyslogHandler` is used ONLY when zero persistence targets are configured/healthy — never wrapped by `PayloadDispatchingHandler`.
4. `PayloadDispatchingHandler`'s `inner` is always a concrete `Arc<MultiSyslogHandler>` when at least one persistence target is live — `syslog::listener::PayloadDispatchingHandler`'s struct definition and generic bound are untouched.
5. No `build_syslog_handle` wrapper introduced anywhere.
6. `cargo fmt --all -- --check` and `cargo clippy --all-targets --quiet -- -D warnings` both clean across the whole branch diff.
