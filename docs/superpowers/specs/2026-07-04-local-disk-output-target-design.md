# Local-Disk Output Target — Design Spec

**Date:** 2026-07-04
**Status:** Approved (auto-develop cycle; independent coherence review passed)
**Origin:** User request — "create a new output path in addition to the s3 shipper, a
'local' target that saves logs to disk", produced via `auto-develop` (autonomous
brainstorming + independent reviewer, no human question-by-question loop).

---

## 1. Problem

Every ingestion source in logthing (Zeek, Suricata, IPFIX, syslog, structured syslog,
sFlow, generic/HEC, WEF) persists buffered records as partitioned Parquet through one
shared generic writer, `PartitionedParquetWriter<S: ParquetSink>`
(`src/forwarding/buffered_writer.rs`), which is hardcoded to upload to
`Arc<crate::forwarding::s3_sink::S3Sink>`. There is no way to persist to local disk —
useful for dev/test without a MinIO/S3 dependency, air-gapped deployments, or simply
wanting a second, cheap copy of the data.

This spec adds a `local` disk target alongside the existing `s3` target, generalizing
the shared writer so any source can enable either, both, or neither.

## 2. Scope

**In scope this increment:**
- Generalize `PartitionedParquetWriter`/`ParquetWriterHandle` to write through a new
  `UploadSink` trait instead of the concrete `S3Sink` type (touches all 8 existing
  `*_start` function signatures mechanically — no behavior change for the S3 path).
- A new `LocalDiskSink` implementing `UploadSink`.
- Full wiring (config, `main.rs`, handler multiplexing, tests, docs) for **Zeek only**.

**Explicitly out of scope this increment:**
- Wiring `.local` config + `main.rs` glue for the other 7 sources (suricata, ipfix,
  syslog, structured_syslog, sflow, generic/HEC, wef). Each is a mechanical follow-on
  once this lands: a new `XxxLocalConfig` struct, a `local` field on the top-level
  config, a `xxx_local_start` sibling function, and a `main.rs` wiring block — the
  same shape as this spec's Zeek changes.
- Renaming `ZeekS3Handler` (considered, rejected by reviewer as unnecessary churn —
  the alias stays as-is even though it now can back a disk-only or dual pipeline too).

## 3. Decision log

| # | Question | Chosen | Why | Confidence |
|---|---|---|---|---|
| 1 | What layer gets the new target? | Generic `UploadSink` trait behind the existing `PartitionedParquetWriter`, not a bespoke/duplicated writer | The buffering/flush/cap machinery was already generalized specifically so sources share one implementation; forking it for one destination fights that abstraction | High |
| 2 | How does a source pick S3 vs local vs both? | Sibling independently-optional `[<source>.local]` TOML table next to the existing `[<source>.s3]`; both may be present simultaneously | Matches the existing config idiom exactly (zero migration); "in addition to the S3 shipper" reads as additive | Medium — reviewer agreed with this reading but flagged it as the most debatable fork |
| 3 | How do dual writes fan out when both are configured? | Two fully independent `ParquetWriterHandle<S>` pipelines (one per destination), each with its own buffer/flush-policy/backpressure/hard-cap; a `MultiZeekHandler` clones the record once and dispatches to each active handler via the existing non-blocking `try_send` pattern | A shared buffer uploading the same bytes to N sinks risks duplicate Parquet files if one sink succeeds and the other fails on retry; independent pipelines keep each destination's retry semantics self-contained. Reviewer verified fan-out is safe because `handle_record` already uses non-blocking `try_send`, so a stalled S3 channel can't block local delivery | High |
| 4 | Where does local's flush-policy come from? | `.local` gets its own full set of flush-policy fields (prefix/max_buffer_rows/flush_threshold_bytes/flush_interval_secs/channel_capacity), independent of `.s3` | Local disk and S3 have different cost/latency tradeoffs; `.local` must work standalone (dev/air-gapped use case has no S3 config at all) | High |
| 5 | New config struct shape? | New `ZeekLocalConfig`, mirroring `ZeekS3Config`'s shape (swap `connection: S3ConnectionConfig` for `directory: PathBuf`) | Matches the codebase's existing per-source-struct convention rather than introducing an asymmetric shared type | High |
| 6 | Scope of this increment? | Generic plumbing for everyone (mechanical) + full wiring for Zeek only | Matches the concrete ask; remaining sources are mechanical repetition that shouldn't gate this cycle | High |
| 7 | On-disk layout & atomicity | Reuse `build_key()` unchanged as the relative path under a configured root directory; write via same-directory temp file + atomic rename | Same Hive-style layout works for any downstream reader (DuckDB/Trino) regardless of source; temp+rename prevents partial-file reads | High |
| 8 | Filesystem write hardening | Reject/sanitize any key segment that could escape the root; verify the resolved path stays under the canonicalized root before writing | A local filesystem write is higher blast radius than an opaque S3 key string, even with upstream `sanitize_log_path` already reducing risk | High |
| 9 | Metrics | Keep existing `parquet_s3_*` counter names; add a new `target` label (`"s3"`\|`"local"`) alongside `source` | Lets operators distinguish destinations without breaking dashboards. **Side effect** (flagged by reviewer): since this label is added at the generic-writer level, all 8 sources' metrics gain this new label dimension in this increment even though only Zeek gets `.local` wired — harmless (existing queries keyed on `source` alone are unaffected; Prometheus label addition is additive), but worth a changelog line | High |
| 10 | Naming cleanup | Dropped — `ZeekS3Handler` alias stays as-is | Reviewer flagged the rename as scope creep disconnected from the actual request | N/A (reverted) |

## 4. Architecture

```
                         UploadSink (trait)
                  async fn upload(key, body) -> Result<()>
                  fn target_label() -> &'static str
                    /                          \
              S3Sink (existing,              LocalDiskSink (new)
              unchanged behavior)             root: PathBuf
                                               temp-file + atomic rename
                                               path-traversal guard
                    \                          /
             PartitionedParquetWriter<S: ParquetSink>
               sink: Arc<dyn UploadSink>   (was: Arc<S3Sink>)
               — all buffering/flush/cap/encode logic unchanged —
                              |
                    ParquetWriterHandle<S>
                              |
        ZeekConfig.s3: Option<ZeekS3Config>  ─┐
        ZeekConfig.local: Option<ZeekLocalConfig> ─┤ independently optional
                                                    |
                     main.rs zeek wiring:
          s3 only        → S3 handler alone
          local only     → local handler alone
          both            → MultiZeekHandler([s3 handler, local handler])
          neither         → DefaultZeekHandler (unchanged today)
```

### 4.1 `UploadSink` trait (`src/forwarding/buffered_writer.rs` or new `sink_target.rs`)

```rust
#[async_trait::async_trait]
pub trait UploadSink: Send + Sync {
    async fn upload(&self, key: &str, body: Vec<u8>) -> anyhow::Result<()>;
    fn target_label(&self) -> &'static str;
}
```

- `impl UploadSink for S3Sink`: delegates to the existing inherent `upload` method
  (kept as an inherent method too, so existing tests calling `sink.upload(...)`
  directly on a concrete `S3Sink` keep compiling unchanged — inherent methods take
  priority over trait methods of the same name). `target_label()` returns `"s3"`.

### 4.2 `LocalDiskSink` (new `src/forwarding/local_sink.rs`)

```rust
pub struct LocalDiskSink { root: PathBuf }

impl LocalDiskSink {
    /// Canonicalizes and creates `root` if missing. Fails fast at construction
    /// (mirrors `S3Sink::from_connection`'s fallibility) if the path cannot be
    /// created or is not a directory.
    pub async fn new(root: PathBuf) -> anyhow::Result<Self>;
}

#[async_trait::async_trait]
impl UploadSink for LocalDiskSink {
    async fn upload(&self, key: &str, body: Vec<u8>) -> anyhow::Result<()> {
        // 1. Reject `key` containing ".." components or leading '/' outright.
        // 2. dest = root.join(key); create parent dirs (create_dir_all).
        // 3. Verify dest, once joined, is still lexically under `root`
        //    (defense-in-depth on top of #1 and upstream sanitize_log_path).
        // 4. Write to `dest` with a sibling temp name in the SAME directory
        //    (e.g. `.<uuid>.tmp`), then `tokio::fs::rename` into `dest` —
        //    atomic on the same filesystem, so a concurrent reader never
        //    observes a partial file.
    }
    fn target_label(&self) -> &'static str { "local" }
}
```

### 4.3 Generic writer changes

- `PartitionedParquetWriter<S>` and `ParquetWriterHandle<S>`: field/param type
  `Arc<crate::forwarding::s3_sink::S3Sink>` → `Arc<dyn UploadSink>`. This is the one
  change that mechanically ripples into every existing `*_start` function's
  signature across the forwarding module (zeek, suricata, ipfix, syslog,
  structured_syslog, sflow, generic/hec, wef) — call sites passing `Arc<S3Sink>`
  keep compiling via unsized coercion, no behavior change for any source that only
  configures `.s3`.
- `flush_partition`: replace `self.s3.upload(...)` with `self.target.upload(...)`;
  add the `target` label to `parquet_s3_uploads`, `parquet_s3_upload_errors`,
  `parquet_s3_records_written` (and the other `parquet_s3_*` counters already
  emitted here) using `self.target.target_label()`.

### 4.4 Config (Zeek only, this increment)

```toml
[zeek]
enabled = true
tcp_port = 47760

[zeek.s3]           # unchanged, still optional
endpoint = "..."
bucket   = "zeek-logs"
prefix   = "zeek"

[zeek.local]        # new, independently optional
directory             = "/var/log/logthing/zeek"
prefix                = "zeek"      # default: "zeek" (same default as zeek.s3)
flush_threshold_bytes  = 104857600   # default: 100 MiB, same default as zeek.s3
flush_interval_secs    = 900         # default: 900s, same default as zeek.s3
channel_capacity       = 256         # default: 256, same default as zeek.s3
max_buffer_rows        = 100000      # default: 100_000, same default as zeek.s3
```

`ZeekLocalConfig` (new, `src/config/mod.rs`) mirrors `ZeekS3Config`'s shape exactly,
swapping `connection: S3ConnectionConfig` for `directory: PathBuf`, and reusing the
same default functions/values (`default_zeek_s3_prefix`, `default_zeek_flush_bytes`,
etc.) so `.local`'s defaults track `.s3`'s.

`ZeekConfig` gains `pub local: Option<ZeekLocalConfig>` (default `None`, absent from
TOML → no local persistence — same convention as `.s3`).

### 4.5 `zeek_local_start` (new, `src/forwarding/zeek_s3.rs` or co-located)

```rust
pub fn zeek_local_start(
    cfg: &ZeekLocalConfig,
    sink: Arc<LocalDiskSink>,
    source_stats: Arc<crate::stats::SourceHourlyStats>,
) -> (ZeekS3Handler, tokio::task::JoinHandle<()>)
```

Structurally identical to the existing `zeek_start`, reusing the same `ZeekSink`
adapter and `DEFAULT_MAX_ZEEK_PARTITIONS` constant; only the config type and the
concrete sink differ. (`ZeekS3Handler` — the `ParquetWriterHandle<ZeekSink>` alias —
keeps its current name per the reviewer's naming-churn pushback.)

### 4.6 `ZeekRecord` + `MultiZeekHandler`

- `ZeekRecord` (`src/zeek/mod.rs`) gains `#[derive(Clone)]` (all fields — `String`,
  `serde_json::Value`, `DateTime<Utc>` — are already `Clone`).
- New `MultiZeekHandler(Vec<Arc<dyn zeek::listener::ZeekHandler>>)` implementing
  `ZeekHandler::handle_record` by cloning the record and calling `handle_record` on
  each inner handler in turn. Only constructed when both `.s3` and `.local` resolve
  to a live handler for the same run.

### 4.7 `main.rs` wiring

Extends the existing `if config.zeek.enabled { ... }` block
(`src/main.rs:191-227`): after building the existing S3 handler (unchanged), also
attempt a local handler if `zeek.local` is `Some` (construct `LocalDiskSink::new`,
call `zeek_local_start`); if both handlers are live, wrap them in
`MultiZeekHandler(vec![s3_handler, local_handler])`; if exactly one is live, use it
directly; if neither, `DefaultZeekHandler` as today. Local-sink construction
failures log an error and are dropped from the active set (same fallback pattern
already used for S3 construction failures), rather than aborting startup.

## 5. Testing plan

- **Unit** (`src/forwarding/local_sink.rs`, `src/forwarding/buffered_writer.rs`,
  `src/zeek/*`): `LocalDiskSink` writes land at the expected path; temp-file+rename
  atomicity (no `.tmp` file visible after success); path-traversal rejection
  (`..`, absolute paths, symlink-escape attempts); `ZeekLocalConfig`
  TOML deserialization + defaults; `MultiZeekHandler` fan-out dispatches to both
  inner handlers and survives one handler's channel being full/closed.
- **Integration**: `PartitionedParquetWriter<ZeekSink>` wired to a real
  `LocalDiskSink` pointed at a tempdir — push real `ZeekRecord`s, force a flush,
  read the resulting Parquet file back with a real Parquet reader and assert row
  contents match (mirrors the existing `encode_round_trip_via_concat_and_parquet`
  test, but through the actual `UploadSink` path instead of hand-rolled encoding).
- **E2E**: extend the existing Zeek e2e test (`tests/zeek_s3_integration.rs` /
  the e2e simulation environment) to configure both `[zeek.s3]` (MinIO) and
  `[zeek.local]` (tempdir) simultaneously, send records through the TCP listener,
  and assert both destinations end up with the data.

## 6. Documentation

Update `ZEEK_IMPLEMENTATION.md`'s `[zeek]`/`[zeek.s3]` config section with a new
`[zeek.local]` subsection (table of keys/defaults, example TOML), and add one line
to the module's file-listing table for `src/forwarding/local_sink.rs`.
