# Local-Disk Output Target Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a local-disk persistence target alongside the existing S3 shipper, generalizing the shared `PartitionedParquetWriter` so it writes through any `UploadSink`, then wiring it fully for the Zeek source (config, `main.rs`, handler fan-out, tests, docs).

**Architecture:** Introduce an `UploadSink` trait (`upload(key, body)` + `target_label()`) implemented by the existing `S3Sink` (unchanged behavior) and a new `LocalDiskSink` (atomic temp-file+rename writes under a root directory, with a path-traversal guard). Generalize `PartitionedParquetWriter`/`ParquetWriterHandle`'s sink field from `Arc<S3Sink>` to `Arc<dyn UploadSink>` — this is a type-only change inside `buffered_writer.rs`; Rust's `Arc` unsizing coercion means every other source's `*_start` function keeps compiling unchanged. Wire a new `ZeekLocalConfig` + `zeek_local_start` + `MultiZeekHandler` (fan-out to both destinations when both are configured) for Zeek specifically.

**Tech Stack:** Rust, Tokio, `async-trait`, Arrow/Parquet (`parquet`, `arrow`, `arrow-array`, `arrow-schema` — all already dependencies), `uuid` (already a dependency), `tempfile` (already a dev-dependency).

## Global Constraints

- Base branch: `feature/local-disk-output-target`, already created off `master` at commit `05017e6` (worktree: `.claude/worktrees/local-disk-output-target`). All work in this plan happens on this branch — do not rebase onto or merge from `feature/admin-source-hourly-stats` (unrelated, unmerged, in-progress work).
- Build env (required for every `cargo build`/`cargo test` invocation in this plan — logthing's C-backed deps fail under the `zig-cc` shim otherwise):
  ```bash
  export CC=/usr/bin/gcc CXX=/usr/bin/g++
  export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
  source ~/.cargo/env
  ```
- If this plan is executed via subagents in their own git worktrees, set a single shared `CARGO_TARGET_DIR` across all of them (e.g. `export CARGO_TARGET_DIR=/home/dev/projects/logthing/.claude/worktrees/.shared-target`) so only the changed crate recompiles per task instead of a full ~6 min rebuild each time.
- No new crate dependencies. No changes to `Cargo.toml`.
- Every `S3Sink`-only behavior (existing tests, existing metric names, existing S3 key layout) must be provably unchanged — each task that touches shared code says exactly which existing test run proves this.
- Out of scope (do not implement, only mention in docs as a follow-on): wiring `.local` config for suricata, ipfix, syslog, structured_syslog, sflow, generic/HEC, wef.

---

### Task 1: `UploadSink` trait + `S3Sink` implementation

**Files:**
- Modify: `src/forwarding/buffered_writer.rs` (add trait near top, after the module doc comment / before `ParquetSink`)
- Modify: `src/forwarding/s3_sink.rs` (add `impl UploadSink for S3Sink`)
- Test: inline `#[cfg(test)]` in both files

**Interfaces:**
- Produces: `pub trait UploadSink: Send + Sync { async fn upload(&self, key: &str, body: Vec<u8>) -> anyhow::Result<()>; fn target_label(&self) -> &'static str; }` in `crate::forwarding::buffered_writer`. `S3Sink::target_label() -> "s3"`.

- [ ] **Step 1: Add the trait definition**

In `src/forwarding/buffered_writer.rs`, immediately after the file's opening doc comment block (before the `// --- ParquetSink trait ---` section, i.e. before line 15 `// ---...` / the existing `ParquetSink` trait), add:

```rust
use async_trait::async_trait;

// ---------------------------------------------------------------------------
// UploadSink trait
// ---------------------------------------------------------------------------

/// A destination for encoded Parquet bytes. Implemented by `S3Sink` (existing)
/// and `LocalDiskSink` (local-disk target). `PartitionedParquetWriter` is
/// generic over this trait so any source can persist to either destination
/// (or, via two independent writer instances, both at once) without touching
/// the buffering/flush/cap machinery.
#[async_trait]
pub trait UploadSink: Send + Sync {
    /// Upload `body` at `key` (a relative path, e.g.
    /// `zeek/conn/year=2026/month=07/day=04/<uuid>.parquet`).
    async fn upload(&self, key: &str, body: Vec<u8>) -> anyhow::Result<()>;

    /// Stable label for the `target` metric dimension, e.g. `"s3"` | `"local"`.
    fn target_label(&self) -> &'static str;
}
```

- [ ] **Step 2: Implement `UploadSink` for `S3Sink`**

In `src/forwarding/s3_sink.rs`, after the existing `impl S3Sink { ... }` block (after its closing `}`, currently ending at line 109, before the `flush_check_interval` function), add:

```rust
#[async_trait::async_trait]
impl crate::forwarding::buffered_writer::UploadSink for S3Sink {
    async fn upload(&self, key: &str, body: Vec<u8>) -> anyhow::Result<()> {
        // Delegates to the inherent method above — kept as an inherent method too
        // so existing tests calling `sink.upload(...)` on a concrete `S3Sink`
        // keep compiling (inherent methods take priority over trait methods of
        // the same name at the call site).
        S3Sink::upload(self, key, body).await
    }

    fn target_label(&self) -> &'static str {
        "s3"
    }
}
```

- [ ] **Step 3: Write a compile-time + behavioral test proving `S3Sink` satisfies `UploadSink`**

Add to the `#[cfg(test)] mod tests` block in `src/forwarding/s3_sink.rs` (after the existing `upload_returns_err_on_unreachable_endpoint` test):

```rust
#[tokio::test]
async fn s3_sink_satisfies_upload_sink_trait() {
    use crate::forwarding::buffered_writer::UploadSink;

    let conn = S3ConnectionConfig {
        endpoint: "http://127.0.0.1:1".to_string(),
        bucket: "test-bucket".to_string(),
        region: "us-east-1".to_string(),
        access_key: "AKIATEST".to_string(),
        secret_key: "SECRETTEST".to_string(),
    };
    let sink: std::sync::Arc<dyn UploadSink> =
        std::sync::Arc::new(S3Sink::from_connection(&conn).await.expect("constructs"));

    assert_eq!(sink.target_label(), "s3");
    // Unreachable endpoint — proves the trait method dispatches to the same
    // upload logic as the inherent method (same failure mode as the existing
    // `upload_returns_err_on_unreachable_endpoint` test).
    let result = sink.upload("some/key.parquet", b"hello".to_vec()).await;
    assert!(result.is_err(), "upload via trait object must fail the same way as the inherent method");
}
```

- [ ] **Step 4: Run the tests**

```bash
cargo test -p logthing --lib forwarding::s3_sink -- --nocapture
```
Expected: all tests in `forwarding::s3_sink` pass, including the two new/existing ones (`s3_sink_satisfies_upload_sink_trait`, `upload_returns_err_on_unreachable_endpoint`).

- [ ] **Step 5: Commit**

```bash
git add src/forwarding/buffered_writer.rs src/forwarding/s3_sink.rs
git commit -m "feat(forwarding): add UploadSink trait, implement for S3Sink"
```

---

### Task 2: `LocalDiskSink`

**Files:**
- Create: `src/forwarding/local_sink.rs`
- Modify: `src/forwarding/mod.rs` (register `pub mod local_sink;`)
- Test: inline `#[cfg(test)]` in `src/forwarding/local_sink.rs`

**Interfaces:**
- Consumes: `UploadSink` trait from Task 1 (`crate::forwarding::buffered_writer::UploadSink`).
- Produces: `pub struct LocalDiskSink { .. }` with `pub async fn new(root: PathBuf) -> anyhow::Result<Self>`, implementing `UploadSink` (`target_label() -> "local"`).

- [ ] **Step 1: Write the failing tests**

Create `src/forwarding/local_sink.rs`:

```rust
//! Local-disk Parquet persistence target.
//!
//! `LocalDiskSink` implements `UploadSink` by writing to a configured root
//! directory using the same relative key layout as S3
//! (`{prefix}/{partition}/year=/month=/day=/{uuid}.parquet`, produced by
//! `buffered_writer::build_key`). Writes are atomic: bytes land in a
//! same-directory temp file first, then are renamed into place, so a
//! concurrent reader scanning the directory never observes a partial file.

use crate::forwarding::buffered_writer::UploadSink;
use std::path::PathBuf;

/// Writes Parquet objects under a root directory on local disk.
pub struct LocalDiskSink {
    root: PathBuf,
}

impl LocalDiskSink {
    /// Creates `root` (and any missing parent directories) and canonicalizes
    /// it. Fails fast on construction — mirrors `S3Sink::from_connection`'s
    /// fallibility, so callers apply the same "log and fall back" pattern
    /// already used for S3 construction failures.
    pub async fn new(root: PathBuf) -> anyhow::Result<Self> {
        tokio::fs::create_dir_all(&root).await?;
        let root = tokio::fs::canonicalize(&root).await?;
        Ok(Self { root })
    }
}

#[async_trait::async_trait]
impl UploadSink for LocalDiskSink {
    async fn upload(&self, key: &str, body: Vec<u8>) -> anyhow::Result<()> {
        if key.is_empty() || key.contains("..") || key.starts_with('/') {
            anyhow::bail!("LocalDiskSink: rejected unsafe key: {key:?}");
        }
        let dest = self.root.join(key);
        let parent = dest
            .parent()
            .ok_or_else(|| anyhow::anyhow!("LocalDiskSink: key has no parent: {key:?}"))?;
        tokio::fs::create_dir_all(parent).await?;

        // Defense-in-depth: even after the ".."/leading-'/' check above, verify
        // the resolved directory is still under the canonical root (catches a
        // symlink planted inside root that could otherwise redirect the write
        // outside the intended tree).
        let canonical_parent = tokio::fs::canonicalize(parent).await?;
        if !canonical_parent.starts_with(&self.root) {
            anyhow::bail!("LocalDiskSink: resolved path escapes root: {key:?}");
        }

        let file_name = dest
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("LocalDiskSink: key has no file name: {key:?}"))?
            .to_string_lossy()
            .into_owned();
        let tmp_path = parent.join(format!(".{}.tmp-{file_name}", uuid::Uuid::new_v4()));

        tokio::fs::write(&tmp_path, &body).await?;
        tokio::fs::rename(&tmp_path, &dest).await?;
        Ok(())
    }

    fn target_label(&self) -> &'static str {
        "local"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn writes_file_at_expected_relative_path() {
        let dir = tempfile::tempdir().unwrap();
        let sink = LocalDiskSink::new(dir.path().to_path_buf()).await.unwrap();

        sink.upload("zeek/conn/year=2026/month=07/day=04/abc.parquet", b"hello".to_vec())
            .await
            .unwrap();

        let written = dir
            .path()
            .join("zeek/conn/year=2026/month=07/day=04/abc.parquet");
        assert!(written.exists(), "expected file at {written:?}");
        assert_eq!(tokio::fs::read(&written).await.unwrap(), b"hello");
    }

    #[tokio::test]
    async fn creates_missing_nested_directories() {
        let dir = tempfile::tempdir().unwrap();
        let sink = LocalDiskSink::new(dir.path().to_path_buf()).await.unwrap();

        sink.upload("a/b/c/d.parquet", b"x".to_vec()).await.unwrap();

        assert!(dir.path().join("a/b/c/d.parquet").exists());
    }

    #[tokio::test]
    async fn no_temp_file_left_behind_after_successful_write() {
        let dir = tempfile::tempdir().unwrap();
        let sink = LocalDiskSink::new(dir.path().to_path_buf()).await.unwrap();

        sink.upload("f.parquet", b"data".to_vec()).await.unwrap();

        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries, vec!["f.parquet".to_string()], "no stray .tmp file: {entries:?}");
    }

    #[tokio::test]
    async fn rejects_path_traversal_key() {
        let dir = tempfile::tempdir().unwrap();
        let sink = LocalDiskSink::new(dir.path().to_path_buf()).await.unwrap();

        let result = sink.upload("../../etc/passwd.parquet", b"x".to_vec()).await;
        assert!(result.is_err(), "must reject a key containing '..'");
    }

    #[tokio::test]
    async fn rejects_absolute_path_key() {
        let dir = tempfile::tempdir().unwrap();
        let sink = LocalDiskSink::new(dir.path().to_path_buf()).await.unwrap();

        let result = sink.upload("/etc/passwd", b"x".to_vec()).await;
        assert!(result.is_err(), "must reject a key with a leading '/'");
    }

    #[tokio::test]
    async fn target_label_is_local() {
        let dir = tempfile::tempdir().unwrap();
        let sink = LocalDiskSink::new(dir.path().to_path_buf()).await.unwrap();
        assert_eq!(sink.target_label(), "local");
    }

    #[tokio::test]
    async fn new_creates_missing_root_directory() {
        let dir = tempfile::tempdir().unwrap();
        let missing_root = dir.path().join("does/not/exist/yet");
        let sink = LocalDiskSink::new(missing_root.clone()).await.unwrap();
        assert!(missing_root.exists());
        sink.upload("f.parquet", b"x".to_vec()).await.unwrap();
        assert!(missing_root.join("f.parquet").exists());
    }
}
```

- [ ] **Step 2: Register the module**

In `src/forwarding/mod.rs`, add `pub mod local_sink;` alphabetically among the existing `pub mod` lines (after `pub mod ipfix_s3;`, before `pub mod parquet_s3;`):

```rust
pub mod buffered_writer;
pub mod generic_s3;
pub mod ipfix_s3;
pub mod local_sink;
pub mod parquet_s3;
pub mod s3_sink;
pub mod sflow_s3;
pub mod structured_syslog_s3;
pub mod syslog_s3;
pub mod suricata_s3;
pub mod zeek_s3;
```

- [ ] **Step 3: Run the tests, confirm they fail first (module not wired), then pass**

```bash
cargo test -p logthing --lib forwarding::local_sink -- --nocapture
```
Expected: 7 tests pass (`writes_file_at_expected_relative_path`, `creates_missing_nested_directories`, `no_temp_file_left_behind_after_successful_write`, `rejects_path_traversal_key`, `rejects_absolute_path_key`, `target_label_is_local`, `new_creates_missing_root_directory`).

- [ ] **Step 4: Commit**

```bash
git add src/forwarding/local_sink.rs src/forwarding/mod.rs
git commit -m "feat(forwarding): add LocalDiskSink (atomic writes, path-traversal guard)"
```

---

### Task 3: Generalize `PartitionedParquetWriter`/`ParquetWriterHandle` to `Arc<dyn UploadSink>`

**Files:**
- Modify: `src/forwarding/buffered_writer.rs` only (field types, metric labels; every other source's `*_start` function is untouched — `Arc<S3Sink>` unsizes to `Arc<dyn UploadSink>` automatically at the call site)

**Interfaces:**
- Consumes: `UploadSink` trait (Task 1).
- Produces: `PartitionedParquetWriter::new(sink: S, s3: Arc<dyn UploadSink>, config, policy)`, `ParquetWriterHandle::start(sink: S, s3: Arc<dyn UploadSink>, config, policy)` (parameter name `s3` and field name `s3` are kept unchanged — only the *type* changes, to minimize diff noise). `ParquetWriterHandle<S>` gains a `target: &'static str` field captured at `start()` time via `sink_target.target_label()` — wait, captured from the `s3: Arc<dyn UploadSink>` argument, i.e. `s3.target_label()`.

- [ ] **Step 1: Change `PartitionedParquetWriter`'s field type and constructor**

In `src/forwarding/buffered_writer.rs`, change (currently lines 176–199):

```rust
pub struct PartitionedParquetWriter<S: ParquetSink> {
    sink: S,
    s3: Arc<crate::forwarding::s3_sink::S3Sink>,
    config: BufferedWriterConfig,
    policy: FlushPolicy,
    /// `""` key for None-partition sources; sanitized-path / `"event_type=<id>"` for multi-partition.
    pub(crate) buffers: HashMap<String, PartitionBuffer>,
}

impl<S: ParquetSink> PartitionedParquetWriter<S> {
    pub fn new(
        sink: S,
        s3: Arc<crate::forwarding::s3_sink::S3Sink>,
        config: BufferedWriterConfig,
        policy: FlushPolicy,
    ) -> Self {
        Self {
            sink,
            s3,
            config,
            policy,
            buffers: HashMap::new(),
        }
    }
```

to:

```rust
pub struct PartitionedParquetWriter<S: ParquetSink> {
    sink: S,
    s3: Arc<dyn UploadSink>,
    config: BufferedWriterConfig,
    policy: FlushPolicy,
    /// `""` key for None-partition sources; sanitized-path / `"event_type=<id>"` for multi-partition.
    pub(crate) buffers: HashMap<String, PartitionBuffer>,
}

impl<S: ParquetSink> PartitionedParquetWriter<S> {
    pub fn new(
        sink: S,
        s3: Arc<dyn UploadSink>,
        config: BufferedWriterConfig,
        policy: FlushPolicy,
    ) -> Self {
        Self {
            sink,
            s3,
            config,
            policy,
            buffers: HashMap::new(),
        }
    }
```

- [ ] **Step 2: Add the `target` label to the three upload-outcome metrics in `flush_partition`**

Change (currently lines 349–367):

```rust
        let partition_seg = if key.is_empty() { None } else { Some(key) };
        let s3_key = build_key(&self.config.prefix, partition_seg, chrono::Utc::now());
        match self.s3.upload(&s3_key, merged).await {
            Ok(()) => {
                metrics::counter!("parquet_s3_records_written", "source" => source)
                    .increment(row_count as u64);
                metrics::counter!("parquet_s3_uploads", "source" => source).increment(1);
                let buf = self.buffers.get_mut(key).unwrap();
                buf.buffer.clear();
                buf.row_count = 0;
                buf.byte_count = 0;
                buf.last_flush = Instant::now();
                Ok(())
            }
            Err(e) => {
                metrics::counter!("parquet_s3_upload_errors", "source" => source).increment(1);
                Err(e)
            }
        }
    }
```

to:

```rust
        let partition_seg = if key.is_empty() { None } else { Some(key) };
        let s3_key = build_key(&self.config.prefix, partition_seg, chrono::Utc::now());
        let target = self.s3.target_label();
        match self.s3.upload(&s3_key, merged).await {
            Ok(()) => {
                metrics::counter!("parquet_s3_records_written", "source" => source, "target" => target)
                    .increment(row_count as u64);
                metrics::counter!("parquet_s3_uploads", "source" => source, "target" => target).increment(1);
                let buf = self.buffers.get_mut(key).unwrap();
                buf.buffer.clear();
                buf.row_count = 0;
                buf.byte_count = 0;
                buf.last_flush = Instant::now();
                Ok(())
            }
            Err(e) => {
                metrics::counter!("parquet_s3_upload_errors", "source" => source, "target" => target).increment(1);
                Err(e)
            }
        }
    }
```

- [ ] **Step 3: Add the `target` label to `parquet_s3_partitions_capped` and `parquet_s3_buffer_dropped`**

In `push()` (currently around line 214), change:

```rust
            metrics::counter!("parquet_s3_partitions_capped", "source" => self.sink.source())
                .increment(1);
```
to:
```rust
            metrics::counter!("parquet_s3_partitions_capped",
                "source" => self.sink.source(), "target" => self.s3.target_label())
                .increment(1);
```

In `drop_oldest_to_cap` (currently around line 383), the function signature is `fn drop_oldest_to_cap(buf: &mut PartitionBuffer, cap: usize, source: &'static str)` — it is a associated function called as `Self::drop_oldest_to_cap(b, cap, source)` from `push()` without access to `self.s3`. Add a `target: &'static str` parameter:

```rust
    fn drop_oldest_to_cap(buf: &mut PartitionBuffer, cap: usize, source: &'static str, target: &'static str) {
        let mut dropped = 0usize;
        while buf.row_count > cap {
            if let Some((batch, est)) = buf.buffer.pop_front() {
                let n = batch.num_rows();
                buf.row_count = buf.row_count.saturating_sub(n);
                buf.byte_count = buf.byte_count.saturating_sub(est);
                dropped += n;
            } else {
                break;
            }
        }
        if dropped > 0 {
            metrics::counter!("parquet_s3_buffer_dropped", "source" => source, "target" => target)
                .increment(dropped as u64);
            let should_warn = buf
                .last_drop_warn
                .map(|t| t.elapsed().as_secs() >= 30)
                .unwrap_or(true);
            if should_warn {
                tracing::warn!(
                    dropped,
                    source,
                    target,
                    "parquet_s3: upload failing — dropped oldest rows to stay within hard cap"
                );
                buf.last_drop_warn = Some(Instant::now());
            }
        }
    }
```

And update its one call site in `push()` (currently around line 272):
```rust
                if cap > 0
                    && let Some(b) = self.buffers.get_mut(&effective_key)
                {
                    Self::drop_oldest_to_cap(b, cap, source, self.s3.target_label());
                }
```

- [ ] **Step 4: Change `ParquetWriterHandle`'s field, `start()` signature, and `try_send`'s metric**

Change (currently lines 405–421):

```rust
#[derive(Clone)]
pub struct ParquetWriterHandle<S: ParquetSink> {
    tx: tokio::sync::mpsc::Sender<S::Record>,
    /// Source label captured at `start()` time; used for the drop metric.
    source: &'static str,
}

impl<S: ParquetSink> ParquetWriterHandle<S> {
    /// Spawn the background writer task.
    /// Returns `(handle, JoinHandle)`. The `JoinHandle` must be awaited during
    /// graceful shutdown after all senders are dropped.
    pub fn start(
        sink: S,
        s3: Arc<crate::forwarding::s3_sink::S3Sink>,
        config: BufferedWriterConfig,
        policy: FlushPolicy,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        let capacity = config.channel_capacity.max(1);
        // Capture the source label before `sink` is moved into the task.
        let source = sink.source();
```

to:

```rust
#[derive(Clone)]
pub struct ParquetWriterHandle<S: ParquetSink> {
    tx: tokio::sync::mpsc::Sender<S::Record>,
    /// Source label captured at `start()` time; used for the drop metric.
    source: &'static str,
    /// Target label captured at `start()` time; used for the drop metric.
    target: &'static str,
}

impl<S: ParquetSink> ParquetWriterHandle<S> {
    /// Spawn the background writer task.
    /// Returns `(handle, JoinHandle)`. The `JoinHandle` must be awaited during
    /// graceful shutdown after all senders are dropped.
    pub fn start(
        sink: S,
        s3: Arc<dyn UploadSink>,
        config: BufferedWriterConfig,
        policy: FlushPolicy,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        let capacity = config.channel_capacity.max(1);
        // Capture the source/target labels before `sink`/`s3` are moved into the task.
        let source = sink.source();
        let target = s3.target_label();
```

Then further down (currently around line 456), change the returned struct literal:
```rust
        (Self { tx, source }, handle)
```
to:
```rust
        (Self { tx, source, target }, handle)
```

Finally, in `try_send` (currently around lines 464–470), change:
```rust
    pub fn try_send(
        &self,
        record: S::Record,
    ) -> Result<(), tokio::sync::mpsc::error::TrySendError<S::Record>> {
        match self.tx.try_send(record) {
            Ok(()) => Ok(()),
            Err(e) => {
                metrics::counter!("parquet_s3_dropped", "source" => self.source).increment(1);
                Err(e)
            }
        }
    }
```
to:
```rust
    pub fn try_send(
        &self,
        record: S::Record,
    ) -> Result<(), tokio::sync::mpsc::error::TrySendError<S::Record>> {
        match self.tx.try_send(record) {
            Ok(()) => Ok(()),
            Err(e) => {
                metrics::counter!("parquet_s3_dropped", "source" => self.source, "target" => self.target)
                    .increment(1);
                Err(e)
            }
        }
    }
```

- [ ] **Step 5: Write a regression test proving the writer works with a non-`S3Sink` `UploadSink`**

Add to the `#[cfg(test)] mod tests` block in `src/forwarding/buffered_writer.rs` (after the existing `MockSink`/helpers, near `push_accumulates_below_row_threshold`):

```rust
    /// Proves `PartitionedParquetWriter` is destination-agnostic: an in-memory
    /// `UploadSink` (not `S3Sink`) receives the flushed bytes.
    struct RecordingSink {
        uploads: std::sync::Arc<std::sync::Mutex<Vec<(String, usize)>>>,
    }

    #[async_trait::async_trait]
    impl UploadSink for RecordingSink {
        async fn upload(&self, key: &str, body: Vec<u8>) -> anyhow::Result<()> {
            self.uploads.lock().unwrap().push((key.to_string(), body.len()));
            Ok(())
        }
        fn target_label(&self) -> &'static str {
            "recording"
        }
    }

    #[tokio::test]
    async fn partitioned_writer_uploads_via_generic_uploadsink_trait_object() {
        let uploads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink: Arc<dyn UploadSink> = Arc::new(RecordingSink { uploads: uploads.clone() });
        let (cfg, policy) = test_config(1); // flush on first row
        let mut w = PartitionedParquetWriter::new(MockSink, sink, cfg, policy);

        w.push("hello".to_string()).await.unwrap();

        let recorded = uploads.lock().unwrap();
        assert_eq!(recorded.len(), 1, "expected exactly one upload via the non-S3 sink");
        assert!(recorded[0].1 > 0, "uploaded body must be non-empty Parquet bytes");
    }

    /// Proves the `target` label reaches `parquet_s3_uploads`/`parquet_s3_upload_errors`.
    #[tokio::test]
    #[allow(clippy::mutable_key_type)]
    async fn flush_metrics_carry_the_target_label() {
        use metrics::set_default_local_recorder;
        use metrics_util::CompositeKey;
        use metrics_util::MetricKind;
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let uploads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink: Arc<dyn UploadSink> = Arc::new(RecordingSink { uploads });
        let (cfg, policy) = test_config(1);
        let mut w = PartitionedParquetWriter::new(MockSink, sink, cfg, policy);

        w.push("hello".to_string()).await.unwrap();

        let snapshot = snapshotter.snapshot();
        let map = snapshot.into_hashmap();
        let key = CompositeKey::new(
            MetricKind::Counter,
            metrics::Key::from_parts(
                "parquet_s3_uploads",
                vec![
                    metrics::Label::new("source", "test"),
                    metrics::Label::new("target", "recording"),
                ],
            ),
        );
        let count = map
            .get(&key)
            .map(|(_, _, v)| if let DebugValue::Counter(c) = v { *c } else { 0 })
            .unwrap_or(0);
        assert_eq!(count, 1, "expected parquet_s3_uploads{{source=\"test\",target=\"recording\"}} == 1");
    }
```

- [ ] **Step 6: Run the full `buffered_writer` test module and confirm zero regressions**

```bash
cargo test -p logthing --lib forwarding::buffered_writer -- --nocapture
```
Expected: every existing test in this module (config deserialization, `build_key`, push/flush/cap tests, `ParquetWriterHandle` tests, byte/age triggers, `_overflow` tests) still passes unchanged, plus the two new tests from Step 5. This is the proof that generalizing the sink type introduced zero behavior change for the existing `S3Sink`-backed path.

- [ ] **Step 7: Run every other source's existing test module to confirm the coercion works with no source-file edits**

```bash
cargo test -p logthing --lib forwarding::zeek_s3 forwarding::suricata_s3 forwarding::ipfix_s3 forwarding::syslog_s3 forwarding::structured_syslog_s3 forwarding::sflow_s3 forwarding::generic_s3 forwarding::parquet_s3
```
Expected: all pass, with **no source changes** in any of these 7 files — this confirms `Arc<S3Sink>` still coerces to `Arc<dyn UploadSink>` at every existing `*_start`/`ParquetWriterHandle::start` call site.

- [ ] **Step 8: Commit**

```bash
git add src/forwarding/buffered_writer.rs
git commit -m "refactor(forwarding): generalize PartitionedParquetWriter to Arc<dyn UploadSink>"
```

---

### Task 4: `ZeekLocalConfig` + `ZeekConfig.local`

**Files:**
- Modify: `src/config/mod.rs`

**Interfaces:**
- Produces: `pub struct ZeekLocalConfig { pub directory: PathBuf, pub prefix: String, pub flush_threshold_bytes: usize, pub flush_interval_secs: u64, pub channel_capacity: usize, pub max_buffer_rows: usize }`; `ZeekConfig.local: Option<ZeekLocalConfig>` (default `None`).

- [ ] **Step 1: Write the failing tests**

Add to the `#[cfg(test)] mod tests` block in `src/config/mod.rs` (after the existing `zeek_s3_flat_toml_deserializes_correctly` test):

```rust
    #[test]
    fn zeek_local_absent_gives_none() {
        let cfg = Config::default();
        assert!(
            cfg.zeek.local.is_none(),
            "absent [zeek.local] must deserialize to None"
        );
    }

    #[test]
    fn zeek_local_config_deserializes_from_toml() {
        let toml_str = r#"
directory = "/var/log/logthing/zeek"
prefix = "zeek"
flush_threshold_bytes = 52428800
flush_interval_secs = 300
channel_capacity = 512
max_buffer_rows = 50000
"#;
        let cfg: ZeekLocalConfig = toml::from_str(toml_str).expect("deserialize");
        assert_eq!(cfg.directory, std::path::PathBuf::from("/var/log/logthing/zeek"));
        assert_eq!(cfg.prefix, "zeek");
        assert_eq!(cfg.flush_threshold_bytes, 52_428_800);
        assert_eq!(cfg.flush_interval_secs, 300);
        assert_eq!(cfg.channel_capacity, 512);
        assert_eq!(cfg.max_buffer_rows, 50_000);
    }

    #[test]
    fn zeek_local_config_defaults_apply_when_only_directory_given() {
        let toml_str = r#"directory = "/data/zeek""#;
        let cfg: ZeekLocalConfig = toml::from_str(toml_str).expect("deserialize");
        assert_eq!(cfg.prefix, "zeek");
        assert_eq!(cfg.flush_threshold_bytes, 100 * 1024 * 1024);
        assert_eq!(cfg.flush_interval_secs, 900);
        assert_eq!(cfg.channel_capacity, 256);
        assert_eq!(cfg.max_buffer_rows, 100_000);
    }

    #[test]
    fn zeek_s3_and_local_can_both_be_configured_simultaneously() {
        let toml_str = r#"
[zeek]
enabled = true

[zeek.s3]
endpoint = "http://minio:9000"
bucket = "b"
region = "us-east-1"
access_key = "k"
secret_key = "s"

[zeek.local]
directory = "/data/zeek"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("deserialize");
        assert!(cfg.zeek.s3.is_some(), "s3 must deserialize when both present");
        assert!(cfg.zeek.local.is_some(), "local must deserialize when both present");
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p logthing --lib config::tests::zeek_local -- --nocapture
```
Expected: FAIL — `ZeekLocalConfig` does not exist / `cfg.zeek.local` field does not exist.

- [ ] **Step 3: Add `ZeekLocalConfig` and the `local` field**

In `src/config/mod.rs`, change `ZeekConfig` (currently lines 249–274):

```rust
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ZeekConfig {
    #[serde(default = "default_zeek_enabled")]
    pub enabled: bool,

    #[serde(default = "default_zeek_tcp_port")]
    pub tcp_port: u16,

    #[serde(default = "default_zeek_bind_address")]
    pub bind_address: String,

    /// Optional S3 persistence. Absent from TOML → `None` → no persistence.
    #[serde(default)]
    pub s3: Option<ZeekS3Config>,
}

impl Default for ZeekConfig {
    fn default() -> Self {
        Self {
            enabled: default_zeek_enabled(),
            tcp_port: default_zeek_tcp_port(),
            bind_address: default_zeek_bind_address(),
            s3: None,
        }
    }
}
```

to:

```rust
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ZeekConfig {
    #[serde(default = "default_zeek_enabled")]
    pub enabled: bool,

    #[serde(default = "default_zeek_tcp_port")]
    pub tcp_port: u16,

    #[serde(default = "default_zeek_bind_address")]
    pub bind_address: String,

    /// Optional S3 persistence. Absent from TOML → `None` → no persistence.
    #[serde(default)]
    pub s3: Option<ZeekS3Config>,

    /// Optional local-disk persistence. Absent from TOML → `None` → no
    /// persistence. Independent of `s3` — both may be configured
    /// simultaneously, in which case records are written to both.
    #[serde(default)]
    pub local: Option<ZeekLocalConfig>,
}

impl Default for ZeekConfig {
    fn default() -> Self {
        Self {
            enabled: default_zeek_enabled(),
            tcp_port: default_zeek_tcp_port(),
            bind_address: default_zeek_bind_address(),
            s3: None,
            local: None,
        }
    }
}
```

Then, immediately after the existing `ZeekS3Config` struct and its `default_zeek_*` functions (currently ending at line 323, right before the `SuricataConfig` section), add:

```rust
/// Per-source local-disk persistence config for the Zeek listener. Mirrors
/// `ZeekS3Config`'s flush-policy shape (reusing the same default functions),
/// swapping the S3 connection for a root directory. Independent of `s3`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ZeekLocalConfig {
    /// Root directory Parquet files are written under (created if missing).
    pub directory: PathBuf,
    /// Key prefix, slash-free (default: `"zeek"` — same default as `zeek.s3`).
    #[serde(default = "default_zeek_s3_prefix")]
    pub prefix: String,
    /// Flush when estimated buffer bytes exceeds this (default: 100 MiB).
    #[serde(default = "default_zeek_flush_bytes")]
    pub flush_threshold_bytes: usize,
    /// Flush after this many seconds regardless of buffer size (default: 900).
    #[serde(default = "default_zeek_flush_secs")]
    pub flush_interval_secs: u64,
    /// Bounded channel capacity (default: 256).
    #[serde(default = "default_zeek_channel_capacity")]
    pub channel_capacity: usize,
    /// Maximum buffered rows before hard cap kicks in (default: 100_000).
    #[serde(default = "default_zeek_max_buffer_rows")]
    pub max_buffer_rows: usize,
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test -p logthing --lib config -- --nocapture
```
Expected: all `config` module tests pass, including the 4 new ones and the pre-existing `zeek_s3_absent_gives_none` / `zeek_s3_flat_toml_deserializes_correctly`.

- [ ] **Step 5: Commit**

```bash
git add src/config/mod.rs
git commit -m "feat(config): add ZeekLocalConfig, ZeekConfig.local (independent of zeek.s3)"
```

---

### Task 5: `zeek_local_start` + `MultiZeekHandler`

**Files:**
- Modify: `src/forwarding/zeek_s3.rs`

**Interfaces:**
- Consumes: `LocalDiskSink` (Task 2), `ZeekLocalConfig` (Task 4), `UploadSink` (Task 1), `ZeekRecord` (already `#[derive(Clone)]` — no change needed, confirmed in `src/zeek/mod.rs:6`).
- Produces: `pub fn zeek_local_start(cfg: &ZeekLocalConfig, sink: Arc<LocalDiskSink>) -> (ZeekS3Handler, JoinHandle<()>)`; `pub struct MultiZeekHandler(pub Vec<Arc<dyn ZeekHandler>>)` implementing `ZeekHandler`.

- [ ] **Step 1: Refactor `zeek_start`'s body into a shared private helper**

In `src/forwarding/zeek_s3.rs`, change the existing `zeek_start` function (currently lines 171–197):

```rust
pub fn zeek_start(
    cfg: &ZeekS3Config,
    s3: std::sync::Arc<crate::forwarding::s3_sink::S3Sink>,
) -> (ZeekS3Handler, tokio::task::JoinHandle<()>) {
    use crate::forwarding::buffered_writer::{
        BufferedWriterConfig, FlushPolicy, ParquetWriterHandle,
    };

    /// Replaces the old `MAX_ZEEK_STREAMS` constant.
    const DEFAULT_MAX_ZEEK_PARTITIONS: usize = 256;

    let bwc = BufferedWriterConfig {
        connection: cfg.connection.clone(),
        prefix: cfg.prefix.clone(),
        max_buffer_rows: cfg.max_buffer_rows,
        flush_threshold_bytes: cfg.flush_threshold_bytes,
        flush_interval_secs: cfg.flush_interval_secs,
        channel_capacity: cfg.channel_capacity,
        max_partitions: DEFAULT_MAX_ZEEK_PARTITIONS,
    };
    let policy = FlushPolicy {
        max_rows: cfg.max_buffer_rows,
        max_bytes: cfg.flush_threshold_bytes,
        interval: std::time::Duration::from_secs(cfg.flush_interval_secs),
    };
    ParquetWriterHandle::start(ZeekSink, s3, bwc, policy)
}
```

to:

```rust
/// `BufferedWriterConfig.connection` is never read by the generic writer once
/// a pre-built sink is supplied — only `prefix`/`max_buffer_rows`/etc. are used
/// in `push`/`flush_partition`/`drop_oldest_to_cap`. For a local-disk-only
/// pipeline there is no S3 connection to report, so this fills the field with
/// harmless placeholder values rather than changing its required type (which
/// would ripple into every other source's `BufferedWriterConfig` literal).
fn unused_s3_connection_placeholder() -> crate::config::S3ConnectionConfig {
    crate::config::S3ConnectionConfig {
        endpoint: String::new(),
        bucket: String::new(),
        region: String::new(),
        access_key: String::new(),
        secret_key: String::new(),
    }
}

/// Shared by `zeek_start` (S3) and `zeek_local_start` (local disk): builds a
/// `ZeekS3Handler` from flush-policy fields and a pre-built, already-typed
/// `Arc<dyn UploadSink>`.
fn build_zeek_handle(
    prefix: String,
    max_buffer_rows: usize,
    flush_threshold_bytes: usize,
    flush_interval_secs: u64,
    channel_capacity: usize,
    sink: std::sync::Arc<dyn crate::forwarding::buffered_writer::UploadSink>,
) -> (ZeekS3Handler, tokio::task::JoinHandle<()>) {
    use crate::forwarding::buffered_writer::{
        BufferedWriterConfig, FlushPolicy, ParquetWriterHandle,
    };

    /// Replaces the old `MAX_ZEEK_STREAMS` constant.
    const DEFAULT_MAX_ZEEK_PARTITIONS: usize = 256;

    let bwc = BufferedWriterConfig {
        connection: unused_s3_connection_placeholder(),
        prefix,
        max_buffer_rows,
        flush_threshold_bytes,
        flush_interval_secs,
        channel_capacity,
        max_partitions: DEFAULT_MAX_ZEEK_PARTITIONS,
    };
    let policy = FlushPolicy {
        max_rows: max_buffer_rows,
        max_bytes: flush_threshold_bytes,
        interval: std::time::Duration::from_secs(flush_interval_secs),
    };
    ParquetWriterHandle::start(ZeekSink, sink, bwc, policy)
}

/// Construct a `ZeekS3Handler` (i.e. `ParquetWriterHandle<ZeekSink>`) from a
/// `ZeekS3Config` and a pre-built `S3Sink`.
///
/// Returns `(handler, writer_task_handle)`. The caller should retain the `JoinHandle`
/// and await it during graceful shutdown, after all `Arc<dyn ZeekHandler>` references
/// have been dropped so the channel closes and the final flush fires.
pub fn zeek_start(
    cfg: &ZeekS3Config,
    s3: std::sync::Arc<crate::forwarding::s3_sink::S3Sink>,
) -> (ZeekS3Handler, tokio::task::JoinHandle<()>) {
    build_zeek_handle(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        cfg.flush_threshold_bytes,
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        s3,
    )
}

/// Construct a `ZeekS3Handler` from a `ZeekLocalConfig` and a pre-built
/// `LocalDiskSink`. Structurally identical to `zeek_start`, writing to local
/// disk instead of S3 — same `ZeekSink` adapter, same buffering/flush/cap
/// machinery, same S3-key-shaped relative path layout on disk.
pub fn zeek_local_start(
    cfg: &crate::config::ZeekLocalConfig,
    sink: std::sync::Arc<crate::forwarding::local_sink::LocalDiskSink>,
) -> (ZeekS3Handler, tokio::task::JoinHandle<()>) {
    build_zeek_handle(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        cfg.flush_threshold_bytes,
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        sink,
    )
}
```

- [ ] **Step 2: Add `MultiZeekHandler`**

After the `ZeekS3Handler` type alias + `ZeekHandler` impl block (currently ending at line 155, right before the `// --- zeek_start — convenience constructor ---` section), add:

```rust
// ---------------------------------------------------------------------------
// MultiZeekHandler — fan-out to multiple destinations
// ---------------------------------------------------------------------------

/// Fans out each record to every configured handler. Used only when both
/// `.s3` and `.local` persistence resolve to a live handler for the same
/// run, so each destination keeps its own independent buffer, flush policy,
/// backpressure, and hard cap (no shared state between destinations).
pub struct MultiZeekHandler(pub Vec<std::sync::Arc<dyn crate::zeek::listener::ZeekHandler>>);

#[async_trait::async_trait]
impl crate::zeek::listener::ZeekHandler for MultiZeekHandler {
    async fn handle_record(&self, record: ZeekRecord, source: std::net::SocketAddr) {
        for handler in &self.0 {
            handler.handle_record(record.clone(), source).await;
        }
    }
}
```

- [ ] **Step 3: Write the tests**

Add to the `#[cfg(test)] mod tests` block in `src/forwarding/zeek_s3.rs` (after the existing `zeek_start_wires_handler_and_join_handle` test):

```rust
    #[tokio::test]
    async fn zeek_local_start_wires_handler_and_join_handle() {
        use crate::config::ZeekLocalConfig;
        use crate::forwarding::local_sink::LocalDiskSink;
        use crate::zeek::listener::ZeekHandler;
        use std::net::SocketAddr;

        let dir = tempfile::tempdir().unwrap();
        let sink = Arc::new(
            LocalDiskSink::new(dir.path().to_path_buf())
                .await
                .expect("LocalDiskSink::new"),
        );
        let cfg = ZeekLocalConfig {
            directory: dir.path().to_path_buf(),
            prefix: "zeek".to_string(),
            flush_threshold_bytes: 1, // flush on first push
            flush_interval_secs: 3600,
            channel_capacity: 256,
            max_buffer_rows: 100_000,
        };
        let (handler, join_handle) = zeek_local_start(&cfg, sink);

        let src: SocketAddr = "127.0.0.1:47760".parse().unwrap();
        handler.handle_record(make_conn_record("Local1"), src).await;

        // Give the background flush a moment, then drop to trigger shutdown flush.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        drop(handler);
        tokio::time::timeout(std::time::Duration::from_secs(5), join_handle)
            .await
            .expect("writer task must exit within 5s")
            .expect("writer task must not panic");

        // A real Parquet file must exist under zeek/conn/ on disk.
        let conn_dir = dir.path().join("zeek/conn");
        let found = std::fs::read_dir(&conn_dir)
            .expect("zeek/conn directory must exist")
            .count();
        assert!(found >= 1, "expected at least one Parquet file under {conn_dir:?}");
    }

    #[tokio::test]
    async fn multi_zeek_handler_fans_out_to_every_inner_handler() {
        use crate::zeek::listener::ZeekHandler;
        use std::net::SocketAddr;
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct CountingHandler(Arc<AtomicUsize>);
        #[async_trait::async_trait]
        impl ZeekHandler for CountingHandler {
            async fn handle_record(&self, _record: ZeekRecord, _source: SocketAddr) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let count_a = Arc::new(AtomicUsize::new(0));
        let count_b = Arc::new(AtomicUsize::new(0));
        let multi = MultiZeekHandler(vec![
            Arc::new(CountingHandler(count_a.clone())),
            Arc::new(CountingHandler(count_b.clone())),
        ]);

        let src: SocketAddr = "127.0.0.1:47760".parse().unwrap();
        multi.handle_record(make_conn_record("Fan1"), src).await;

        assert_eq!(count_a.load(Ordering::SeqCst), 1, "handler A must receive the record");
        assert_eq!(count_b.load(Ordering::SeqCst), 1, "handler B must receive the record");
    }

    #[tokio::test]
    async fn multi_zeek_handler_survives_one_inner_handler_dropping() {
        use crate::zeek::listener::ZeekHandler;
        use std::net::SocketAddr;

        // A handler backed by a writer with channel_capacity=1 and a slow/unreachable
        // sink will drop records via try_send rather than blocking — proving that a
        // struggling destination cannot stall MultiZeekHandler's fan-out to the other.
        let sink = unreachable_sink().await;
        let cfg = ZeekS3Config {
            connection: S3ConnectionConfig {
                endpoint: "http://127.0.0.1:1".to_string(),
                bucket: "test-bucket".to_string(),
                region: "us-east-1".to_string(),
                access_key: "AKIATEST".to_string(),
                secret_key: "SECRETTEST".to_string(),
            },
            prefix: "zeek".to_string(),
            flush_threshold_bytes: usize::MAX,
            flush_interval_secs: 3600,
            channel_capacity: 1,
            max_buffer_rows: 1,
        };
        let (struggling_handler, _jh) = zeek_start(&cfg, sink);

        use std::sync::atomic::{AtomicUsize, Ordering};
        struct CountingHandler(Arc<AtomicUsize>);
        #[async_trait::async_trait]
        impl ZeekHandler for CountingHandler {
            async fn handle_record(&self, _record: ZeekRecord, _source: SocketAddr) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let healthy_count = Arc::new(AtomicUsize::new(0));
        let multi = MultiZeekHandler(vec![
            Arc::new(struggling_handler),
            Arc::new(CountingHandler(healthy_count.clone())),
        ]);

        let src: SocketAddr = "127.0.0.1:47760".parse().unwrap();
        for i in 0..20 {
            multi.handle_record(make_conn_record(&format!("C{i}")), src).await;
        }

        assert_eq!(
            healthy_count.load(Ordering::SeqCst),
            20,
            "the healthy handler must receive every record even if the struggling one drops some"
        );
    }
```

- [ ] **Step 4: Run the tests**

```bash
cargo test -p logthing --lib forwarding::zeek_s3 -- --nocapture
```
Expected: all existing tests plus the 3 new ones pass. Note: `zeek_local_start_wires_handler_and_join_handle` requires `tempfile` — already a dev-dependency (`Cargo.toml`), so no new import needed beyond `use tempfile;` implicitly via `tempfile::tempdir()`.

- [ ] **Step 5: Commit**

```bash
git add src/forwarding/zeek_s3.rs
git commit -m "feat(forwarding): add zeek_local_start + MultiZeekHandler fan-out"
```

---

### Task 6: `main.rs` wiring

**Files:**
- Modify: `src/main.rs:186-224` (the Zeek listener startup block)

**Interfaces:**
- Consumes: `forwarding::local_sink::LocalDiskSink::new` (Task 2), `forwarding::zeek_s3::zeek_local_start` + `MultiZeekHandler` (Task 5), `config.zeek.local` (Task 4).

- [ ] **Step 1: Replace the Zeek startup block**

In `src/main.rs`, replace the block currently at lines 185–224:

```rust
    // -----------------------------------------------------------------------
    // Start Zeek listener if enabled
    // -----------------------------------------------------------------------
    if config.zeek.enabled {
        let zeek_config_clone = config.clone();
        let zeek_shutdown_rx = shutdown_rx.clone();

        let zeek_handler: Arc<dyn zeek::listener::ZeekHandler> =
            if let Some(s3_cfg) = zeek_config_clone.zeek.s3.as_ref() {
                match forwarding::s3_sink::S3Sink::from_connection(&s3_cfg.connection).await {
                    Ok(sink) => {
                        let (handler, writer_handle) =
                            forwarding::zeek_s3::zeek_start(s3_cfg, Arc::new(sink));
                        writer_handles.push(writer_handle);
                        Arc::new(handler)
                    }
                    Err(e) => {
                        error!(
                            "Failed to create S3Sink for Zeek persistence, \
                                 falling back to DefaultZeekHandler: {e}"
                        );
                        Arc::new(zeek::listener::DefaultZeekHandler)
                    }
                }
            } else {
                Arc::new(zeek::listener::DefaultZeekHandler)
            };

        let listener_config = zeek::listener::ZeekListenerConfig {
            tcp_port: zeek_config_clone.zeek.tcp_port,
            bind_address: zeek_config_clone.zeek.bind_address.clone(),
        };
        let handle = tokio::spawn(async move {
            let listener = zeek::listener::ZeekListener::new(listener_config, zeek_handler);
            if let Err(e) = listener.start_with_shutdown(zeek_shutdown_rx).await {
                error!("Zeek listener error: {}", e);
            }
        });
        listener_handles.push(handle);
    }
```

with:

```rust
    // -----------------------------------------------------------------------
    // Start Zeek listener if enabled
    // -----------------------------------------------------------------------
    if config.zeek.enabled {
        let zeek_config_clone = config.clone();
        let zeek_shutdown_rx = shutdown_rx.clone();

        let mut zeek_handlers: Vec<Arc<dyn zeek::listener::ZeekHandler>> = Vec::new();

        if let Some(s3_cfg) = zeek_config_clone.zeek.s3.as_ref() {
            match forwarding::s3_sink::S3Sink::from_connection(&s3_cfg.connection).await {
                Ok(sink) => {
                    let (handler, writer_handle) =
                        forwarding::zeek_s3::zeek_start(s3_cfg, Arc::new(sink));
                    writer_handles.push(writer_handle);
                    zeek_handlers.push(Arc::new(handler));
                }
                Err(e) => {
                    error!(
                        "Failed to create S3Sink for Zeek persistence, \
                             skipping S3 target: {e}"
                    );
                }
            }
        }

        if let Some(local_cfg) = zeek_config_clone.zeek.local.as_ref() {
            match forwarding::local_sink::LocalDiskSink::new(local_cfg.directory.clone()).await {
                Ok(sink) => {
                    let (handler, writer_handle) =
                        forwarding::zeek_s3::zeek_local_start(local_cfg, Arc::new(sink));
                    writer_handles.push(writer_handle);
                    zeek_handlers.push(Arc::new(handler));
                }
                Err(e) => {
                    error!(
                        "Failed to create LocalDiskSink for Zeek persistence, \
                             skipping local target: {e}"
                    );
                }
            }
        }

        let zeek_handler: Arc<dyn zeek::listener::ZeekHandler> = match zeek_handlers.len() {
            0 => Arc::new(zeek::listener::DefaultZeekHandler),
            1 => zeek_handlers.into_iter().next().unwrap(),
            _ => Arc::new(forwarding::zeek_s3::MultiZeekHandler(zeek_handlers)),
        };

        let listener_config = zeek::listener::ZeekListenerConfig {
            tcp_port: zeek_config_clone.zeek.tcp_port,
            bind_address: zeek_config_clone.zeek.bind_address.clone(),
        };
        let handle = tokio::spawn(async move {
            let listener = zeek::listener::ZeekListener::new(listener_config, zeek_handler);
            if let Err(e) = listener.start_with_shutdown(zeek_shutdown_rx).await {
                error!("Zeek listener error: {}", e);
            }
        });
        listener_handles.push(handle);
    }
```

- [ ] **Step 2: Build the whole workspace to confirm no type errors**

```bash
cargo build -p logthing 2>&1 | tail -50
```
Expected: clean build, no errors or new warnings attributable to this change.

- [ ] **Step 3: Run the full existing test suite to confirm no regressions from the `main.rs` change**

```bash
cargo test -p logthing --lib 2>&1 | tail -30
```
Expected: all tests pass (this file has no `#[cfg(test)]` module of its own to extend — `main.rs` wiring is exercised by the e2e test in Task 8, not a unit test).

- [ ] **Step 4: Commit**

```bash
git add src/main.rs
git commit -m "feat(main): wire zeek.local alongside zeek.s3, fan out via MultiZeekHandler when both configured"
```

---

### Task 7: Integration test — real Parquet round-trip through `LocalDiskSink`

**Files:**
- Create: `tests/zeek_local_integration.rs`

**Interfaces:**
- Consumes: `zeek_start`'s sibling `zeek_local_start` (Task 5), `LocalDiskSink` (Task 2), `ZeekRecord` (existing).

- [ ] **Step 1: Write the test**

Create `tests/zeek_local_integration.rs`:

```rust
//! Integration test: ZeekRecord → zeek_local_start → real Parquet files on
//! local disk, read back with a real Parquet reader.
//!
//! Unlike `zeek_s3_integration.rs` (gated on a running MinIO), this test needs
//! no external service — local disk is always available — so it runs
//! unconditionally in CI.

use logthing::config::ZeekLocalConfig;
use logthing::forwarding::local_sink::LocalDiskSink;
use logthing::forwarding::zeek_s3::zeek_local_start;
use logthing::zeek::ZeekRecord;
use logthing::zeek::listener::ZeekHandler;
use std::sync::Arc;

fn make_conn_record(uid: &str) -> ZeekRecord {
    ZeekRecord {
        log_path: "conn".to_string(),
        fields: serde_json::json!({
            "_path": "conn",
            "ts": 1700000000.0,
            "uid": uid,
            "id.orig_h": "10.0.0.1",
            "id.orig_p": 12345,
            "id.resp_h": "10.0.0.2",
            "id.resp_p": 443,
            "proto": "tcp",
            "conn_state": "SF",
            "orig_bytes": 1024,
            "resp_bytes": 8192,
        }),
        received_at: chrono::Utc::now(),
    }
}

fn make_dns_record(uid: &str) -> ZeekRecord {
    ZeekRecord {
        log_path: "dns".to_string(),
        fields: serde_json::json!({
            "_path": "dns",
            "ts": 1700000100.0,
            "uid": uid,
            "id.orig_h": "192.168.1.100",
            "id.orig_p": 12345,
            "id.resp_h": "8.8.8.8",
            "id.resp_p": 53,
            "query": "example.com",
            "qtype_name": "A",
            "rcode_name": "NOERROR",
        }),
        received_at: chrono::Utc::now(),
    }
}

#[tokio::test]
async fn zeek_records_appear_as_parquet_on_local_disk() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sink = Arc::new(
        LocalDiskSink::new(dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new"),
    );
    let cfg = ZeekLocalConfig {
        directory: dir.path().to_path_buf(),
        prefix: "zeek".to_string(),
        max_buffer_rows: 1, // flush immediately on first record per partition
        flush_threshold_bytes: 1,
        flush_interval_secs: 3600,
        channel_capacity: 256,
    };

    let (handler, _writer_task) = zeek_local_start(&cfg, sink);

    let src: std::net::SocketAddr = "127.0.0.1:47760".parse().unwrap();
    handler.handle_record(make_conn_record("CLocal001"), src).await;
    handler.handle_record(make_dns_record("DLocal001"), src).await;

    // Give the background task time to flush (max_buffer_rows=1 and
    // flush_threshold_bytes=1 both trigger flush on the first push per partition).
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // --- Verify the typed `conn` record under zeek/conn/ ---
    {
        let conn_dir = dir.path().join("zeek/conn");
        let entries: Vec<_> = std::fs::read_dir(&conn_dir)
            .unwrap_or_else(|e| panic!("expected {conn_dir:?} to exist: {e}"))
            .collect();
        assert!(!entries.is_empty(), "expected at least one Parquet file under {conn_dir:?}");

        let file_path = entries[0].as_ref().unwrap().path();
        let bytes = std::fs::read(&file_path).expect("read parquet file");

        use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
        let builder = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(bytes))
            .expect("parquet builder for conn");
        let schema = builder.schema().clone();
        for col in ["ts", "uid", "id_orig_h", "proto", "conn_state", "_extra"] {
            assert!(schema.field_with_name(col).is_ok(), "expected column '{col}' in conn schema");
        }

        let mut reader = builder.build().expect("parquet reader for conn");
        let rb = reader.next().expect("at least one batch").expect("batch ok");
        assert_eq!(rb.num_rows(), 1);

        use arrow::array::StringArray;
        let uid = rb
            .column_by_name("uid")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(uid.value(0), "CLocal001");
    }

    // --- Verify the typed `dns` record under zeek/dns/ ---
    {
        let dns_dir = dir.path().join("zeek/dns");
        let entries: Vec<_> = std::fs::read_dir(&dns_dir)
            .unwrap_or_else(|e| panic!("expected {dns_dir:?} to exist: {e}"))
            .collect();
        assert!(!entries.is_empty(), "expected at least one Parquet file under {dns_dir:?}");

        let file_path = entries[0].as_ref().unwrap().path();
        let bytes = std::fs::read(&file_path).expect("read parquet file");

        use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
        let builder = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(bytes))
            .expect("parquet builder for dns");
        let mut reader = builder.build().expect("parquet reader for dns");
        let rb = reader.next().expect("at least one batch").expect("batch ok");
        assert_eq!(rb.num_rows(), 1);

        use arrow::array::StringArray;
        let uid = rb
            .column_by_name("uid")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(uid.value(0), "DLocal001");
    }

    // --- No stray temp files left behind anywhere under the root ---
    for entry in walk_all_files(dir.path()) {
        let name = entry.file_name().unwrap().to_string_lossy();
        assert!(!name.contains(".tmp-"), "found leftover temp file: {entry:?}");
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

- [ ] **Step 2: Run the test**

```bash
cargo test --test zeek_local_integration -- --nocapture
```
Expected: `zeek_records_appear_as_parquet_on_local_disk` passes, with no external services required.

- [ ] **Step 3: Commit**

```bash
git add tests/zeek_local_integration.rs
git commit -m "test(zeek): integration test proving real Parquet round-trip through LocalDiskSink"
```

---

### Task 8: E2E — extend the docker-compose simulation environment

**Files:**
- Modify: `tests/e2e/simulation-environment/docker-compose.yml`
- Modify: `tests/e2e/simulation-environment/config/logthing.toml`
- Create: `tests/e2e/simulation-environment/zeek-local-verifier/entrypoint.py`
- Create: `tests/e2e/simulation-environment/zeek-local-verifier/Dockerfile`

**Interfaces:**
- Consumes: the `[zeek.local]` config wiring from Tasks 4 and 6.

- [ ] **Step 1: Add `[zeek.local]` to the e2e config**

In `tests/e2e/simulation-environment/config/logthing.toml`, change the existing `[zeek]`/`[zeek.s3]` section (currently lines 39–51):

```toml
[zeek]
enabled = true
tcp_port = 47760

[zeek.s3]
endpoint   = "http://minio:9000"
bucket     = "zeek-logs"
region     = "us-east-1"
access_key = "miniouser"
secret_key = "miniopassword"
prefix     = "zeek"
flush_threshold_bytes = 1
flush_interval_secs   = 5
```

to:

```toml
[zeek]
enabled = true
tcp_port = 47760

[zeek.s3]
endpoint   = "http://minio:9000"
bucket     = "zeek-logs"
region     = "us-east-1"
access_key = "miniouser"
secret_key = "miniopassword"
prefix     = "zeek"
flush_threshold_bytes = 1
flush_interval_secs   = 5

[zeek.local]
directory             = "/var/log/zeek-local"
prefix                = "zeek"
flush_threshold_bytes = 1
flush_interval_secs   = 5
```

- [ ] **Step 2: Add a shared volume and mount it into both `logthing` and a new verifier service**

In `tests/e2e/simulation-environment/docker-compose.yml`, add a named volume mount to the `logthing` service's existing `volumes:` list (currently just `- ./config/logthing.toml:/etc/logthing/config.toml:ro`):

```yaml
  logthing:
    build:
      context: ../../..
    image: logthing:e2e
    environment:
      - RUST_LOG=info
      - WEF__TLS__ENABLED=false
    volumes:
      - ./config/logthing.toml:/etc/logthing/config.toml:ro
      - zeek-local-data:/var/log/zeek-local
    depends_on:
      - minio
```

Add the new verifier service after the existing `zeek-s3-verifier` service block:

```yaml
  zeek-local-verifier:
    build:
      context: .
      dockerfile: zeek-local-verifier/Dockerfile
    environment:
      - ZEEK_LOCAL_DIR=/var/log/zeek-local
      - E2E_TIMEOUT_SECS=60
    volumes:
      - zeek-local-data:/var/log/zeek-local:ro
    depends_on:
      - zeek-generator
      - logthing
    networks:
      - e2e
```

Add the named volume to the top-level `volumes:` section (create this section if absent; if a `networks:` section already exists at the bottom, add `volumes:` alongside it):

```yaml
volumes:
  zeek-local-data:
```

- [ ] **Step 3: Write the local-disk verifier**

Create `tests/e2e/simulation-environment/zeek-local-verifier/entrypoint.py` (mirrors `zeek-s3-verifier/entrypoint.py`'s structure, reading local files instead of S3):

```python
#!/usr/bin/env python3
"""
Zeek local-disk verifier for E2E testing.

Walks a local directory tree (shared volume with the `logthing` container) for
Parquet objects under zeek/conn/ and zeek/dns/, downloads each, and validates
schema and row count. Mirrors zeek-s3-verifier/entrypoint.py's checks, applied
to the local-disk target instead of MinIO.
"""

import glob
import os
import sys
import time

import pyarrow.parquet as pq

ZEEK_LOCAL_DIR = os.environ.get("ZEEK_LOCAL_DIR", "/var/log/zeek-local")
TIMEOUT = int(os.environ.get("E2E_TIMEOUT_SECS", "60"))

EXPECTED_STREAMS = {
    "zeek/conn": {
        "min_rows": 5,
        "required_columns": ["ts", "uid", "id_orig_h", "id_orig_p",
                              "id_resp_h", "id_resp_p", "proto",
                              "orig_bytes", "conn_state", "_extra"],
    },
    "zeek/dns": {
        "min_rows": 3,
        "required_columns": ["ts", "uid", "query", "qtype_name",
                              "rcode_name", "_extra"],
    },
}


def scan_dir(relative_prefix):
    """Read every .parquet file under ZEEK_LOCAL_DIR/relative_prefix/**,
    return (total_rows, union_of_columns, file_count)."""
    pattern = os.path.join(ZEEK_LOCAL_DIR, relative_prefix, "**", "*.parquet")
    files = glob.glob(pattern, recursive=True)
    total_rows = 0
    columns = set()
    for path in files:
        table = pq.read_table(path)
        total_rows += table.num_rows
        columns |= set(table.schema.names)
    return total_rows, columns, len(files)


def verify_stream(relative_prefix, spec, timeout):
    deadline = time.time() + timeout
    total_rows, columns, n = 0, set(), 0
    while time.time() < deadline:
        total_rows, columns, n = scan_dir(relative_prefix)
        if total_rows >= spec["min_rows"]:
            break
        time.sleep(3)

    missing = [c for c in spec["required_columns"] if c not in columns]
    if missing:
        print(
            f"ERROR [{relative_prefix}]: missing columns: {missing} "
            f"(saw {sorted(columns)} across {n} file(s))",
            file=sys.stderr,
        )
        sys.exit(1)
    if total_rows < spec["min_rows"]:
        print(
            f"ERROR [{relative_prefix}]: expected >= {spec['min_rows']} rows, "
            f"got {total_rows} across {n} file(s) within {timeout}s",
            file=sys.stderr,
        )
        sys.exit(1)
    print(
        f"OK [{relative_prefix}]: {total_rows} row(s) across {n} file(s), "
        f"{len(columns)} column(s): {sorted(columns)}"
    )


def main():
    for relative_prefix, spec in EXPECTED_STREAMS.items():
        verify_stream(relative_prefix, spec, TIMEOUT)
    print("Zeek local-disk verifier succeeded")
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(0)


if __name__ == "__main__":
    main()
```

Create `tests/e2e/simulation-environment/zeek-local-verifier/Dockerfile` (mirrors `zeek-s3-verifier/Dockerfile`, minus the `boto3` dependency since there is no S3 client involved):

```dockerfile
FROM python:3.12-slim

RUN pip install --no-cache-dir pyarrow

COPY zeek-local-verifier/entrypoint.py /entrypoint.py

ENTRYPOINT ["python3", "/entrypoint.py"]
```

- [ ] **Step 4: Run the e2e simulation**

```bash
cd tests/e2e/simulation-environment
docker compose up --build --abort-on-container-exit zeek-local-verifier
docker compose down -v
```
Expected: `zeek-local-verifier` prints `OK [zeek/conn]: ...` and `OK [zeek/dns]: ...` then `Zeek local-disk verifier succeeded`, and exits 0. The existing `zeek-s3-verifier` service is unaffected (still exercises the same records via the S3 target, run separately or as part of the full `docker compose up`).

- [ ] **Step 5: Commit**

```bash
git add tests/e2e/simulation-environment/docker-compose.yml \
        tests/e2e/simulation-environment/config/logthing.toml \
        tests/e2e/simulation-environment/zeek-local-verifier/
git commit -m "test(e2e): verify zeek.local persists alongside zeek.s3 in the simulation environment"
```

---

### Task 9: Documentation

**Files:**
- Modify: `ZEEK_IMPLEMENTATION.md`

- [ ] **Step 1: Add a `[zeek.local]` subsection**

In `ZEEK_IMPLEMENTATION.md`, in section "6. Configuration", after the existing `### [zeek.s3] block (optional)` table and its example, add:

```markdown
### `[zeek.local]` block (optional)

Independent of `[zeek.s3]` — either, both, or neither may be configured. When
both are present, every record is persisted to both destinations (each with
its own buffer, flush policy, and backpressure — a slow/failing destination
cannot block the other).

| Key | Type | Default | Description |
|---|---|---|---|
| `directory` | String | — | Root directory Parquet files are written under (created if missing) |
| `prefix` | String | `"zeek"` | Key prefix under `directory` (same default as `zeek.s3`) |
| `flush_threshold_bytes` | usize | `104857600` (100 MiB) | Flush when estimated buffer bytes exceed this |
| `flush_interval_secs` | u64 | `900` | Flush every N seconds regardless of buffer size |
| `channel_capacity` | usize | `256` | `mpsc` channel capacity between listener and writer |
| `max_buffer_rows` | usize | `100000` | Soft buffer cap; hard cap is `max_buffer_rows * 4` |

Files land at `{directory}/{prefix}/<log_path>/year={Y}/month={MM}/day={DD}/{uuid}.parquet` — the same relative layout as the S3 key, so the same downstream tooling (DuckDB, Trino, etc.) works against either destination. Writes are atomic (same-directory temp file + rename), so a concurrent reader never observes a partial file.

**Example:**

```toml
[zeek.local]
directory             = "/var/log/logthing/zeek"
prefix                = "zeek"
flush_threshold_bytes = 104857600
flush_interval_secs   = 900
channel_capacity      = 256
max_buffer_rows       = 100000
```
```

- [ ] **Step 2: Add `local_sink.rs` to the file-listing table**

In section "9. Files", add a row after the `src/forwarding/zeek_s3.rs` row:

```markdown
| `src/forwarding/local_sink.rs` | `LocalDiskSink` — `UploadSink` implementation for local-disk persistence |
```

- [ ] **Step 3: Commit**

```bash
git add ZEEK_IMPLEMENTATION.md
git commit -m "docs(zeek): document [zeek.local] config and LocalDiskSink"
```

---

## Self-Review Notes (for the plan author, not a task)

- **Spec coverage:** Every decision-log row (1–9; row 10 was reverted per the reviewer) maps to a task: row 1→Tasks 1&3, row 2→Task 4, row 3→Task 5's `MultiZeekHandler`, row 4→Task 4 (independent flush-policy fields), row 5→Task 4 (`ZeekLocalConfig` mirrors `ZeekS3Config`), row 6→scope is Zeek-only throughout (explicitly out-of-scope section in the header), row 7→Task 2 (`build_key` reuse, atomic rename), row 8→Task 2 (traversal guard tests), row 9→Task 3 (`target` label). Testing plan (spec §5) → Tasks 7 (integration), 8 (e2e), plus unit tests embedded in Tasks 1, 2, 3, 4, 5. Docs (spec §6) → Task 9.
- **Type consistency check:** `ZeekS3Handler` (unchanged alias for `ParquetWriterHandle<ZeekSink>`) is used consistently as the return type of both `zeek_start` and `zeek_local_start` (Task 5). `UploadSink` trait methods (`upload`, `target_label`) are named identically everywhere they're consumed (Tasks 1, 2, 3). `ZeekLocalConfig` field names (`directory`, `prefix`, `flush_threshold_bytes`, `flush_interval_secs`, `channel_capacity`, `max_buffer_rows`) match between Task 4 (definition), Task 5 (`zeek_local_start` usage), Task 6 (`main.rs` usage), and Task 7 (integration test construction).
