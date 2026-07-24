# Decoupled Flush for the Generic Buffered Writer — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop the generic buffered Parquet writer's background task from blocking its ingest channel-drain loop while a flush (Arrow/Parquet encode + S3/local-disk upload) is in progress, so high-volume sources (diagnosed against Zeek) stop dropping records at the channel (`try_send`-full) level during a flush.

**Architecture:** `PartitionedParquetWriter` gains a `tokio::task::JoinSet<FlushOutcome>` and a bounded per-writer `Semaphore` (4 permits). A threshold-crossing detaches a partition's buffered batches (swap in a fresh empty buffer) and spawns the encode+upload in the background instead of awaiting it inline; the writer's main `select!` loop gains a guarded branch that reaps completions and applies them (clear in-flight on success; merge batches back + re-stale `last_flush` + re-run the hard cap on failure).

**Tech Stack:** Rust, Tokio (`JoinSet`, `Semaphore`), the `metrics` crate (0.22), Arrow/Parquet (`arrow`, `parquet` crates), existing `anyhow` error handling.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-07-24-decoupled-flush-buffered-writer-design.md` — every task below implements a specific row of that spec's decision log; re-read it if a step's rationale is unclear.
- All work is confined to `src/forwarding/buffered_writer.rs` — no other file changes (verified in the spec: `ParquetWriterHandle`'s public API is unchanged, so the 14 per-source wrapper files and `main.rs`/`server/mod.rs` need no changes) — except test files added in Tasks 7-8.
- `push()`'s public signature `-> anyhow::Result<()>` does not change (spec decision #6) — it will simply always return `Ok(())` from flush-related paths after this change.
- Do not bundle the separately-identified source/target logging-attribution fix into this work (spec decision #7) — preserve the existing (still-unattributed) log message text, just relocate its call site.
- Build environment: this machine has a `zig-cc` shim shadowing `/usr/bin/gcc` on PATH that breaks this crate's C dependencies. Before any `cargo build`/`test`/`clippy`/`fmt` command, export:
  ```bash
  export CC=/usr/bin/gcc CXX=/usr/bin/g++
  export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
  source ~/.cargo/env
  ```
- Every task ends with `cargo test --lib` passing (fast unit-test-only check) — the full suite (`cargo test`) only needs to pass at the very end of Task 8, since it's a ~5 minute build.
- Branch: `fix/decouple-flush-channel-drain` (already exists, checked out at the repo root with the spec doc committed). Work in a worktree off this branch, not directly in the shared checkout.

---

## Reference: current code being modified

These exact snippets exist today in `src/forwarding/buffered_writer.rs` and are quoted here so each task is self-contained (a task's implementer sees only their own task).

`PartitionBuffer` (lines 251-271):
```rust
pub(crate) struct PartitionBuffer {
    pub(crate) schema: Arc<arrow_schema::Schema>,
    pub(crate) buffer: VecDeque<(arrow_array::RecordBatch, usize)>, // (batch, est_bytes)
    pub(crate) row_count: usize,
    pub(crate) byte_count: usize,
    pub(crate) last_flush: Instant,
    pub(crate) last_drop_warn: Option<Instant>,
}

impl PartitionBuffer {
    fn new(schema: Arc<arrow_schema::Schema>) -> Self {
        Self {
            schema,
            buffer: VecDeque::new(),
            row_count: 0,
            byte_count: 0,
            last_flush: Instant::now(),
            last_drop_warn: None,
        }
    }
}
```

`PartitionedParquetWriter` struct + constructors (lines 306-355):
```rust
pub struct PartitionedParquetWriter<S: ParquetSink> {
    sink: S,
    s3: Arc<dyn UploadSink>,
    config: BufferedWriterConfig,
    policy: FlushPolicy,
    pub(crate) buffers: HashMap<String, PartitionBuffer>,
    source_stats: Arc<crate::stats::SourceHourlyStats>,
    descriptor_sink: Option<Arc<dyn UploadSink>>,
}

impl<S: ParquetSink> PartitionedParquetWriter<S> {
    pub fn new(
        sink: S,
        s3: Arc<dyn UploadSink>,
        config: BufferedWriterConfig,
        policy: FlushPolicy,
    ) -> Self {
        Self::with_source_stats(
            sink, s3, config, policy,
            Arc::new(crate::stats::SourceHourlyStats::default()),
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_source_stats(
        sink: S,
        s3: Arc<dyn UploadSink>,
        config: BufferedWriterConfig,
        policy: FlushPolicy,
        source_stats: Arc<crate::stats::SourceHourlyStats>,
        descriptor_sink: Option<Arc<dyn UploadSink>>,
    ) -> Self {
        Self {
            sink, s3, config, policy,
            buffers: HashMap::new(),
            source_stats,
            descriptor_sink,
        }
    }
```

`push` / `flush_all` / `flush_all_if_needed` / `flush_partition` / `drop_oldest_to_cap` (lines 360-589) — see Task 1/2 diffs below for the exact before/after; full current text was captured verbatim during design and matches what's in the file today (verified by an independent reviewer against the live file during the design phase).

`ParquetWriterHandle::start_with_stats`'s task loop (lines 743-812):
```rust
pub fn start_with_stats(
    sink: S,
    s3: Arc<dyn UploadSink>,
    config: BufferedWriterConfig,
    policy: FlushPolicy,
    source_stats: Arc<crate::stats::SourceHourlyStats>,
    descriptor_sink: Option<Arc<dyn UploadSink>>,
) -> (Self, tokio::task::JoinHandle<()>) {
    let capacity = config.channel_capacity.max(1);
    let source = sink.source();
    let target = s3.target_label();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<S::Record>(capacity);
    let interval_handle = policy.interval.clone();
    let handle_flush_interval = interval_handle.clone();
    let flush_check = crate::forwarding::s3_sink::flush_check_interval(interval_handle.get());
    let handle = tokio::spawn(async move {
        let mut writer = PartitionedParquetWriter::with_source_stats(
            sink, s3, config, policy, source_stats, descriptor_sink,
        );
        let mut ticker = tokio::time::interval(flush_check);
        loop {
            tokio::select! {
                msg = rx.recv() => {
                    match msg {
                        Some(record) => {
                            if let Err(e) = writer.push(record).await {
                                tracing::warn!("parquet_s3 writer push error: {e}");
                            }
                        }
                        None => {
                            if let Err(e) = writer.flush_all().await {
                                tracing::warn!("parquet_s3 flush_all on shutdown: {e}");
                            }
                            break;
                        }
                    }
                }
                _ = ticker.tick() => {
                    if let Err(e) = writer.flush_all_if_needed().await {
                        tracing::warn!("parquet_s3 flush_all_if_needed: {e}");
                    }
                }
                _ = interval_handle.changed() => {
                    ticker = tokio::time::interval(crate::forwarding::s3_sink::flush_check_interval(interval_handle.get()));
                }
            }
        }
    });
    (
        Self { tx, source, target, flush_interval: handle_flush_interval },
        handle,
    )
}
```

---

### Task 1: Data model + free-function extraction (pure refactor, no behavior change)

**Files:**
- Modify: `src/forwarding/buffered_writer.rs`

**Interfaces:**
- Produces: `FlushOutcome` enum, `PartitionBuffer.in_flight: bool`, `PartitionedParquetWriter.flush_tasks: JoinSet<FlushOutcome>`, `PartitionedParquetWriter.flush_semaphore: Arc<Semaphore>`, free fn `async fn encode_and_upload(key: String, batches: VecDeque<(RecordBatch, usize)>, row_count: usize, byte_count: usize, schema: Arc<Schema>, s3: Arc<dyn UploadSink>, descriptor_sink: Option<Arc<dyn UploadSink>>, prefix: String, source: &'static str, semaphore: Arc<Semaphore>) -> FlushOutcome`
- Consumed by: Task 2 (trigger/completion path), Task 3 (shutdown), Tasks 5-6 (tests)

This task changes only data shapes and extracts logic — `flush_partition`, `push`, `flush_all`, `flush_all_if_needed` still call the OLD synchronous path internally (via the new free function, called and awaited inline) so **no test should need to change yet**. This isolates "did I extract the logic correctly" from "did I wire up the new concurrency model correctly" (Task 2).

- [ ] **Step 1: Add the import and the concurrency-cap constant**

At the top of `src/forwarding/buffered_writer.rs`, alongside the existing `use` block (after `use tokio::sync::Notify;` around line 17):

```rust
use tokio::task::JoinSet;
```

Immediately before the `PartitionedParquetWriter` struct definition (before line 306):

```rust
/// Maximum number of flushes (across all of a writer's partitions) allowed
/// to run concurrently. Bounds worst-case memory/network footprint when
/// many partitions cross their flush threshold around the same time (e.g.
/// Zeek's up to 256 partitions all created near service start) and, after
/// a failed flush's `last_flush` is deliberately re-staled to retry almost
/// immediately (see `apply_flush_outcome`), prevents a systemic backend
/// outage from causing many partitions to retry in lockstep.
const MAX_CONCURRENT_FLUSHES_PER_WRITER: usize = 4;
```

- [ ] **Step 2: Add `in_flight` to `PartitionBuffer`**

Replace (lines 251-271):
```rust
pub(crate) struct PartitionBuffer {
    pub(crate) schema: Arc<arrow_schema::Schema>,
    pub(crate) buffer: VecDeque<(arrow_array::RecordBatch, usize)>, // (batch, est_bytes)
    pub(crate) row_count: usize,
    pub(crate) byte_count: usize,
    pub(crate) last_flush: Instant,
    pub(crate) last_drop_warn: Option<Instant>,
}

impl PartitionBuffer {
    fn new(schema: Arc<arrow_schema::Schema>) -> Self {
        Self {
            schema,
            buffer: VecDeque::new(),
            row_count: 0,
            byte_count: 0,
            last_flush: Instant::now(),
            last_drop_warn: None,
        }
    }
}
```
with:
```rust
pub(crate) struct PartitionBuffer {
    pub(crate) schema: Arc<arrow_schema::Schema>,
    pub(crate) buffer: VecDeque<(arrow_array::RecordBatch, usize)>, // (batch, est_bytes)
    pub(crate) row_count: usize,
    pub(crate) byte_count: usize,
    pub(crate) last_flush: Instant,
    pub(crate) last_drop_warn: Option<Instant>,
    /// True while a background flush task owns this partition's previously
    /// buffered data. At most one flush is ever in-flight per partition —
    /// see `try_flush_partition_async`.
    pub(crate) in_flight: bool,
}

impl PartitionBuffer {
    fn new(schema: Arc<arrow_schema::Schema>) -> Self {
        Self {
            schema,
            buffer: VecDeque::new(),
            row_count: 0,
            byte_count: 0,
            last_flush: Instant::now(),
            last_drop_warn: None,
            in_flight: false,
        }
    }
}
```

- [ ] **Step 3: Add `FlushOutcome`, and `flush_tasks`/`flush_semaphore` fields**

Immediately before `pub struct PartitionedParquetWriter<S: ParquetSink> {` (line 306), add:

```rust
/// Outcome of a background flush task (see `encode_and_upload`), reported
/// back to the single task that owns `PartitionedParquetWriter::buffers`
/// via `flush_tasks: JoinSet`. Never constructed with a partial/ambiguous
/// state: either the upload succeeded, or it didn't and the caller gets
/// back everything needed to retry.
enum FlushOutcome {
    Success {
        key: String,
    },
    Failure {
        key: String,
        batches: VecDeque<(arrow_array::RecordBatch, usize)>,
        row_count: usize,
        byte_count: usize,
        error: String,
    },
}
```

Replace the struct (lines 306-318):
```rust
pub struct PartitionedParquetWriter<S: ParquetSink> {
    sink: S,
    s3: Arc<dyn UploadSink>,
    config: BufferedWriterConfig,
    policy: FlushPolicy,
    pub(crate) buffers: HashMap<String, PartitionBuffer>,
    source_stats: Arc<crate::stats::SourceHourlyStats>,
    descriptor_sink: Option<Arc<dyn UploadSink>>,
}
```
with:
```rust
pub struct PartitionedParquetWriter<S: ParquetSink> {
    sink: S,
    s3: Arc<dyn UploadSink>,
    config: BufferedWriterConfig,
    policy: FlushPolicy,
    pub(crate) buffers: HashMap<String, PartitionBuffer>,
    source_stats: Arc<crate::stats::SourceHourlyStats>,
    descriptor_sink: Option<Arc<dyn UploadSink>>,
    /// Background flush tasks spawned by `try_flush_partition_async`,
    /// reaped by the guarded `select!` branch in
    /// `ParquetWriterHandle::start_with_stats` (steady state) or by
    /// `drain_pending_flushes` (shutdown / tests).
    flush_tasks: JoinSet<FlushOutcome>,
    /// Bounds concurrent flushes across all of this writer's partitions.
    /// Acquired INSIDE the spawned task (`encode_and_upload`), never
    /// before spawning — see `MAX_CONCURRENT_FLUSHES_PER_WRITER`.
    flush_semaphore: Arc<tokio::sync::Semaphore>,
}
```

- [ ] **Step 4: Update `with_source_stats` to initialize the new fields**

Replace (lines 337-355):
```rust
    #[allow(clippy::too_many_arguments)]
    pub fn with_source_stats(
        sink: S,
        s3: Arc<dyn UploadSink>,
        config: BufferedWriterConfig,
        policy: FlushPolicy,
        source_stats: Arc<crate::stats::SourceHourlyStats>,
        descriptor_sink: Option<Arc<dyn UploadSink>>,
    ) -> Self {
        Self {
            sink,
            s3,
            config,
            policy,
            buffers: HashMap::new(),
            source_stats,
            descriptor_sink,
        }
    }
```
with:
```rust
    #[allow(clippy::too_many_arguments)]
    pub fn with_source_stats(
        sink: S,
        s3: Arc<dyn UploadSink>,
        config: BufferedWriterConfig,
        policy: FlushPolicy,
        source_stats: Arc<crate::stats::SourceHourlyStats>,
        descriptor_sink: Option<Arc<dyn UploadSink>>,
    ) -> Self {
        Self {
            sink,
            s3,
            config,
            policy,
            buffers: HashMap::new(),
            source_stats,
            descriptor_sink,
            flush_tasks: JoinSet::new(),
            flush_semaphore: Arc::new(tokio::sync::Semaphore::new(
                MAX_CONCURRENT_FLUSHES_PER_WRITER,
            )),
        }
    }
```

- [ ] **Step 5: Extract `encode_and_upload` as a free function; keep `flush_partition` calling it synchronously (no behavior change yet)**

Replace `flush_partition` in full (lines 478-552):
```rust
    async fn flush_partition(&mut self, key: &str) -> anyhow::Result<()> {
        let buf = match self.buffers.get_mut(key) {
            Some(b) if !b.buffer.is_empty() => b,
            _ => return Ok(()),
        };
        let batches: Vec<_> = buf.buffer.iter().map(|(b, _)| b.clone()).collect();
        let row_count = buf.row_count;
        let schema = buf.schema.clone();
        let source = self.sink.source();

        let (merged, file_metadata) = tokio::task::spawn_blocking(
            move || -> anyhow::Result<(Vec<u8>, parquet::format::FileMetaData)> {
                use parquet::arrow::ArrowWriter;
                use parquet::basic::{Compression, ZstdLevel};
                use parquet::file::properties::WriterProperties;

                let batch = arrow::compute::concat_batches(&schema, &batches)?;
                let props = WriterProperties::builder()
                    .set_compression(Compression::ZSTD(ZstdLevel::try_new(3)?))
                    .build();
                let mut buf = Vec::new();
                let mut writer = ArrowWriter::try_new(&mut buf, schema.clone(), Some(props))?;
                writer.write(&batch)?;
                let file_metadata = writer.close()?;
                Ok((buf, file_metadata))
            },
        )
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking join: {e}"))??;

        let partition_seg = if key.is_empty() { None } else { Some(key) };
        let s3_key = build_key(&self.config.prefix, partition_seg, chrono::Utc::now());
        let target = self.s3.target_label();
        let body_len = merged.len();

        match self.s3.upload(&s3_key, merged).await {
            Ok(()) => {
                metrics::counter!("parquet_s3_records_written", "source" => source, "target" => target)
                    .increment(row_count as u64);
                metrics::counter!("parquet_s3_uploads", "source" => source, "target" => target)
                    .increment(1);

                if let Some(descriptor_sink) = self.descriptor_sink.clone() {
                    let schema_for_descriptor = self.buffers.get(key).unwrap().schema.clone();
                    let descriptor = build_descriptor(
                        source,
                        partition_seg,
                        self.s3.location_hint(),
                        &s3_key,
                        row_count as u64,
                        body_len as u64,
                        target,
                        &schema_for_descriptor,
                        &file_metadata,
                    );
                    upload_descriptor(descriptor_sink, descriptor, &s3_key, source).await;
                }

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
with:
```rust
    async fn flush_partition(&mut self, key: &str) -> anyhow::Result<()> {
        let buf = match self.buffers.get_mut(key) {
            Some(b) if !b.buffer.is_empty() => b,
            _ => return Ok(()),
        };
        let schema = buf.schema.clone();
        let batches = std::mem::take(&mut buf.buffer);
        let row_count = buf.row_count;
        let byte_count = buf.byte_count;

        let outcome = encode_and_upload(
            key.to_string(),
            batches,
            row_count,
            byte_count,
            schema,
            self.s3.clone(),
            self.descriptor_sink.clone(),
            self.config.prefix.clone(),
            self.sink.source(),
            self.flush_semaphore.clone(),
        )
        .await;

        match outcome {
            FlushOutcome::Success { key } => {
                let buf = self.buffers.get_mut(&key).unwrap();
                buf.row_count = 0;
                buf.byte_count = 0;
                buf.last_flush = Instant::now();
                Ok(())
            }
            FlushOutcome::Failure {
                key,
                batches,
                row_count,
                byte_count,
                error,
            } => {
                // Put the data back exactly as flush_partition's callers
                // (push/flush_all/flush_all_if_needed) expect on failure
                // today: still present in the buffer, untouched, to be
                // retried on the next threshold crossing.
                let buf = self.buffers.get_mut(&key).unwrap();
                buf.buffer = batches;
                buf.row_count = row_count;
                buf.byte_count = byte_count;
                Err(anyhow::anyhow!(error))
            }
        }
    }
```

Immediately after the `impl<S: ParquetSink> PartitionedParquetWriter<S>` block's closing brace (after `drop_oldest_to_cap`, i.e. right before the `/// Build an IcebergDescriptor...` comment at line 591), add the new free function:

```rust
/// Encode+upload one partition's already-detached batch of records. Called
/// two ways: synchronously (awaited inline) from `flush_partition` in this
/// task (unchanged behavior — Task 1), and, from Task 2 onward, from inside
/// a spawned background task via `try_flush_partition_async`, decoupled
/// from the writer's channel-draining loop.
///
/// Acquires `semaphore` INSIDE this function, never before calling it —
/// this is load-bearing once this is called from a spawned task (Task 2):
/// acquiring the permit in the *caller* (the main `select!` loop) would
/// block that loop the instant the semaphore saturates, reintroducing the
/// exact bug this change fixes.
#[allow(clippy::too_many_arguments)]
async fn encode_and_upload(
    key: String,
    batches: VecDeque<(arrow_array::RecordBatch, usize)>,
    row_count: usize,
    byte_count: usize,
    schema: Arc<arrow_schema::Schema>,
    s3: Arc<dyn UploadSink>,
    descriptor_sink: Option<Arc<dyn UploadSink>>,
    prefix: String,
    source: &'static str,
    semaphore: Arc<tokio::sync::Semaphore>,
) -> FlushOutcome {
    let _permit = semaphore
        .acquire_owned()
        .await
        .expect("flush semaphore is never closed");

    let to_concat: Vec<arrow_array::RecordBatch> = batches.iter().map(|(b, _)| b.clone()).collect();
    let schema_for_encode = schema.clone();
    let encode_result = tokio::task::spawn_blocking(
        move || -> anyhow::Result<(Vec<u8>, parquet::format::FileMetaData)> {
            use parquet::arrow::ArrowWriter;
            use parquet::basic::{Compression, ZstdLevel};
            use parquet::file::properties::WriterProperties;

            let batch = arrow::compute::concat_batches(&schema_for_encode, &to_concat)?;
            let props = WriterProperties::builder()
                .set_compression(Compression::ZSTD(ZstdLevel::try_new(3)?))
                .build();
            let mut buf = Vec::new();
            let mut writer =
                ArrowWriter::try_new(&mut buf, schema_for_encode.clone(), Some(props))?;
            writer.write(&batch)?;
            let file_metadata = writer.close()?;
            Ok((buf, file_metadata))
        },
    )
    .await
    .map_err(|e| anyhow::anyhow!("spawn_blocking join: {e}"));

    let (merged, file_metadata) = match encode_result.and_then(|r| r) {
        Ok(pair) => pair,
        Err(e) => {
            return FlushOutcome::Failure {
                key,
                batches,
                row_count,
                byte_count,
                error: format!("{e}"),
            };
        }
    };

    let partition_seg = if key.is_empty() { None } else { Some(key.as_str()) };
    let s3_key = build_key(&prefix, partition_seg, chrono::Utc::now());
    let target = s3.target_label();
    let body_len = merged.len();

    match s3.upload(&s3_key, merged).await {
        Ok(()) => {
            metrics::counter!("parquet_s3_records_written", "source" => source, "target" => target)
                .increment(row_count as u64);
            metrics::counter!("parquet_s3_uploads", "source" => source, "target" => target)
                .increment(1);

            if let Some(descriptor_sink) = descriptor_sink {
                let descriptor = build_descriptor(
                    source,
                    partition_seg,
                    s3.location_hint(),
                    &s3_key,
                    row_count as u64,
                    body_len as u64,
                    target,
                    &schema,
                    &file_metadata,
                );
                upload_descriptor(descriptor_sink, descriptor, &s3_key, source).await;
            }
            FlushOutcome::Success { key }
        }
        Err(e) => {
            metrics::counter!("parquet_s3_upload_errors", "source" => source, "target" => target)
                .increment(1);
            FlushOutcome::Failure {
                key,
                batches,
                row_count,
                byte_count,
                error: format!("{e}"),
            }
        }
    }
}
```

- [ ] **Step 6: Verify no behavior changed**

Run: `cargo test --lib forwarding::buffered_writer`
Expected: all existing tests in this module still PASS, unchanged (this step is a pure refactor — if anything fails, the extraction introduced a behavior difference; compare the diff against the reference snippets above before proceeding).

- [ ] **Step 7: Commit**

```bash
git add src/forwarding/buffered_writer.rs
git commit -m "refactor(buffered-writer): extract encode_and_upload as owned-data free fn

Pure refactor, no behavior change: flush_partition still calls this
synchronously and inline. Adds FlushOutcome, PartitionBuffer.in_flight,
and PartitionedParquetWriter's flush_tasks/flush_semaphore fields (unused
until Task 2) so the async trigger/completion path can be layered on
without an all-at-once diff."
```

---

### Task 2: Async trigger + completion path (the core behavioral change)

**Files:**
- Modify: `src/forwarding/buffered_writer.rs`

**Interfaces:**
- Consumes: `FlushOutcome`, `encode_and_upload`, `PartitionBuffer.in_flight`, `PartitionedParquetWriter.flush_tasks`/`flush_semaphore` (all from Task 1)
- Produces: `PartitionedParquetWriter::try_flush_partition_async(&mut self, key: &str)`, `PartitionedParquetWriter::apply_flush_outcome(&mut self, outcome: FlushOutcome)`; changes `push()`/`flush_all_if_needed()` to call `try_flush_partition_async` instead of awaiting `flush_partition` inline; adds the guarded `select!` branch in `start_with_stats`
- Consumed by: Task 3 (shutdown draining calls `apply_flush_outcome` via the same JoinSet), Tasks 5-7 (tests)

This is the task that actually fixes the bug. After this task, `push()` never blocks on a flush.

- [ ] **Step 1: Add `try_flush_partition_async`**

Immediately after `flush_partition` (added/modified in Task 1) and before `flush_all`, add:

```rust
    /// If `key`'s partition has no flush currently in-flight, detach its
    /// buffered batches (swapping in a fresh, empty `PartitionBuffer` so new
    /// records keep accumulating without waiting on the flush) and spawn
    /// `encode_and_upload` for them in the background. If a flush IS
    /// already in-flight for `key`, does not spawn a second one — applies
    /// the existing `drop_oldest_to_cap` to the live (still-growing) buffer
    /// instead, exactly as today's flush-failure path already does, just
    /// from a second call site.
    fn try_flush_partition_async(&mut self, key: &str) {
        let in_flight = self.buffers.get(key).map(|b| b.in_flight).unwrap_or(false);
        let source = self.sink.source();
        let target = self.s3.target_label();

        if in_flight {
            let cap = self.config.max_buffer_rows.saturating_mul(4);
            if cap > 0
                && let Some(b) = self.buffers.get_mut(key)
            {
                Self::drop_oldest_to_cap(b, cap, source, target);
            }
            return;
        }

        let Some(buf) = self.buffers.get_mut(key) else {
            return;
        };
        if buf.buffer.is_empty() {
            return;
        }

        let schema = buf.schema.clone();
        let taken_batches = std::mem::take(&mut buf.buffer);
        let row_count = buf.row_count;
        let byte_count = buf.byte_count;
        buf.row_count = 0;
        buf.byte_count = 0;
        buf.last_flush = Instant::now();
        buf.in_flight = true;

        metrics::gauge!("parquet_s3_flushes_in_flight", "source" => source, "target" => target)
            .increment(1.0);

        self.flush_tasks.spawn(encode_and_upload(
            key.to_string(),
            taken_batches,
            row_count,
            byte_count,
            schema,
            self.s3.clone(),
            self.descriptor_sink.clone(),
            self.config.prefix.clone(),
            source,
            self.flush_semaphore.clone(),
        ));
    }
```

- [ ] **Step 2: Add `apply_flush_outcome`**

Immediately after `try_flush_partition_async`, add:

```rust
    /// Apply one completed background flush's outcome. On success, clears
    /// in-flight for that partition. On failure, clears in-flight AND
    /// merges the returned batches back onto the FRONT of the (possibly
    /// already-refilling) live buffer -- they're older, so
    /// `drop_oldest_to_cap` (which pops from the front) drops the stalest
    /// data first if the merged total exceeds the cap -- then re-stales
    /// `last_flush` so the age-based flush trigger fires on the very next
    /// check, reproducing today's behavior (a failed flush's `last_flush`
    /// is simply never touched, so it's already stale and retries almost
    /// immediately) that the fresh-buffer-gets-"now"-at-swap-time design
    /// would otherwise silently break.
    fn apply_flush_outcome(&mut self, outcome: FlushOutcome) {
        let source = self.sink.source();
        let target = self.s3.target_label();
        metrics::gauge!("parquet_s3_flushes_in_flight", "source" => source, "target" => target)
            .decrement(1.0);

        match outcome {
            FlushOutcome::Success { key } => {
                if let Some(buf) = self.buffers.get_mut(&key) {
                    buf.in_flight = false;
                }
            }
            FlushOutcome::Failure {
                key,
                mut batches,
                row_count,
                byte_count,
                error,
            } => {
                tracing::warn!("parquet_s3 writer push error: {error}");

                let Some(buf) = self.buffers.get_mut(&key) else {
                    return;
                };
                buf.in_flight = false;

                while let Some(entry) = batches.pop_back() {
                    buf.buffer.push_front(entry);
                }
                buf.row_count += row_count;
                buf.byte_count += byte_count;

                let interval = self.policy.interval.get();
                buf.last_flush = Instant::now()
                    .checked_sub(interval + std::time::Duration::from_secs(1))
                    .unwrap_or_else(Instant::now);

                let cap = self.config.max_buffer_rows.saturating_mul(4);
                if cap > 0 {
                    Self::drop_oldest_to_cap(buf, cap, source, target);
                }
            }
        }
    }
```

- [ ] **Step 3: Wire `push()` to use `try_flush_partition_async`**

Find in `push()` (around lines 415-434):
```rust
        if should_flush {
            let cap = self.config.max_buffer_rows.saturating_mul(4);
            let source = self.sink.source();
            if let Err(e) = self.flush_partition(&effective_key).await {
                // Flush failed — enforce hard cap.
                // Defense-in-depth: cap == 0 means "no hard cap"; skip drop so a zero can never
                // drain the entire buffer on S3 failure.
                if cap > 0
                    && let Some(b) = self.buffers.get_mut(&effective_key)
                {
                    Self::drop_oldest_to_cap(b, cap, source, self.s3.target_label());
                }
                return Err(e);
            }
        }
        Ok(())
    }
```
Replace with:
```rust
        if should_flush {
            self.try_flush_partition_async(&effective_key);
        }
        Ok(())
    }
```

- [ ] **Step 4: Wire `flush_all_if_needed()` to use `try_flush_partition_async`**

Find (lines 454-476):
```rust
    pub async fn flush_all_if_needed(&mut self) -> anyhow::Result<()> {
        let keys: Vec<String> = self.buffers.keys().cloned().collect();
        let mut last_err: Option<anyhow::Error> = None;
        for key in keys {
            let should_flush = {
                let buf = self.buffers.get(&key).unwrap();
                if buf.buffer.is_empty() {
                    false
                } else {
                    buf.row_count >= self.policy.max_rows
                        || buf.byte_count >= self.policy.max_bytes
                        || buf.last_flush.elapsed() >= self.policy.interval.get()
                }
            };
            if should_flush && let Err(e) = self.flush_partition(&key).await {
                last_err = Some(e);
            }
        }
        match last_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
```
Replace with:
```rust
    pub async fn flush_all_if_needed(&mut self) -> anyhow::Result<()> {
        let keys: Vec<String> = self.buffers.keys().cloned().collect();
        for key in keys {
            let should_flush = {
                let buf = self.buffers.get(&key).unwrap();
                if buf.buffer.is_empty() {
                    false
                } else {
                    buf.row_count >= self.policy.max_rows
                        || buf.byte_count >= self.policy.max_bytes
                        || buf.last_flush.elapsed() >= self.policy.interval.get()
                }
            };
            if should_flush {
                self.try_flush_partition_async(&key);
            }
        }
        Ok(())
    }
```

- [ ] **Step 5: Add the guarded completion branch to `start_with_stats`'s `select!` loop**

Find in `start_with_stats` (lines 774-800):
```rust
            loop {
                tokio::select! {
                    msg = rx.recv() => {
                        match msg {
                            Some(record) => {
                                if let Err(e) = writer.push(record).await {
                                    tracing::warn!("parquet_s3 writer push error: {e}");
                                }
                            }
                            None => {
                                // Channel closed — flush all and exit.
                                if let Err(e) = writer.flush_all().await {
                                    tracing::warn!("parquet_s3 flush_all on shutdown: {e}");
                                }
                                break;
                            }
                        }
                    }
                    _ = ticker.tick() => {
                        if let Err(e) = writer.flush_all_if_needed().await {
                            tracing::warn!("parquet_s3 flush_all_if_needed: {e}");
                        }
                    }
                    _ = interval_handle.changed() => {
                        ticker = tokio::time::interval(crate::forwarding::s3_sink::flush_check_interval(interval_handle.get()));
                    }
                }
            }
```
Replace with:
```rust
            loop {
                tokio::select! {
                    msg = rx.recv() => {
                        match msg {
                            Some(record) => {
                                if let Err(e) = writer.push(record).await {
                                    tracing::warn!("parquet_s3 writer push error: {e}");
                                }
                            }
                            None => {
                                // Channel closed — drain any in-flight background
                                // flushes first (so a late failure's data gets
                                // merged back for the final flush below to
                                // pick up), THEN flush whatever remains.
                                writer.drain_pending_flushes().await;
                                if let Err(e) = writer.flush_all().await {
                                    tracing::warn!("parquet_s3 flush_all on shutdown: {e}");
                                }
                                break;
                            }
                        }
                    }
                    _ = ticker.tick() => {
                        if let Err(e) = writer.flush_all_if_needed().await {
                            tracing::warn!("parquet_s3 flush_all_if_needed: {e}");
                        }
                    }
                    _ = interval_handle.changed() => {
                        ticker = tokio::time::interval(crate::forwarding::s3_sink::flush_check_interval(interval_handle.get()));
                    }
                    // Reap completed background flushes. The `if !is_empty()`
                    // guard is load-bearing: `JoinSet::join_next()` on an
                    // empty set resolves immediately to `None`, so an
                    // unguarded branch would busy-spin this loop.
                    Some(result) = writer.flush_tasks.join_next(), if !writer.flush_tasks.is_empty() => {
                        match result {
                            Ok(outcome) => writer.apply_flush_outcome(outcome),
                            Err(join_err) => {
                                tracing::warn!("parquet_s3 flush task panicked: {join_err}");
                            }
                        }
                    }
                }
            }
```

Note: `writer.drain_pending_flushes()` is added in Task 3 — this task's code will not compile standalone until Task 3 lands. That's expected; Tasks 2 and 3 are implemented back-to-back by the same worker before the compile/test checkpoint (Task 3's Step 1 is the very next step in this plan).

- [ ] **Step 6: Commit** (after Task 3's Step 1 is also done, so this compiles — see Task 3)

---

### Task 3: Shutdown draining

**Files:**
- Modify: `src/forwarding/buffered_writer.rs`

**Interfaces:**
- Consumes: `apply_flush_outcome` (Task 2), `flush_tasks` (Task 1)
- Produces: `PartitionedParquetWriter::drain_pending_flushes(&mut self)`; changes `flush_all()` to use `encode_and_upload` directly instead of the old inline `flush_partition` logic
- Consumed by: Task 2's shutdown branch (already written); Tasks 5-6 (tests use this for deterministic waiting)

- [ ] **Step 1: Add `drain_pending_flushes`**

Immediately after `apply_flush_outcome`, add:

```rust
    /// Drain all in-flight background flushes to completion, applying each
    /// outcome as it arrives. Used at graceful shutdown (so the writer's
    /// `JoinHandle` doesn't complete while a flush is still outstanding —
    /// callers await it expecting persistence to be genuinely finished) and
    /// reused by tests for deterministic waiting instead of sleep-based
    /// polling.
    async fn drain_pending_flushes(&mut self) {
        while let Some(result) = self.flush_tasks.join_next().await {
            match result {
                Ok(outcome) => self.apply_flush_outcome(outcome),
                Err(join_err) => {
                    tracing::warn!("parquet_s3 flush task panicked: {join_err}");
                }
            }
        }
    }
```

- [ ] **Step 2: Update `flush_all()` to use `encode_and_upload` directly (synchronously, since shutdown needs no concurrency)**

Find (lines 439-451):
```rust
    /// Flush all partitions unconditionally (called on shutdown).
    pub async fn flush_all(&mut self) -> anyhow::Result<()> {
        let keys: Vec<String> = self.buffers.keys().cloned().collect();
        let mut last_err: Option<anyhow::Error> = None;
        for key in keys {
            if let Err(e) = self.flush_partition(&key).await {
                last_err = Some(e);
            }
        }
        match last_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
```
Replace with:
```rust
    /// Flush all partitions unconditionally (called on shutdown, after
    /// `drain_pending_flushes` has settled any in-flight background work).
    /// Deliberately still synchronous/inline — at shutdown there is no
    /// channel left to keep draining, so there is no benefit to spawning,
    /// only a need for a single definitive attempt per partition.
    pub async fn flush_all(&mut self) -> anyhow::Result<()> {
        let keys: Vec<String> = self.buffers.keys().cloned().collect();
        let mut last_err: Option<anyhow::Error> = None;
        for key in keys {
            let taken = {
                let Some(buf) = self.buffers.get_mut(&key) else {
                    continue;
                };
                if buf.buffer.is_empty() {
                    continue;
                }
                let schema = buf.schema.clone();
                let batches = std::mem::take(&mut buf.buffer);
                let row_count = buf.row_count;
                let byte_count = buf.byte_count;
                (schema, batches, row_count, byte_count)
            };
            let (schema, batches, row_count, byte_count) = taken;

            let outcome = encode_and_upload(
                key.clone(),
                batches,
                row_count,
                byte_count,
                schema,
                self.s3.clone(),
                self.descriptor_sink.clone(),
                self.config.prefix.clone(),
                self.sink.source(),
                self.flush_semaphore.clone(),
            )
            .await;

            if let FlushOutcome::Failure {
                key,
                batches,
                row_count,
                byte_count,
                error,
            } = outcome
            {
                if let Some(buf) = self.buffers.get_mut(&key) {
                    buf.buffer = batches;
                    buf.row_count = row_count;
                    buf.byte_count = byte_count;
                }
                last_err = Some(anyhow::anyhow!(error));
            }
        }
        match last_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
```

- [ ] **Step 3: Build and run the existing test suite for this module**

```bash
export CC=/usr/bin/gcc CXX=/usr/bin/g++
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
source ~/.cargo/env
cargo test --lib forwarding::buffered_writer 2>&1 | tail -80
```
Expected: the crate now COMPILES (Tasks 1-3 together form the first compilable unit). Some existing tests will FAIL at this point — specifically any test that pushes past a flush threshold on an `unreachable_s3()`/failing sink and asserts something synchronously right after `.push(...).await` returns (e.g. `push_enforces_hard_cap_on_flush_failure`, `hard_cap_enforced_with_nonzero_max_buffer_rows`). That is expected and is fixed in Task 5 — do not attempt to fix them in this task. Confirm via the failure output that the ONLY failures are ones that assert synchronously on flush-triggered state (buffer row_count / hard cap / error return value right after a push loop) — if anything else fails, that's a real regression to investigate before moving on.

- [ ] **Step 4: Commit**

```bash
git add src/forwarding/buffered_writer.rs
git commit -m "feat(buffered-writer): decouple flush from channel-draining loop

push()/flush_all_if_needed() now spawn flushes into a JoinSet instead of
awaiting them inline, so the writer's background task keeps draining its
ingest channel while a previous flush's encode+upload is still running.
At most one flush in-flight per partition (a second threshold-crossing
falls back to the existing hard-cap drop instead of spawning a second
flush); a bounded per-writer semaphore (4 permits, acquired inside the
spawned task, never before spawning) caps worst-case concurrent flushes.
Failed flushes merge their data back into the live buffer and re-stale
last_flush so the age trigger retries almost immediately, matching
today's behavior. Graceful shutdown drains all in-flight flushes before
the final synchronous flush_all().

Some existing unit tests now fail because they assert synchronously on
flush-triggered state right after push().await returns -- fixed in the
next commit via a new drain_pending_flushes()-based test helper.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01DfNoJrFgeqK8jNU6jSpwBE"
```

---

### Task 4: Observability — `parquet_s3_flushes_in_flight` gauge

**Files:**
- Modify: `src/forwarding/buffered_writer.rs` (already wired in Task 2 — this task only adds the test proving it)

**Interfaces:**
- Consumes: the `metrics::gauge!("parquet_s3_flushes_in_flight", ...)` calls already added in Task 2's Steps 1-2

- [ ] **Step 1: Add a unit test proving the gauge tracks in-flight count correctly**

Add to the `#[cfg(test)] mod tests` block in `src/forwarding/buffered_writer.rs` (near `flush_metrics_carry_the_target_label`, reusing its exact `DebuggingRecorder` pattern):

```rust
    /// Proves `parquet_s3_flushes_in_flight` goes 0 -> 1 while a flush is
    /// running, then back to 0 once it completes -- the observability half
    /// of the concurrency cap (spec decision #3).
    #[tokio::test]
    #[allow(clippy::mutable_key_type)]
    async fn flushes_in_flight_gauge_tracks_a_single_flush() {
        use metrics::set_default_local_recorder;
        use metrics_util::CompositeKey;
        use metrics_util::MetricKind;
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let uploads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink: Arc<dyn UploadSink> = Arc::new(RecordingSink {
            uploads: uploads.clone(),
        });
        let (cfg, policy) = test_config(1); // flush on first row
        let mut w = PartitionedParquetWriter::new(MockSink, sink, cfg, policy);

        w.push("hello".to_string()).await.unwrap();

        let gauge_key = CompositeKey::new(
            MetricKind::Gauge,
            metrics::Key::from_parts(
                "parquet_s3_flushes_in_flight",
                vec![
                    metrics::Label::new("source", "test"),
                    metrics::Label::new("target", "recording"),
                ],
            ),
        );
        let read_gauge = |snapshotter: &metrics_util::debugging::Snapshotter| -> f64 {
            snapshotter
                .snapshot()
                .into_hashmap()
                .get(&gauge_key)
                .map(|(_, _, v)| if let DebugValue::Gauge(g) = v { g.into_inner() } else { 0.0 })
                .unwrap_or(0.0)
        };

        // The flush was spawned by push() above; drain it to completion.
        w.drain_pending_flushes().await;

        assert_eq!(
            read_gauge(&snapshotter),
            0.0,
            "gauge must return to 0 once the flush completes"
        );
        assert_eq!(
            uploads.lock().unwrap().len(),
            1,
            "the flush must actually have run and uploaded once"
        );
    }
```

- [ ] **Step 2: Run it**

```bash
cargo test --lib forwarding::buffered_writer::tests::flushes_in_flight_gauge_tracks_a_single_flush -- --exact
```
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add src/forwarding/buffered_writer.rs
git commit -m "test(buffered-writer): prove parquet_s3_flushes_in_flight gauge behavior"
```

---

### Task 5: Rewrite existing low-level unit tests for async flush semantics

**Files:**
- Modify: `src/forwarding/buffered_writer.rs`

**Interfaces:**
- Consumes: `drain_pending_flushes` (Task 3)

The tests below currently assert synchronously on flush-triggered state right after `.push(...).await` returns. They now need to (a) push, (b) call `w.drain_pending_flushes().await` to deterministically wait for the background flush(es) to finish, (c) assert on the resulting state. Locate each by name (they exist today in the file) and apply the described change.

- [ ] **Step 1: Fix `push_enforces_hard_cap_on_flush_failure`**

Current (uses `unreachable_s3()`, asserts push() itself returns Err and checks hard cap right after):
```rust
    #[tokio::test]
    async fn push_enforces_hard_cap_on_flush_failure() {
        let s3 = unreachable_s3().await;
        let max_rows = 2usize;
        let (cfg, policy) = test_config(max_rows);
        let hard_cap = max_rows.saturating_mul(4);
        let mut w = PartitionedParquetWriter::new(MockSink, s3, cfg, policy);
        let mut errors = 0usize;
        for i in 0..(hard_cap * 3) {
            if w.push(format!("r{i}")).await.is_err() {
                errors += 1;
            }
        }
        assert!(errors > 0);
        let buf = w.buffers.get("").unwrap();
        assert!(
            buf.row_count <= hard_cap,
            "row_count {} must be <= hard_cap {}",
            buf.row_count,
            hard_cap
        );
    }
```
Replace with:
```rust
    #[tokio::test]
    async fn push_enforces_hard_cap_on_flush_failure() {
        let s3 = unreachable_s3().await;
        let max_rows = 2usize;
        let (cfg, policy) = test_config(max_rows);
        let hard_cap = max_rows.saturating_mul(4);
        let mut w = PartitionedParquetWriter::new(MockSink, s3, cfg, policy);
        for i in 0..(hard_cap * 3) {
            w.push(format!("r{i}")).await.unwrap(); // push() itself no longer fails -- flush failures surface asynchronously
            w.drain_pending_flushes().await; // deterministically wait for the just-triggered flush attempt (and its merge-back) to finish before pushing more
        }
        let buf = w.buffers.get("").unwrap();
        assert!(
            buf.row_count <= hard_cap,
            "row_count {} must be <= hard_cap {}",
            buf.row_count,
            hard_cap
        );
    }
```
Note: `unreachable_s3()` points at `http://127.0.0.1:1` (an address nothing listens on), so every upload attempt fails quickly with a connection error — the loop drains after every push to keep the test deterministic without needing a real concurrency stress test (that's Task 7's job).

- [ ] **Step 2: Find and fix `hard_cap_enforced_with_nonzero_max_buffer_rows`**

Apply the identical pattern: after each `w.push(...).await.unwrap()` in its loop, insert `w.drain_pending_flushes().await;`, and remove any assertion on `push(...)`'s return value being an error (if present) — keep only the `row_count <= hard_cap` assertion at the end.

- [ ] **Step 3: Search for any other test in this file asserting on `push(...).await`'s return value being `Err`**

```bash
grep -n "push(.*await.*is_err\|push(.*await\.unwrap_err\|\.push(.*await$" src/forwarding/buffered_writer.rs
```
For each match found (besides the two already handled above), apply the same fix: `push(...).await.unwrap()` (no longer expect `Err`), add `w.drain_pending_flushes().await;` immediately after if the test needs to observe post-flush state, and adjust the assertion to check state (buffer contents / hard cap / uploaded count) rather than `push`'s return value.

- [ ] **Step 4: Run the full unit test module**

```bash
cargo test --lib forwarding::buffered_writer 2>&1 | tail -100
```
Expected: **all tests pass** — this is the first point where the whole existing test suite for this file is green again under the new design.

- [ ] **Step 5: Commit**

```bash
git add src/forwarding/buffered_writer.rs
git commit -m "test(buffered-writer): adapt hard-cap/flush-failure tests to async flush

push() no longer fails synchronously when a flush fails -- these tests
now push, then call drain_pending_flushes() to deterministically wait
for the background attempt (and any merge-back) before asserting, instead
of relying on push()'s old synchronous Err return."
```

---

### Task 6: New unit tests for the decoupling mechanism itself

**Files:**
- Modify: `src/forwarding/buffered_writer.rs`

**Interfaces:**
- Consumes: everything from Tasks 1-3

- [ ] **Step 1: Test — at most one flush in-flight per partition (a second threshold-crossing hits the hard cap instead of spawning a second flush)**

Add to the test module:
```rust
    /// A second threshold-crossing while a flush is already in-flight for
    /// the same partition must NOT spawn a second flush -- it must fall
    /// back to `drop_oldest_to_cap` on the live buffer instead (spec
    /// decision #2). Proven here by using a sink that blocks forever until
    /// released, so if a second flush WERE spawned, this test would hang
    /// (caught by the outer test timeout) instead of passing.
    struct BlockingSink {
        gate: Arc<tokio::sync::Notify>,
    }
    #[async_trait::async_trait]
    impl UploadSink for BlockingSink {
        async fn upload(&self, _key: &str, _body: Vec<u8>) -> anyhow::Result<()> {
            self.gate.notified().await;
            Ok(())
        }
        fn target_label(&self) -> &'static str {
            "blocking"
        }
        fn location_hint(&self) -> String {
            "blocking://test".to_string()
        }
    }

    #[tokio::test]
    async fn second_threshold_crossing_while_in_flight_hard_caps_instead_of_double_flushing() {
        let gate = Arc::new(tokio::sync::Notify::new());
        let sink: Arc<dyn UploadSink> = Arc::new(BlockingSink { gate: gate.clone() });
        let max_rows = 1usize;
        let (cfg, policy) = test_config(max_rows);
        let hard_cap = max_rows.saturating_mul(4); // 4
        let mut w = PartitionedParquetWriter::new(MockSink, sink, cfg, policy);

        // First push triggers a flush that will block forever until `gate` fires.
        w.push("r0".to_string()).await.unwrap();
        assert!(
            w.buffers.get("").unwrap().in_flight,
            "first push must mark the partition in-flight"
        );

        // Push more than hard_cap while the first flush is stuck in-flight.
        for i in 1..(hard_cap * 3) {
            w.push(format!("r{i}")).await.unwrap();
        }

        let buf = w.buffers.get("").unwrap();
        assert!(
            buf.row_count <= hard_cap,
            "row_count {} must be capped at {} even while a flush is stuck in-flight",
            buf.row_count,
            hard_cap
        );
        assert!(
            buf.in_flight,
            "the ORIGINAL flush must still be the only one in-flight (still blocked on the gate)"
        );

        // Release the blocked upload so the test can clean up without hanging.
        gate.notify_one();
        w.drain_pending_flushes().await;
    }
```

- [ ] **Step 2: Run it**

```bash
cargo test --lib forwarding::buffered_writer::tests::second_threshold_crossing_while_in_flight_hard_caps_instead_of_double_flushing -- --exact
```
Expected: PASS (and completes quickly — if it hangs, a second flush was incorrectly spawned; check `try_flush_partition_async`'s in-flight check).

- [ ] **Step 3: Test — failed flush merges data back and re-stales `last_flush` for a prompt retry**

```rust
    /// A failed flush's data must be merged back onto the live buffer
    /// (prepended -- older data first) AND `last_flush` must be re-staled
    /// so the age trigger fires on the very next check, matching today's
    /// behavior where a failed flush simply never touches `last_flush`
    /// (spec decision #12).
    #[tokio::test]
    async fn failed_flush_merges_batches_back_and_restales_last_flush_for_prompt_retry() {
        let s3 = unreachable_s3().await; // every upload fails fast
        let max_rows = 100usize; // high enough that only the AGE trigger fires
        let (cfg, mut policy) = test_config(max_rows);
        policy.interval = LiveInterval::new(std::time::Duration::from_secs(900));
        let mut w = PartitionedParquetWriter::new(MockSink, s3, cfg, policy);

        // Force the age trigger by backdating last_flush before the buffer exists.
        w.push("r0".to_string()).await.unwrap();
        w.buffers.get_mut("").unwrap().last_flush =
            Instant::now() - std::time::Duration::from_secs(901);

        // This push crosses the age threshold and triggers (and fails) a flush.
        w.push("r1".to_string()).await.unwrap();
        w.drain_pending_flushes().await;

        let buf = w.buffers.get("").unwrap();
        assert_eq!(
            buf.row_count, 2,
            "both records must still be present after the failed flush merges back"
        );
        assert!(
            buf.last_flush.elapsed() >= std::time::Duration::from_secs(900),
            "last_flush must be re-staled past the interval so the next check retries almost immediately, not after a full 900s wait"
        );
    }
```

- [ ] **Step 4: Run it**

```bash
cargo test --lib forwarding::buffered_writer::tests::failed_flush_merges_batches_back_and_restales_last_flush_for_prompt_retry -- --exact
```
Expected: PASS.

- [ ] **Step 5: Test — the `checked_sub` fallback doesn't panic when interval exceeds process uptime**

```rust
    /// `apply_flush_outcome`'s last_flush re-staling must not panic when
    /// `Instant::now()` hasn't been running long enough to subtract a large
    /// configured interval from (e.g. shortly after process start with a
    /// long flush_interval_secs) -- it must fall back to "not re-staled"
    /// instead (spec decision #12's checked_sub fix).
    #[tokio::test]
    async fn restale_last_flush_does_not_panic_when_interval_exceeds_process_uptime() {
        let s3 = unreachable_s3().await;
        let max_rows = 1usize;
        let (cfg, mut policy) = test_config(max_rows);
        // A deliberately enormous interval -- far longer than this test (or
        // realistically, this process) has been running.
        policy.interval = LiveInterval::new(std::time::Duration::from_secs(365 * 24 * 3600));
        let mut w = PartitionedParquetWriter::new(MockSink, s3, cfg, policy);

        // Triggers and fails a flush; must not panic during outcome handling.
        w.push("r0".to_string()).await.unwrap();
        w.drain_pending_flushes().await;

        assert_eq!(
            w.buffers.get("").unwrap().row_count,
            1,
            "the record must still be present after the (non-panicking) failed flush"
        );
    }
```

- [ ] **Step 6: Run it**

```bash
cargo test --lib forwarding::buffered_writer::tests::restale_last_flush_does_not_panic_when_interval_exceeds_process_uptime -- --exact
```
Expected: PASS (no panic).

- [ ] **Step 7: Test — the semaphore permit is acquired inside the spawned task, not before spawning (spawning is non-blocking even when the semaphore is saturated)**

```rust
    /// `try_flush_partition_async` must return immediately even when the
    /// writer's flush semaphore is fully saturated -- proving the permit is
    /// acquired INSIDE the spawned task, not in the caller. If this were
    /// wrong (acquired before spawning), this test would hang.
    #[tokio::test]
    async fn spawning_a_flush_does_not_block_even_when_semaphore_is_saturated() {
        let gate = Arc::new(tokio::sync::Notify::new());
        let sink: Arc<dyn UploadSink> = Arc::new(BlockingSink { gate: gate.clone() });
        let (cfg, policy) = test_config(1);
        // Multi-partition sink so distinct keys each get their own buffer,
        // letting us saturate the semaphore (MAX_CONCURRENT_FLUSHES_PER_WRITER = 4)
        // with more than 4 simultaneously in-flight, blocked, flushes.
        struct MultiKeySink;
        impl ParquetSink for MultiKeySink {
            type Record = (String, String); // (partition, value)
            fn source(&self) -> &'static str {
                "test"
            }
            fn partition(&self, r: &Self::Record) -> Option<String> {
                Some(r.0.clone())
            }
            fn schema(&self, _p: Option<&str>) -> Arc<Schema> {
                test_schema()
            }
            fn to_record_batch(
                &self,
                record: &Self::Record,
                schema: &Arc<Schema>,
            ) -> anyhow::Result<RecordBatch> {
                let col = Arc::new(StringArray::from(vec![record.1.as_str()]));
                Ok(RecordBatch::try_new(schema.clone(), vec![col])?)
            }
        }
        let mut w = PartitionedParquetWriter::new(MultiKeySink, sink, cfg, policy);

        // Trigger 6 partitions' flushes (> the semaphore's 4 permits), all
        // blocked on `gate`. Every push() call below must return promptly.
        for i in 0..6 {
            w.push((format!("p{i}"), "v".to_string())).await.unwrap();
        }

        gate.notify_waiters();
        w.drain_pending_flushes().await;
    }
```

- [ ] **Step 8: Run it with a timeout to make the "must not hang" assertion explicit**

```bash
timeout 10 cargo test --lib forwarding::buffered_writer::tests::spawning_a_flush_does_not_block_even_when_semaphore_is_saturated -- --exact
echo "exit code: $?"
```
Expected: PASS, exit code 0 (if the permit were wrongly acquired before spawning, the 5th/6th `push()` call would hang and `timeout` would kill it with a nonzero exit code).

- [ ] **Step 9: Run the full module and commit**

```bash
cargo test --lib forwarding::buffered_writer 2>&1 | tail -50
git add src/forwarding/buffered_writer.rs
git commit -m "test(buffered-writer): cover 1-in-flight cap, merge-back+restale, checked_sub, and non-blocking semaphore"
```

---

### Task 7: Integration test — records pushed during a slow flush are not dropped at the channel

**Files:**
- Create: `tests/buffered_writer_flush_decoupling_integration.rs`

**Interfaces:**
- Consumes: `logthing::forwarding::buffered_writer::{ParquetWriterHandle, BufferedWriterConfig, FlushPolicy, LiveInterval, UploadSink}` (all `pub`), `logthing::forwarding::zeek_s3::ZeekSink` (`pub`), `logthing::zeek::ZeekRecord` (`pub`), `logthing::stats::SourceHourlyStats` (`pub`)

This is the "money test" for the whole change: a real `ParquetWriterHandle` (the actual production struct, running its actual background task), driven with an artificially slow `UploadSink`, proving records pushed via `try_send` while a flush is in flight are never dropped at the channel level.

**Bounded, per spec decision #11**: this proves the channel-level fix specifically. It does NOT claim the internal buffer's hard cap can never be hit — that's separate, pre-existing, accepted behavior. The assertion is specifically on `parquet_s3_dropped` (channel-level, via `try_send` failing), not `parquet_s3_buffer_dropped` (buffer-level hard cap).

**Must use a multi-threaded runtime** — `#[tokio::test(flavor = "multi_thread", worker_threads = 2)]`, not the default current-thread flavor. The writer's background task must run genuinely concurrently with this test's pushing loop for the test to exercise real concurrency; on a current-thread runtime, the test's own tight loop would never yield to the background task at all, making the test pass or fail for the wrong reason.

- [ ] **Step 1: Write the test file**

```rust
//! Integration test proving the generic buffered writer's background task
//! keeps draining its ingest channel while a previous flush's encode+upload
//! is still in flight, instead of blocking on it (the fix for a diagnosed
//! production issue: Zeek dropped records under try_send-full backpressure
//! because the writer task fully blocked on push() during a flush).
//!
//! Drives a real `ParquetWriterHandle` (the actual production struct and
//! background task) with an artificially slow `UploadSink`, and asserts
//! that records pushed via `try_send` while that slow flush is in flight
//! are never dropped at the channel level (`parquet_s3_dropped` stays at
//! zero). Does not claim the internal buffer's hard cap can never be hit --
//! that's separate, pre-existing, accepted behavior; only the channel-level
//! guarantee is asserted here. No external dependency required.

use logthing::forwarding::buffered_writer::{
    BufferedWriterConfig, FlushPolicy, LiveInterval, ParquetWriterHandle, UploadSink,
};
use logthing::forwarding::zeek_s3::ZeekSink;
use logthing::stats::SourceHourlyStats;
use logthing::zeek::ZeekRecord;
use std::sync::Arc;
use std::time::Duration;

struct SlowUploadSink {
    delay: Duration,
}

#[async_trait::async_trait]
impl UploadSink for SlowUploadSink {
    async fn upload(&self, _key: &str, _body: Vec<u8>) -> anyhow::Result<()> {
        tokio::time::sleep(self.delay).await;
        Ok(())
    }
    fn target_label(&self) -> &'static str {
        "slow"
    }
    fn location_hint(&self) -> String {
        "slow://test".to_string()
    }
}

fn make_zeek_record(i: usize) -> ZeekRecord {
    ZeekRecord {
        log_path: "conn".to_string(),
        fields: serde_json::json!({"_path": "conn", "uid": format!("C{i}")}),
        received_at: chrono::Utc::now(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn records_pushed_during_a_slow_flush_are_not_dropped_at_the_channel() {
    use metrics::set_default_local_recorder;
    use metrics_util::CompositeKey;
    use metrics_util::MetricKind;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};

    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let _guard = set_default_local_recorder(&recorder);

    let cfg = BufferedWriterConfig {
        connection: logthing::config::S3ConnectionConfig {
            endpoint: String::new(),
            bucket: String::new(),
            region: String::new(),
            access_key: String::new(),
            secret_key: String::new(),
        },
        prefix: "zeek".to_string(),
        max_buffer_rows: 1, // flush on every single push
        flush_threshold_bytes: usize::MAX,
        flush_interval_secs: 3600,
        channel_capacity: 4, // deliberately small -- the old, buggy code would overflow this
        max_partitions: 8,
    };
    let policy = FlushPolicy {
        max_rows: 1,
        max_bytes: usize::MAX,
        interval: LiveInterval::new(Duration::from_secs(3600)),
    };
    let slow_sink: Arc<dyn UploadSink> = Arc::new(SlowUploadSink {
        delay: Duration::from_millis(200),
    });

    let (handler, _join_handle) = ParquetWriterHandle::<ZeekSink>::start_with_stats(
        ZeekSink,
        slow_sink,
        cfg,
        policy,
        Arc::new(SourceHourlyStats::new()),
        None,
    );

    // Push far more records than channel_capacity while the first flush
    // (200ms) is in flight, yielding periodically so the background task
    // (on this multi-threaded runtime) genuinely runs concurrently.
    let mut send_errors = 0usize;
    for i in 0..40 {
        if handler.try_send(make_zeek_record(i)).is_err() {
            send_errors += 1;
        }
        tokio::task::yield_now().await;
    }

    // Give the background task time to finish processing everything pushed above.
    tokio::time::sleep(Duration::from_millis(1000)).await;

    assert_eq!(
        send_errors, 0,
        "no try_send should fail at the channel level while a flush is in flight"
    );

    let key = CompositeKey::new(
        MetricKind::Counter,
        metrics::Key::from_parts(
            "parquet_s3_dropped",
            vec![
                metrics::Label::new("source", "zeek"),
                metrics::Label::new("target", "slow"),
            ],
        ),
    );
    let dropped = snapshotter
        .snapshot()
        .into_hashmap()
        .get(&key)
        .map(|(_, _, v)| if let DebugValue::Counter(c) = v { *c } else { 0 })
        .unwrap_or(0);
    assert_eq!(
        dropped, 0,
        "parquet_s3_dropped must stay at 0 -- the channel must never report Full while a flush is in flight"
    );
}
```

- [ ] **Step 2: Run it**

```bash
export CC=/usr/bin/gcc CXX=/usr/bin/g++
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
source ~/.cargo/env
cargo test --test buffered_writer_flush_decoupling_integration
```
Expected: PASS. If it fails with `send_errors > 0` or `dropped > 0` before the code changes in Tasks 1-3, that confirms the test genuinely reproduces the original bug; after those changes, it must pass.

- [ ] **Step 3: Commit**

```bash
git add tests/buffered_writer_flush_decoupling_integration.rs
git commit -m "test(integration): prove real ParquetWriterHandle doesn't drop at the channel during a slow flush

Drives the actual production writer task with an artificially slow
UploadSink and 40 rapid pushes against a deliberately small channel
capacity (4). Bounded per spec decision #11 -- asserts on
parquet_s3_dropped (channel-level) specifically, not the separate,
pre-existing, accepted buffer-level hard cap."
```

---

### Task 8: E2e test + full verification

**Files:**
- Create: `tests/zeek_flush_decoupling_e2e.rs`
- Final full-suite verification across the whole worktree

**Interfaces:**
- Consumes: `logthing::zeek::listener::{ZeekListener, ZeekListenerConfig, ZeekHandler}` (all `pub`), `logthing::forwarding::buffered_writer::{ParquetWriterHandle, ...}`, same `SlowUploadSink` pattern as Task 7

This extends coverage to the actual outermost interface (a real TCP socket, real NDJSON parsing, real listener code) per this repo's three-tier testing rule — Task 7 called `try_send` directly; this task sends real bytes over a real socket.

- [ ] **Step 1: Write the e2e test file**

```rust
//! End-to-end test: a real Zeek TCP listener, wired to the real generic
//! writer (via ParquetWriterHandle) with an artificially slow UploadSink,
//! driven by a real TCP client sending real NDJSON lines -- proving no
//! records are dropped at the channel level under a slow flush through the
//! full real ingest path (socket -> parse -> handler -> writer channel).
//!
//! Uses a custom slow UploadSink rather than a real S3/local-disk target --
//! this repo's existing e2e tests already substitute out the actual
//! persistence backend the same way (see tests/hec_e2e.rs's doc comment).
//! No external dependency (no MinIO, no real disk writes) required.

use logthing::forwarding::buffered_writer::{
    BufferedWriterConfig, FlushPolicy, LiveInterval, ParquetWriterHandle, UploadSink,
};
use logthing::forwarding::zeek_s3::ZeekSink;
use logthing::stats::SourceHourlyStats;
use logthing::zeek::listener::{ZeekListener, ZeekListenerConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

struct SlowUploadSink {
    delay: Duration,
}

#[async_trait::async_trait]
impl UploadSink for SlowUploadSink {
    async fn upload(&self, _key: &str, _body: Vec<u8>) -> anyhow::Result<()> {
        tokio::time::sleep(self.delay).await;
        Ok(())
    }
    fn target_label(&self) -> &'static str {
        "slow"
    }
    fn location_hint(&self) -> String {
        "slow://test".to_string()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zeek_tcp_ingest_does_not_drop_records_at_the_channel_during_a_slow_flush() {
    use metrics::set_default_local_recorder;
    use metrics_util::CompositeKey;
    use metrics_util::MetricKind;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};

    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let _guard = set_default_local_recorder(&recorder);

    let cfg = BufferedWriterConfig {
        connection: logthing::config::S3ConnectionConfig {
            endpoint: String::new(),
            bucket: String::new(),
            region: String::new(),
            access_key: String::new(),
            secret_key: String::new(),
        },
        prefix: "zeek".to_string(),
        max_buffer_rows: 1,
        flush_threshold_bytes: usize::MAX,
        flush_interval_secs: 3600,
        channel_capacity: 4,
        max_partitions: 8,
    };
    let policy = FlushPolicy {
        max_rows: 1,
        max_bytes: usize::MAX,
        interval: LiveInterval::new(Duration::from_secs(3600)),
    };
    let slow_sink: Arc<dyn UploadSink> = Arc::new(SlowUploadSink {
        delay: Duration::from_millis(200),
    });
    let (handler, _join_handle) = ParquetWriterHandle::<ZeekSink>::start_with_stats(
        ZeekSink,
        slow_sink,
        cfg,
        policy,
        Arc::new(SourceHourlyStats::new()),
        None,
    );
    let handler: Arc<dyn logthing::zeek::listener::ZeekHandler> = Arc::new(handler);

    // Reserve an ephemeral port (bind-then-drop is the standard pattern for
    // this shape of test elsewhere in this repo, given ZeekListener::start()
    // binds internally and doesn't report back which port it chose).
    let port = {
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        probe.local_addr().unwrap().port()
    };

    let listener_cfg = ZeekListenerConfig {
        tcp_port: port,
        bind_address: "127.0.0.1".to_string(),
    };
    let zeek_listener = ZeekListener::new(listener_cfg, handler.clone());
    tokio::spawn(async move {
        let _ = zeek_listener.start().await;
    });

    // Connect, retrying briefly until the listener is up.
    let mut stream = loop {
        match TcpStream::connect(("127.0.0.1", port)).await {
            Ok(s) => break s,
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    };

    // Send 40 NDJSON lines rapidly -- comfortably more than channel_capacity (4)
    // -- while the first flush (200ms) is in flight in the background.
    for i in 0..40 {
        let line = format!("{{\"_path\":\"conn\",\"uid\":\"C{i}\"}}\n");
        stream.write_all(line.as_bytes()).await.unwrap();
        tokio::task::yield_now().await;
    }
    stream.flush().await.unwrap();

    // Give the background writer task time to finish processing everything.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let key = CompositeKey::new(
        MetricKind::Counter,
        metrics::Key::from_parts(
            "parquet_s3_dropped",
            vec![
                metrics::Label::new("source", "zeek"),
                metrics::Label::new("target", "slow"),
            ],
        ),
    );
    let dropped = snapshotter
        .snapshot()
        .into_hashmap()
        .get(&key)
        .map(|(_, _, v)| if let DebugValue::Counter(c) = v { *c } else { 0 })
        .unwrap_or(0);
    assert_eq!(
        dropped, 0,
        "parquet_s3_dropped must stay at 0 through the real TCP ingest path while a flush is in flight"
    );
}
```

- [ ] **Step 2: Run it**

```bash
cargo test --test zeek_flush_decoupling_e2e
```
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/zeek_flush_decoupling_e2e.rs
git commit -m "test(e2e): prove the real Zeek TCP ingest path doesn't drop at the channel during a slow flush

Real TCP listener, real NDJSON parsing, real ParquetWriterHandle -- only
the S3/disk upload leaf is substituted for an artificially slow no-op,
matching this repo's existing e2e convention (see hec_e2e.rs)."
```

- [ ] **Step 4: Full-suite verification**

```bash
export CC=/usr/bin/gcc CXX=/usr/bin/g++
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
source ~/.cargo/env
cargo fmt
cargo clippy --all-targets 2>&1 | tail -60
cargo test 2>&1 | tee /tmp/full_test_run.log
grep -c "^test result: ok" /tmp/full_test_run.log
grep -c "FAILED\|^error" /tmp/full_test_run.log
```
Expected: `cargo fmt` produces no diff (or only formats new code cleanly), `cargo clippy --all-targets` ends with `Finished` and no warnings, every `test result:` line says `ok`, and the FAILED/error count is 0.

- [ ] **Step 5: Final commit (if `cargo fmt` changed anything)**

```bash
git status --short
# if anything is unstaged (fmt changes):
git add -A
git commit -m "style: apply cargo fmt"
```

---

## Self-review notes (completed during plan authoring)

- **Spec coverage**: every row of the spec's decision log (1-12) maps to a specific task/step above — concurrency mechanism (Task 1-2), 1-in-flight limit (Task 2 Step 1, tested Task 6 Step 1), semaphore + observability (Task 1 Step 1/3, Task 2 Steps 1-2, Task 4, tested Task 6 Step 7), merge-back-on-failure (Task 2 Step 2, tested Task 6 Step 3), outcome routing via JoinSet only (Task 1-2), unchanged `push()` signature (Task 2 Step 3), no logging-attribution bundling (Task 2 Step 2's log line text is verbatim-preserved), test rewrites (Task 5), drain_pending_flushes as shared production/test primitive (Task 3), no other files touched (verified — only `buffered_writer.rs` and two new `tests/*.rs` files), bounded integration/e2e guarantee (Tasks 7-8's doc comments state the bound explicitly), `checked_sub` fix (Task 2 Step 2, tested Task 6 Step 5).
- **Type consistency checked**: `FlushOutcome` fields, `try_flush_partition_async`/`apply_flush_outcome`/`drain_pending_flushes`/`encode_and_upload` signatures are used identically everywhere they're referenced across Tasks 1-8.
- **No placeholders**: every step has complete, real code (no "TODO"/"similar to above"/"add error handling").
