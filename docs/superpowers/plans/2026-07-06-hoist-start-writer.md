# Hoist start_writer<S> Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate the near-identical `build_zeek_handle`/`build_suricata_handle` duplication by hoisting one generic `start_writer<S: ParquetSink + Default>` into `src/forwarding/buffered_writer.rs`, so future sources (IPFIX, sFlow, syslog, HEC, WEF) never need to write their own copy.

**Architecture:** Per the architecture review that motivated this: `build_zeek_handle` and `build_suricata_handle` are byte-for-byte identical except for the sink type and where the `max_partitions` constant lives. Everything they do — assemble `BufferedWriterConfig`/`FlushPolicy` from scalar args, call `ParquetWriterHandle::start_with_stats` — is already fully generic over `S: ParquetSink`. This is pure code motion: no public API changes, no behavior changes, no test changes to existing `zeek_start`/`suricata_start`/`zeek_local_start`/`suricata_local_start` call signatures.

**Tech Stack:** Rust — no new dependencies.

## Global Constraints

- `start_writer`'s signature must be `pub(crate) fn start_writer<S: ParquetSink + Default>(prefix: String, max_buffer_rows: usize, flush_threshold_bytes: usize, flush_interval_secs: u64, channel_capacity: usize, max_partitions: usize, sink: Arc<dyn UploadSink>, source_stats: Arc<crate::stats::SourceHourlyStats>) -> (ParquetWriterHandle<S>, tokio::task::JoinHandle<()>)` — `max_partitions` MUST be a parameter (not hardcoded inside `start_writer`), since different sources use different values (Zeek/Suricata: 256; other sources: other values not touched by this plan).
- `ZeekSink` and `SuricataSink` must gain `#[derive(Default)]` (they are already zero-field unit structs, so this is a no-op addition, not a behavior change) to satisfy the `S: Default` bound.
- No change to `zeek_start`/`zeek_local_start`/`suricata_start`/`suricata_local_start`'s public signatures — callers in `main.rs` must not need any changes.
- No change to `ZeekS3Handler`/`SuricataS3Handler` type aliases.
- Existing tests in `zeek_s3.rs` and `suricata_s3.rs` must pass unmodified — this is a pure refactor of code underneath them, not a change to any tested behavior.

---

### Task 1: Add `start_writer<S>` to `buffered_writer.rs`

**Files:**
- Modify: `src/forwarding/buffered_writer.rs` (insert after the `impl<S: ParquetSink> ParquetWriterHandle<S>` block closes at line 565, before the `// Unit tests` section comment at line 567)
- Test: same file's `#[cfg(test)] mod tests` block

**Interfaces:**
- Consumes: `ParquetSink`, `UploadSink`, `BufferedWriterConfig`, `FlushPolicy`, `ParquetWriterHandle::start_with_stats` (all already in this file), `unused_s3_connection_placeholder` (already in this file, line 144).
- Produces: `pub(crate) fn start_writer<S: ParquetSink + Default>(...) -> (ParquetWriterHandle<S>, tokio::task::JoinHandle<()>)`, consumed by Task 2 (`zeek_s3.rs`, `suricata_s3.rs`).

- [ ] **Step 1: Write a failing test proving the function works end-to-end with a real `ParquetSink` impl**

Add this test inside the existing `#[cfg(test)] mod tests { ... }` block in `src/forwarding/buffered_writer.rs`. Find a natural location — e.g. right after any existing test that already exercises `ParquetWriterHandle::start_with_stats` directly (search for `start_with_stats` inside this file's test module; if none exist, add it as the last test in the module, immediately before the module's closing `}`).

This test needs a minimal `ParquetSink` impl. Reuse the same pattern the file's existing tests already use for a mock sink (search this file's test module for an existing `struct` implementing `ParquetSink` for tests — if one exists, reuse its shape; otherwise use this self-contained one):

```rust
    #[tokio::test]
    async fn start_writer_wires_a_generic_parquet_sink_and_exits_cleanly() {
        use std::sync::Arc as StdArc;

        #[derive(Default)]
        struct TestSink;

        impl ParquetSink for TestSink {
            type Record = String;

            fn source(&self) -> &'static str {
                "test_start_writer"
            }

            fn partition(&self, _record: &Self::Record) -> Option<String> {
                None
            }

            fn schema(&self, _partition: Option<&str>) -> Arc<arrow_schema::Schema> {
                Arc::new(arrow_schema::Schema::new(vec![Field::new(
                    "value",
                    DataType::Utf8,
                    false,
                )]))
            }

            fn to_record_batch(
                &self,
                record: &Self::Record,
                schema: &Arc<arrow_schema::Schema>,
            ) -> anyhow::Result<RecordBatch> {
                let col = StdArc::new(StringArray::from(vec![record.as_str()]));
                Ok(RecordBatch::try_new(schema.clone(), vec![col])?)
            }
        }

        struct UnreachableUploadSink;
        #[async_trait::async_trait]
        impl UploadSink for UnreachableUploadSink {
            async fn upload(&self, _key: &str, _body: Vec<u8>) -> anyhow::Result<()> {
                anyhow::bail!("unreachable in this test")
            }
            fn target_label(&self) -> &'static str {
                "test"
            }
        }

        let (handle, join_handle) = start_writer::<TestSink>(
            "test-prefix".to_string(),
            100_000,
            usize::MAX,
            3600,
            256,
            1,
            StdArc::new(UnreachableUploadSink),
            StdArc::new(crate::stats::SourceHourlyStats::new()),
        );

        handle.try_send("hello".to_string()).ok();
        drop(handle);

        tokio::time::timeout(std::time::Duration::from_secs(5), join_handle)
            .await
            .expect("writer task must exit within 5s")
            .expect("writer task must not panic");
    }
```

- [ ] **Step 2: Run the test to verify it fails (function doesn't exist yet)**

Run: `cargo test --lib forwarding::buffered_writer::tests::start_writer_wires -- --nocapture`
Expected: FAIL with a compile error — `start_writer` is not defined.

- [ ] **Step 3: Add `start_writer<S>`**

In `src/forwarding/buffered_writer.rs`, insert this immediately after the `impl<S: ParquetSink> ParquetWriterHandle<S> { ... }` block's closing `}` (line 565), before the `// ---------------------------------------------------------------------------\n// Unit tests` comment block:

```rust

/// Generic replacement for each source's former `build_xxx_handle` helper
/// (e.g. Zeek's `build_zeek_handle`, Suricata's `build_suricata_handle`).
/// Every such helper did nothing beyond this: assemble
/// `BufferedWriterConfig`/`FlushPolicy` from flat scalar fields and forward
/// to `ParquetWriterHandle::start_with_stats` — there was no source-specific
/// behavior in any of them, only code the `S: ParquetSink` bound already
/// makes fully generic. `max_partitions` is a parameter (not hardcoded here)
/// because it differs per source.
pub(crate) fn start_writer<S: ParquetSink + Default>(
    prefix: String,
    max_buffer_rows: usize,
    flush_threshold_bytes: usize,
    flush_interval_secs: u64,
    channel_capacity: usize,
    max_partitions: usize,
    sink: Arc<dyn UploadSink>,
    source_stats: Arc<crate::stats::SourceHourlyStats>,
) -> (ParquetWriterHandle<S>, tokio::task::JoinHandle<()>) {
    let bwc = BufferedWriterConfig {
        connection: unused_s3_connection_placeholder(),
        prefix,
        max_buffer_rows,
        flush_threshold_bytes,
        flush_interval_secs,
        channel_capacity,
        max_partitions,
    };
    let policy = FlushPolicy {
        max_rows: max_buffer_rows,
        max_bytes: flush_threshold_bytes,
        interval: std::time::Duration::from_secs(flush_interval_secs),
    };
    ParquetWriterHandle::start_with_stats(S::default(), sink, bwc, policy, source_stats)
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test --lib forwarding::buffered_writer:: -- --nocapture`
Expected: PASS — the new test, plus every pre-existing test in this file's `mod tests` block.

- [ ] **Step 5: Commit**

```bash
git add src/forwarding/buffered_writer.rs
git commit -m "feat(forwarding): add generic start_writer<S> replacing per-source build_xxx_handle helpers

build_zeek_handle and build_suricata_handle are byte-for-byte identical
except for the sink type and where max_partitions lives — everything they
do is already generic over S: ParquetSink. Not yet adopted by either
source; that's the next task."
```

---

### Task 2: Migrate `zeek_s3.rs` and `suricata_s3.rs` to use `start_writer<S>`

**Files:**
- Modify: `src/forwarding/zeek_s3.rs` (remove `build_zeek_handle`, add `#[derive(Default)]` to `ZeekSink`, update `zeek_start`/`zeek_local_start` to call `start_writer::<ZeekSink>`)
- Modify: `src/forwarding/suricata_s3.rs` (remove `build_suricata_handle` and the now-unused `DEFAULT_MAX_SURICATA_PARTITIONS` module-level const's private use — keep the const itself since both call sites still need the `256` value, just inline it at each call site or keep the const and reference it from both — see Step 3 for the exact approach), add `#[derive(Default)]` to `SuricataSink`, update `suricata_start`/`suricata_local_start` to call `start_writer::<SuricataSink>`)

**Interfaces:**
- Consumes: `crate::forwarding::buffered_writer::start_writer` (Task 1).
- Produces: nothing new for later tasks — this completes the hoist for the two sources that currently have the duplication. Future sources' local-disk PRs (IPFIX, sFlow, syslog, HEC, WEF) should use `start_writer<S>` from the start rather than writing a new `build_xxx_handle`.

- [ ] **Step 1: Confirm the existing test suites in both files as the pre-refactor baseline**

Run: `cargo test --lib forwarding::zeek_s3:: forwarding::suricata_s3:: -- --nocapture`
Expected: PASS (all pre-existing tests) — record this as your baseline; every one of these must still pass after Steps 2-3 with zero modifications to the tests themselves.

- [ ] **Step 2: Migrate `zeek_s3.rs`**

Add `#[derive(Default)]` to `ZeekSink`'s declaration (currently `pub struct ZeekSink;` at line 63) — change to:

```rust
#[derive(Default)]
pub struct ZeekSink;
```

Replace the entire `build_zeek_handle` function (lines 184-215 — from `fn build_zeek_handle(` through its closing `}`) with nothing (delete it entirely).

Then replace `zeek_start` and `zeek_local_start` (currently calling `build_zeek_handle`) — change:

```rust
pub fn zeek_start(
    cfg: &ZeekS3Config,
    s3: std::sync::Arc<crate::forwarding::s3_sink::S3Sink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
) -> (ZeekS3Handler, tokio::task::JoinHandle<()>) {
    build_zeek_handle(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        cfg.flush_threshold_bytes,
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        s3,
        source_stats,
    )
}
```

to:

```rust
pub fn zeek_start(
    cfg: &ZeekS3Config,
    s3: std::sync::Arc<crate::forwarding::s3_sink::S3Sink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
) -> (ZeekS3Handler, tokio::task::JoinHandle<()>) {
    crate::forwarding::buffered_writer::start_writer::<ZeekSink>(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        cfg.flush_threshold_bytes,
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        DEFAULT_MAX_ZEEK_PARTITIONS,
        s3,
        source_stats,
    )
}
```

and change:

```rust
pub fn zeek_local_start(
    cfg: &crate::config::ZeekLocalConfig,
    sink: std::sync::Arc<crate::forwarding::local_sink::LocalDiskSink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
) -> (ZeekS3Handler, tokio::task::JoinHandle<()>) {
    build_zeek_handle(
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

to:

```rust
pub fn zeek_local_start(
    cfg: &crate::config::ZeekLocalConfig,
    sink: std::sync::Arc<crate::forwarding::local_sink::LocalDiskSink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
) -> (ZeekS3Handler, tokio::task::JoinHandle<()>) {
    crate::forwarding::buffered_writer::start_writer::<ZeekSink>(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        cfg.flush_threshold_bytes,
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        DEFAULT_MAX_ZEEK_PARTITIONS,
        sink,
        source_stats,
    )
}
```

Note `DEFAULT_MAX_ZEEK_PARTITIONS` no longer exists as a local `const` inside the deleted `build_zeek_handle` — add it as a module-level `const` instead, placed right before `zeek_start` (immediately after the deleted function's former location, or anywhere above its first use — place it directly above `pub fn zeek_start`):

```rust
/// Replaces the old `MAX_ZEEK_STREAMS` constant.
const DEFAULT_MAX_ZEEK_PARTITIONS: usize = 256;

```

- [ ] **Step 3: Migrate `suricata_s3.rs`**

Add `#[derive(Default)]` to `SuricataSink`'s declaration (currently `pub struct SuricataSink;` at line 64) — change to:

```rust
#[derive(Default)]
pub struct SuricataSink;
```

Delete the entire `build_suricata_handle` function (lines 151-179 — from `fn build_suricata_handle(` through its closing `}`). Leave the existing module-level `const DEFAULT_MAX_SURICATA_PARTITIONS: usize = 256;` in place (it's already at module level in this file, unlike Zeek's, and both `suricata_start`/`suricata_local_start` still need it).

Replace `suricata_start` and `suricata_local_start` — change:

```rust
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
```

to:

```rust
pub fn suricata_start(
    cfg: &SuricataS3Config,
    s3: std::sync::Arc<crate::forwarding::s3_sink::S3Sink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
) -> (SuricataS3Handler, tokio::task::JoinHandle<()>) {
    crate::forwarding::buffered_writer::start_writer::<SuricataSink>(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        cfg.flush_threshold_bytes,
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        DEFAULT_MAX_SURICATA_PARTITIONS,
        s3,
        source_stats,
    )
}
```

and change:

```rust
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

to:

```rust
pub fn suricata_local_start(
    cfg: &crate::config::SuricataLocalConfig,
    sink: std::sync::Arc<crate::forwarding::local_sink::LocalDiskSink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
) -> (SuricataS3Handler, tokio::task::JoinHandle<()>) {
    crate::forwarding::buffered_writer::start_writer::<SuricataSink>(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        cfg.flush_threshold_bytes,
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        DEFAULT_MAX_SURICATA_PARTITIONS,
        sink,
        source_stats,
    )
}
```

- [ ] **Step 4: Run both files' full test suites to confirm zero regressions**

Run: `cargo test --lib forwarding::zeek_s3:: forwarding::suricata_s3:: -- --nocapture`
Expected: PASS — identical pass count to Step 1's baseline, with zero test modifications. In particular: `zeek_start_wires_handler_and_join_handle`, `zeek_local_start_wires_handler_and_join_handle`, `multi_zeek_handler_fans_out_to_every_inner_handler`, `suricata_start_wires_handler_and_join_handle`, `suricata_local_start_wires_handler_and_join_handle`, `multi_suricata_handler_fans_out_to_every_inner_handler` must all still pass — these exercise `zeek_start`/`suricata_start`/etc.'s observable behavior directly.

- [ ] **Step 5: Run the full workspace build, full test suite, fmt, and clippy**

Run: `cargo build --quiet` — expected: no errors, no warnings.
Run: `cargo test --quiet` — expected: PASS, same total pass count as before this plan (no regressions anywhere in the workspace, since `main.rs`'s callers of `zeek_start`/`suricata_start`/etc. are unaffected — their signatures didn't change).
Run: `cargo fmt --all -- --check` — expected: no output.
Run: `cargo clippy --all-targets --quiet -- -D warnings` — expected: no output.

- [ ] **Step 6: Commit**

```bash
git add src/forwarding/zeek_s3.rs src/forwarding/suricata_s3.rs
git commit -m "refactor(forwarding): migrate zeek_s3/suricata_s3 to shared start_writer<S>

Deletes build_zeek_handle and build_suricata_handle — both were byte-for-byte
identical wrappers around ParquetWriterHandle::start_with_stats. zeek_start,
zeek_local_start, suricata_start, and suricata_local_start now call the
shared start_writer<S> from Task 1 directly. No public signature changes,
no test changes, no behavior changes — pure code motion."
```

---

## Post-plan note for the final whole-branch review

When the final reviewer looks at this branch as a whole, it should confirm:
1. `zeek_start`, `zeek_local_start`, `suricata_start`, `suricata_local_start` still have the exact same public signatures as before this plan (no caller in `main.rs` needed changes — confirm `main.rs` has zero diff from this branch).
2. `ZeekSink`/`SuricataSink` gaining `#[derive(Default)]` has no observable effect beyond satisfying `start_writer`'s `S: Default` bound (both are zero-field unit structs; `Default::default()` for a unit struct is trivially the same single value the struct always was).
3. No test file changed — every pre-existing test in `zeek_s3.rs` and `suricata_s3.rs` still passes with its original assertions intact, proving this was truly behavior-preserving code motion.
