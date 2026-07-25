# Perf Do-Next Items Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the 3 "do next" items from `docs/superpowers/specs/2026-07-24-performance-improvements-plan.md` §5 (log-field additions, buffer/channel gauges, a HashSet-removal micro-optimization), each backed by tests at the tiers that genuinely apply, and benchmarked before/after via `examples/flush_decoupling_benchmark.rs`.

**Architecture:** No new modules. All changes are additive edits to `src/forwarding/buffered_writer.rs` (2 items: log fields, gauges) and `src/zeek/schema.rs` (1 item: HashSet removal), plus matching test additions in the same files and in `tests/buffered_writer_flush_decoupling_integration.rs` / `tests/zeek_flush_decoupling_e2e.rs`.

**Tech Stack:** Rust, tokio, `tracing`/`tracing-subscriber` (already dependencies), `metrics`/`metrics-util` (already dependencies, `DebuggingRecorder` pattern already established in this file).

**Full design rationale:** `docs/superpowers/specs/2026-07-24-perf-do-next-items-design.md` — read it before starting; this plan assumes its decisions (they are not re-litigated here).

## Global Constraints

- Do not touch anything outside the 3 named items (§2.7, §2.4, §2.2 of the source plan). No refactors, no drive-by cleanups.
- `push()` (the per-record hot path in `buffered_writer.rs`) must not gain any new unconditional work. The two new gauges are set only from the writer's existing periodic ticker branch.
- No new external crate dependencies. The tracing-capture test helper uses only `tracing`/`tracing-subscriber`, both already in `Cargo.toml`.
- Every new `#[tokio::test]` that needs to observe a value emitted by the writer's background task (spawned via `tokio::spawn` inside `ParquetWriterHandle::start_with_stats`) MUST use the default (current-thread) flavor, never `#[tokio::test(flavor = "multi_thread")]` — both `metrics::set_default_local_recorder` and `tracing::subscriber::set_default` install thread-local state, and a multi-thread runtime can schedule the background task onto a different OS thread, silently hiding its output from the test. This is a documented, previously-diagnosed pitfall in this exact file family — see the doc comments at the top of `tests/zeek_flush_decoupling_e2e.rs` and `tests/buffered_writer_flush_decoupling_integration.rs`.
- Follow existing test-fixture duplication convention: small in-test structs (`MockSink`, `RecordingSink`, `SlowUploadSink`, etc.) are redefined locally in each test file that needs them, not factored into a shared test-utils module. Do the same for the new tracing-capture helper — do not introduce a shared module.

---

## Task 0: Capture baseline benchmark numbers

**Files:**
- Create: `docs/superpowers/specs/2026-07-24-benchmark-results-baseline.md`

**Interfaces:**
- Produces: baseline throughput/drop-counter figures that Tasks 1, 2, and 3 compare against.

This task runs on the feature branch (`perf/do-next-items`) before any of the 3 items are implemented — it must be the first task completed.

- [ ] **Step 1: Build the benchmark binary in release mode**

Run: `cargo build --release --example flush_decoupling_benchmark`
Expected: clean build, no errors.

- [ ] **Step 2: Run `realistic` mode twice**

Run (twice, capture both outputs):
```bash
cargo run --release --example flush_decoupling_benchmark -- mode=realistic duration_secs=30 target_rate=4000 upload_delay_ms=150
```
Expected: the harness prints final counter values for `parquet_s3_records_written`, `parquet_s3_dropped`, `parquet_s3_buffer_dropped`, and overall throughput (records/sec). Record both runs' full output.

- [ ] **Step 3: Run `stress` mode twice**

Run (twice, capture both outputs):
```bash
cargo run --release --example flush_decoupling_benchmark -- mode=stress duration_secs=30 target_rate=4000 upload_delay_ms=150
```
Expected: same metric set printed; stress mode is expected to show the pre-existing hard-cap drop behavior described in `BENCHMARK_RESULTS.md` §4/§6 — this is expected baseline behavior, not a regression to fix.

- [ ] **Step 4: Write the baseline results file**

Create `docs/superpowers/specs/2026-07-24-benchmark-results-baseline.md` containing: the exact commands run, the git commit hash (`git rev-parse HEAD`), and all 4 runs' full output (2× realistic, 2× stress), verbatim.

- [ ] **Step 5: Commit**

```bash
git add docs/superpowers/specs/2026-07-24-benchmark-results-baseline.md
git commit -m "docs: capture pre-change benchmark baseline for do-next items"
```

---

## Task 1: 2.7 — Buffered-writer log-field additions

**Depends on:** Task 0 (must start from the baseline commit).

**Files:**
- Modify: `src/forwarding/buffered_writer.rs` (6 call sites + new tests in its `#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: nothing new from other tasks.
- Produces: nothing new consumed by later tasks (Task 2 shares this file but touches different lines; no shared new symbols).

**Background — which of the 6 sites are actually reachable by a test today**, verified by reading the surrounding code:

| Line | Function | Reachable how | Test tier |
|---|---|---|---|
| 649 | `apply_flush_outcome` (failure branch) | Directly: construct a `FlushOutcome::Failure` and call `w.apply_flush_outcome(...)` on a `PartitionedParquetWriter` built in-test | Unit |
| 686 | `drain_pending_flushes` (panic branch) | Directly: push a record with `max_buffer_rows=1` against a sink whose `UploadSink::upload()` panics, then call `w.drain_pending_flushes().await` | Unit |
| 1042 | `start_with_stats` task, shutdown `flush_all` error | `flush_all()` (line 487-540) genuinely returns `Err` when an upload fails during the final drain-and-flush — reachable, but only via the full spawned task (drop the sender to close the channel while an upload is failing) | Integration |
| 1067 | `start_with_stats` task, flush task panic (outer `join_next` branch) | Reachable via a panicking upload while the writer task is still running (steady state, not shutdown) — only via the full spawned task | Integration |
| 1032 | `start_with_stats` task, push error | **Dead code today** — `push()` (line 416) always returns `Ok(())`; the existing code comment at line 1028-1030 states this branch is "currently unreachable" | None (see Step 5) |
| 1053 | `start_with_stats` task, `flush_all_if_needed` error | **Dead code today** — `flush_all_if_needed()` (line 543-560) always returns `Ok(())` (verified: no `Err` path exists in its body); the existing code comment states this branch is "currently unreachable" | None (see Step 5) |

- [ ] **Step 1: Add the tracing-capture test helper**

Add this to `src/forwarding/buffered_writer.rs`'s `#[cfg(test)] mod tests` block, near the top alongside the other test fixtures (after `test_schema()`, before `MockSink`):

```rust
    // -----------------------------------------------------------------------
    // In-test tracing field capture (for asserting `source`/`target` fields
    // on warn! calls — uses only already-present `tracing`/`tracing-subscriber`
    // deps, not a new external test crate).
    // -----------------------------------------------------------------------

    #[derive(Default, Clone, Debug)]
    struct CapturedEvent {
        message: String,
        fields: std::collections::HashMap<String, String>,
    }

    struct FieldVisitor(CapturedEvent);
    impl tracing::field::Visit for FieldVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            let s = format!("{value:?}").trim_matches('"').to_string();
            if field.name() == "message" {
                self.0.message = s;
            } else {
                self.0.fields.insert(field.name().to_string(), s);
            }
        }
    }

    struct CaptureLayer {
        events: std::sync::Arc<std::sync::Mutex<Vec<CapturedEvent>>>,
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CaptureLayer {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut visitor = FieldVisitor(CapturedEvent::default());
            event.record(&mut visitor);
            self.events.lock().unwrap().push(visitor.0);
        }
    }

    /// Installs a thread-local tracing subscriber for the lifetime of the
    /// returned guard. Must be used with the default (current-thread)
    /// `#[tokio::test]` flavor so any background-task-emitted events land
    /// on the same OS thread this installs on.
    struct TestTracingCapture {
        events: std::sync::Arc<std::sync::Mutex<Vec<CapturedEvent>>>,
        _guard: tracing::subscriber::DefaultGuard,
    }

    impl TestTracingCapture {
        fn install() -> Self {
            use tracing_subscriber::layer::SubscriberExt as _;
            let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let layer = CaptureLayer {
                events: events.clone(),
            };
            let subscriber = tracing_subscriber::registry().with(layer);
            let guard = tracing::subscriber::set_default(subscriber);
            Self {
                events,
                _guard: guard,
            }
        }

        fn events(&self) -> Vec<CapturedEvent> {
            self.events.lock().unwrap().clone()
        }
    }

    /// Upload sink whose `upload()` always panics — used to exercise the
    /// flush-task-panicked warning paths (lines 686, 1067).
    struct PanicUploadSink;
    #[async_trait::async_trait]
    impl UploadSink for PanicUploadSink {
        async fn upload(&self, _key: &str, _body: Vec<u8>) -> anyhow::Result<()> {
            panic!("intentional test panic to exercise flush-task panic handling")
        }
        fn target_label(&self) -> &'static str {
            "panicky"
        }
        fn location_hint(&self) -> String {
            "panic://test".to_string()
        }
    }
```

- [ ] **Step 2: Write the two failing unit tests (649, 686)**

Add these tests directly after `flushes_in_flight_gauge_tracks_a_single_flush` (or any convenient point in the same `mod tests`):

```rust
    /// Line 649 (`apply_flush_outcome`'s failure branch) must log both
    /// `source` and `target` as structured fields, not just interpolate
    /// them into the message.
    #[tokio::test]
    async fn apply_flush_outcome_failure_logs_source_and_target_fields() {
        let uploads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink: Arc<dyn UploadSink> = Arc::new(RecordingSink { uploads });
        let (cfg, policy) = test_config(5);
        let mut w = PartitionedParquetWriter::new(MockSink, sink, cfg, policy);

        let capture = TestTracingCapture::install();
        w.apply_flush_outcome(FlushOutcome::Failure {
            key: "".to_string(),
            batches: std::collections::VecDeque::new(),
            row_count: 0,
            byte_count: 0,
            error: "simulated upload failure".to_string(),
        });

        let events = capture.events();
        let found = events.iter().any(|e| {
            e.message.contains("writer push error")
                && e.fields.get("source").map(String::as_str) == Some("test")
                && e.fields.get("target").map(String::as_str) == Some("recording")
        });
        assert!(
            found,
            "expected a warn event with source=\"test\" target=\"recording\", got: {events:?}"
        );
    }

    /// Line 686 (`drain_pending_flushes`'s panic branch) must log both
    /// `source` and `target` — neither is a local in that function, so
    /// they must be fetched via `self.sink.source()` / `self.s3.target_label()`.
    #[tokio::test]
    async fn drain_pending_flushes_panic_logs_source_and_target_fields() {
        let sink: Arc<dyn UploadSink> = Arc::new(PanicUploadSink);
        let (cfg, policy) = test_config(1); // flush on first row
        let mut w = PartitionedParquetWriter::new(MockSink, sink, cfg, policy);

        w.push("hello".to_string()).await.unwrap(); // spawns the flush task, which will panic inside upload()

        let capture = TestTracingCapture::install();
        w.drain_pending_flushes().await;

        let events = capture.events();
        let found = events.iter().any(|e| {
            e.message.contains("flush task panicked")
                && e.fields.get("source").map(String::as_str) == Some("test")
                && e.fields.get("target").map(String::as_str) == Some("panicky")
        });
        assert!(
            found,
            "expected a warn event with source=\"test\" target=\"panicky\", got: {events:?}"
        );
    }
```

- [ ] **Step 3: Run the new tests to verify they fail**

Run: `cargo test --lib forwarding::buffered_writer::tests::apply_flush_outcome_failure_logs_source_and_target_fields forwarding::buffered_writer::tests::drain_pending_flushes_panic_logs_source_and_target_fields -- --nocapture`
Expected: both FAIL — the assertions find no matching event, because `source`/`target` are not yet structured fields at these call sites (the current code is `tracing::warn!("parquet_s3 writer push error: {error}");` and `tracing::warn!("parquet_s3 flush task panicked: {join_err}");` — plain string interpolation only).

- [ ] **Step 4: Add the fields at all 6 call sites**

Line 649, inside `apply_flush_outcome`'s `FlushOutcome::Failure` arm — change:
```rust
                tracing::warn!("parquet_s3 writer push error: {error}");
```
to:
```rust
                tracing::warn!(source, target, "parquet_s3 writer push error: {error}");
```
(`source`/`target` are already bound as locals at the top of `apply_flush_outcome`, lines 631-632.)

Line 686, inside `drain_pending_flushes`'s `Err(join_err)` arm — change:
```rust
                Err(join_err) => {
                    tracing::warn!("parquet_s3 flush task panicked: {join_err}");
                }
```
to:
```rust
                Err(join_err) => {
                    tracing::warn!(
                        source = self.sink.source(),
                        target = self.s3.target_label(),
                        "parquet_s3 flush task panicked: {join_err}"
                    );
                }
```

Line 1042, inside `start_with_stats`'s shutdown branch — change:
```rust
                                if let Err(e) = writer.flush_all().await {
                                    tracing::warn!("parquet_s3 flush_all on shutdown: {e}");
                                }
```
to:
```rust
                                if let Err(e) = writer.flush_all().await {
                                    tracing::warn!(source, target, "parquet_s3 flush_all on shutdown: {e}");
                                }
```
(`source`/`target` are captured as locals at lines 1002-1003, in scope for the whole `async move` closure.)

Line 1067, inside `start_with_stats`'s `Some(result) = writer.flush_tasks.join_next()` branch — change:
```rust
                            Err(join_err) => {
                                tracing::warn!("parquet_s3 flush task panicked: {join_err}");
                            }
```
to:
```rust
                            Err(join_err) => {
                                tracing::warn!(source, target, "parquet_s3 flush task panicked: {join_err}");
                            }
```

Line 1032, inside `start_with_stats`'s push-error branch (dead code, see Step 5) — change:
```rust
                                if let Err(e) = writer.push(record).await {
                                    tracing::warn!("parquet_s3 writer push error: {e}");
                                }
```
to:
```rust
                                if let Err(e) = writer.push(record).await {
                                    tracing::warn!(source, target, "parquet_s3 writer push error: {e}");
                                }
```

Line 1053, inside `start_with_stats`'s ticker branch (dead code, see Step 5) — change:
```rust
                        if let Err(e) = writer.flush_all_if_needed().await {
                            tracing::warn!("parquet_s3 flush_all_if_needed: {e}");
                        }
```
to:
```rust
                        if let Err(e) = writer.flush_all_if_needed().await {
                            tracing::warn!(source, target, "parquet_s3 flush_all_if_needed: {e}");
                        }
```

- [ ] **Step 5: Run the two unit tests again to verify they pass**

Run: `cargo test --lib forwarding::buffered_writer::tests::apply_flush_outcome_failure_logs_source_and_target_fields forwarding::buffered_writer::tests::drain_pending_flushes_panic_logs_source_and_target_fields`
Expected: both PASS.

- [ ] **Step 6: Write the integration test for lines 1042 and 1067**

Add to `tests/buffered_writer_flush_decoupling_integration.rs`, after the existing `records_pushed_during_a_slow_flush_are_not_dropped_at_the_channel` test. This needs its own local copy of the tracing-capture helper (following this codebase's existing fixture-duplication convention) and its own `PanicUploadSink`:

```rust
struct PanicUploadSink;
#[async_trait::async_trait]
impl UploadSink for PanicUploadSink {
    async fn upload(&self, _key: &str, _body: Vec<u8>) -> anyhow::Result<()> {
        panic!("intentional test panic to exercise flush-task panic handling")
    }
    fn target_label(&self) -> &'static str {
        "panicky"
    }
    fn location_hint(&self) -> String {
        "panic://test".to_string()
    }
}

#[derive(Default, Clone, Debug)]
struct CapturedEvent {
    message: String,
    fields: std::collections::HashMap<String, String>,
}

struct FieldVisitor(CapturedEvent);
impl tracing::field::Visit for FieldVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let s = format!("{value:?}").trim_matches('"').to_string();
        if field.name() == "message" {
            self.0.message = s;
        } else {
            self.0.fields.insert(field.name().to_string(), s);
        }
    }
}

struct CaptureLayer {
    events: Arc<std::sync::Mutex<Vec<CapturedEvent>>>,
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CaptureLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) {
        let mut visitor = FieldVisitor(CapturedEvent::default());
        event.record(&mut visitor);
        self.events.lock().unwrap().push(visitor.0);
    }
}

/// Line 1067: a flush task panics while the writer's background task is
/// still in its steady-state select! loop (not shutdown) — the panic must
/// surface via the outer `Some(result) = writer.flush_tasks.join_next()`
/// branch with `source`/`target` fields attached. Uses default
/// (current-thread) `#[tokio::test]` flavor so the background task's
/// tracing events land on the same thread this test's subscriber guard
/// installs on -- see this file's own top-of-file doc comment for why a
/// multi_thread flavor would silently miss them.
#[tokio::test]
async fn flush_task_panic_during_steady_state_logs_source_and_target() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let layer = CaptureLayer {
        events: events.clone(),
    };
    let subscriber = tracing_subscriber::registry().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    let cfg = BufferedWriterConfig {
        connection: logthing::config::S3ConnectionConfig {
            endpoint: String::new(),
            bucket: String::new(),
            region: String::new(),
            access_key: String::new(),
            secret_key: String::new(),
        },
        prefix: "zeek".to_string(),
        max_buffer_rows: 1, // flush on every push
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
    let panic_sink: Arc<dyn UploadSink> = Arc::new(PanicUploadSink);

    let (handler, _join_handle) = ParquetWriterHandle::<SimpleFastSink>::start_with_stats(
        SimpleFastSink,
        panic_sink,
        cfg,
        policy,
        Arc::new(SourceHourlyStats::new()),
        None,
    );

    handler
        .try_send("record-0".to_string())
        .expect("first try_send must succeed on a fresh, empty channel");

    // Poll (bounded) for the panic-handling warning to appear, rather than
    // a fixed sleep -- the flush task's panic is asynchronous.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut found = false;
    while tokio::time::Instant::now() < deadline {
        let snapshot = events.lock().unwrap().clone();
        found = snapshot.iter().any(|e| {
            e.message.contains("flush task panicked")
                && e.fields.get("source").map(String::as_str) == Some("zeek")
                && e.fields.get("target").map(String::as_str) == Some("panicky")
        });
        if found {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        found,
        "expected a warn event with source=\"zeek\" target=\"panicky\" for the steady-state flush-task panic, got: {:?}",
        events.lock().unwrap()
    );
}
```

Note: this test only exercises line 1067 directly (the reachable, non-shutdown panic path). Line 1042 (`flush_all` returning `Err` at shutdown) is exercised implicitly by the same kind of setup but is lower-value to test in isolation — its warning uses the exact same `source, target` field-passing pattern already proven correct by this test and by `apply_flush_outcome_failure_logs_source_and_target_fields` in Task 1 Step 2 (same locals, same macro shape). Do not add a second near-duplicate integration test for it; this is intentionally scoped, not an oversight.

- [ ] **Step 7: Run the integration test to verify it fails, then passes**

Run: `cargo test --test buffered_writer_flush_decoupling_integration flush_task_panic_during_steady_state_logs_source_and_target -- --nocapture`
Expected: FAILs before Step 4's edits are visible to this binary (it should already pass once Step 4 is done, since Step 4 happens before this step in execution order — if you're following this plan strictly top-to-bottom, write this test in Step 6 as shown, then confirm it fails against a temporarily-reverted line 1067 to prove it discriminates, then confirm it passes with Step 4's real edit in place; do not skip the fail-then-pass cycle).

- [ ] **Step 8: Add explicit no-test rationale comments for the two dead-code sites (1032, 1053)**

These two branches cannot be exercised by any test today because `push()` and `flush_all_if_needed()` are hardcoded to always return `Ok(())` (this is a pre-existing characteristic, tracked separately as "Row 6" in the source plan's deferred decision log — out of scope to change here). Add a one-line comment directly above each, so a future reader doesn't assume test coverage was simply forgotten:

At line 1032 (just above the existing "push() always returns Ok now..." comment):
```rust
                                // NOTE: unreachable today (see comment below) -- no test
                                // exercises this branch; source/target fields verified by
                                // code review + successful compilation only.
```

At line 1053 (just above the existing "flush_all_if_needed() always returns Ok now..." comment):
```rust
                        // NOTE: unreachable today (see comment below) -- no test
                        // exercises this branch; source/target fields verified by
                        // code review + successful compilation only.
```

- [ ] **Step 9: Run the full existing test suite for this file to confirm no regression**

Run: `cargo test --lib forwarding::buffered_writer`
Expected: all tests pass, including the pre-existing ones (`push_accumulates_below_row_threshold`, `flushes_in_flight_gauge_tracks_a_single_flush`, `push_enforces_hard_cap_on_flush_failure`, etc.) and the two new ones from Step 2.

Run: `cargo test --test buffered_writer_flush_decoupling_integration`
Expected: all tests pass, including the pre-existing `records_pushed_during_a_slow_flush_are_not_dropped_at_the_channel` and the new one from Step 6.

Run: `cargo test --test zeek_flush_decoupling_e2e`
Expected: passes unchanged (no edits made to this file in this task).

- [ ] **Step 10: Benchmark regression check**

Run:
```bash
cargo run --release --example flush_decoupling_benchmark -- mode=realistic duration_secs=30 target_rate=4000 upload_delay_ms=150
cargo run --release --example flush_decoupling_benchmark -- mode=stress duration_secs=30 target_rate=4000 upload_delay_ms=150
```
Expected: `parquet_s3_records_written`/`parquet_s3_dropped`/`parquet_s3_buffer_dropped` and overall throughput within noise of Task 0's baseline readings — this item is log-field-only, off the hot path, no throughput change expected. Append both runs' output to a new file `docs/superpowers/specs/2026-07-24-benchmark-results-task1-log-fields.md`, with a one-line comparison note against baseline.

- [ ] **Step 11: Commit**

```bash
git add src/forwarding/buffered_writer.rs tests/buffered_writer_flush_decoupling_integration.rs docs/superpowers/specs/2026-07-24-benchmark-results-task1-log-fields.md
git commit -m "fix(forwarding): add source/target fields to buffered-writer warn! call sites"
```

---

## Task 2: 2.4 — Buffer/channel-depth gauges

**Depends on:** Task 1 (same file, same worktree — do not run this in a separate worktree from Task 1).

**Files:**
- Modify: `src/forwarding/buffered_writer.rs` (new method + ticker branch + new tests)
- Modify: `tests/buffered_writer_flush_decoupling_integration.rs` (new test)
- Modify: `tests/zeek_flush_decoupling_e2e.rs` (new assertions on existing test, or new test)

**Interfaces:**
- Produces: `pub(crate) fn update_buffer_gauges(&self)` on `PartitionedParquetWriter<S>` — no parameters, reads `self.sink.source()`, `self.s3.target_label()`, and `self.buffers` internally.

- [ ] **Step 1: Write the failing unit test**

Add to `src/forwarding/buffered_writer.rs`'s `#[cfg(test)] mod tests`, after `flushes_in_flight_gauge_tracks_a_single_flush`:

```rust
    /// `update_buffer_gauges()` must set `parquet_s3_buffer_rows` to each
    /// partition's live `row_count`, labeled by source/target/partition.
    #[tokio::test]
    #[allow(clippy::mutable_key_type)]
    async fn update_buffer_gauges_reports_live_row_counts() {
        use metrics::set_default_local_recorder;
        use metrics_util::CompositeKey;
        use metrics_util::MetricKind;
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let s3 = unreachable_s3().await;
        let (cfg, policy) = test_config(1_000); // high threshold: nothing flushes
        let mut w = PartitionedParquetWriter::new(MockSink, s3, cfg, policy);

        for i in 0..7 {
            w.push(format!("r{i}")).await.unwrap();
        }
        w.update_buffer_gauges();

        let key = CompositeKey::new(
            MetricKind::Gauge,
            metrics::Key::from_parts(
                "parquet_s3_buffer_rows",
                vec![
                    metrics::Label::new("source", "test"),
                    metrics::Label::new("target", "s3"),
                    metrics::Label::new("partition", ""),
                ],
            ),
        );
        let value = snapshotter
            .snapshot()
            .into_hashmap()
            .get(&key)
            .map(|(_, _, v)| {
                if let DebugValue::Gauge(g) = v {
                    g.into_inner()
                } else {
                    0.0
                }
            })
            .unwrap_or(0.0);
        assert_eq!(
            value, 7.0,
            "expected parquet_s3_buffer_rows{{source=\"test\",target=\"s3\",partition=\"\"}} == 7.0"
        );
    }
```

This test uses `unreachable_s3()` (already defined in this module, see line 1363), whose `target_label()` is `"s3"` — confirm this by reading `crate::forwarding::s3_sink::S3Sink::target_label()` if unsure before running.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --lib forwarding::buffered_writer::tests::update_buffer_gauges_reports_live_row_counts`
Expected: FAIL with a compile error (`update_buffer_gauges` does not exist yet).

- [ ] **Step 3: Implement `update_buffer_gauges`**

Add this method to the `impl<S: ParquetSink> PartitionedParquetWriter<S>` block, directly after `apply_flush_outcome` (after line 673, before `drain_pending_flushes`):

```rust
    /// Report each partition's live buffered row count as a leading
    /// indicator of backpressure. Called only from the writer's periodic
    /// ticker (see `ParquetWriterHandle::start_with_stats`), never from
    /// `push()` -- `push()` is the hottest call in this file and must not
    /// gain unconditional per-record work.
    pub(crate) fn update_buffer_gauges(&self) {
        let source = self.sink.source();
        let target = self.s3.target_label();
        for (partition, buf) in &self.buffers {
            metrics::gauge!("parquet_s3_buffer_rows",
                "source" => source, "target" => target, "partition" => partition.clone())
                .set(buf.row_count as f64);
        }
    }
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test --lib forwarding::buffered_writer::tests::update_buffer_gauges_reports_live_row_counts`
Expected: PASS.

- [ ] **Step 5: Wire `update_buffer_gauges` and the new channel-capacity gauge into the ticker branch**

In `ParquetWriterHandle::start_with_stats`, the `ticker.tick()` branch (around line 1048-1055) currently reads:

```rust
                    _ = ticker.tick() => {
                        // flush_all_if_needed() always returns Ok now (flush failures surface
                        // async via apply_flush_outcome) -- kept as Result to avoid churning
                        // callers; this branch is currently unreachable.
                        if let Err(e) = writer.flush_all_if_needed().await {
                            tracing::warn!(source, target, "parquet_s3 flush_all_if_needed: {e}");
                        }
                    }
```

Change it to:

```rust
                    _ = ticker.tick() => {
                        metrics::gauge!("parquet_s3_channel_available", "source" => source, "target" => target)
                            .set(rx.capacity() as f64);
                        writer.update_buffer_gauges();
                        // flush_all_if_needed() always returns Ok now (flush failures surface
                        // async via apply_flush_outcome) -- kept as Result to avoid churning
                        // callers; this branch is currently unreachable.
                        if let Err(e) = writer.flush_all_if_needed().await {
                            tracing::warn!(source, target, "parquet_s3 flush_all_if_needed: {e}");
                        }
                    }
```

`rx` (the `tokio::sync::mpsc::Receiver`) is already captured by this closure (it's what `msg = rx.recv() =>` reads from in the sibling branch); `Receiver::capacity()` reads the same underlying semaphore as `Sender::capacity()` would, so no extra clone of `tx` is needed.

- [ ] **Step 6: Write the failing integration test**

Add to `tests/buffered_writer_flush_decoupling_integration.rs`, after the test added in Task 1 Step 6. Uses default (current-thread) `#[tokio::test]` flavor for the same reason as Task 1's integration test:

```rust
/// Both new gauges must be observable via the real spawned writer task
/// once its periodic ticker has fired at least once. Uses a 1-second
/// flush interval (the minimum `flush_check_interval` clamps to) and
/// polls (bounded) rather than sleeping a fixed amount, to avoid flakiness.
#[tokio::test]
#[allow(clippy::mutable_key_type)]
async fn channel_and_buffer_gauges_appear_after_a_tick() {
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
        max_buffer_rows: 1_000_000, // nothing flushes on its own during this test
        flush_threshold_bytes: usize::MAX,
        flush_interval_secs: 1, // minimum flush_check_interval clamps to 1s
        channel_capacity: 16,
        max_partitions: 8,
    };
    let policy = FlushPolicy {
        max_rows: 1_000_000,
        max_bytes: usize::MAX,
        interval: LiveInterval::new(Duration::from_secs(1)),
    };
    let uploads = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink: Arc<dyn UploadSink> = Arc::new(SlowUploadSink {
        delay: Duration::from_millis(1),
        started: Arc::new(tokio::sync::Notify::new()),
    });
    let _ = uploads; // silence unused warning if SlowUploadSink's own fields suffice

    let (handler, _join_handle) = ParquetWriterHandle::<SimpleFastSink>::start_with_stats(
        SimpleFastSink,
        sink,
        cfg,
        policy,
        Arc::new(SourceHourlyStats::new()),
        None,
    );

    for i in 0..3 {
        handler
            .try_send(format!("record-{i}"))
            .expect("try_send must succeed on a fresh channel");
    }

    let buffer_rows_key = CompositeKey::new(
        MetricKind::Gauge,
        metrics::Key::from_parts(
            "parquet_s3_buffer_rows",
            vec![
                metrics::Label::new("source", "zeek"),
                metrics::Label::new("target", "slow"),
                metrics::Label::new("partition", "conn"),
            ],
        ),
    );
    let channel_available_key = CompositeKey::new(
        MetricKind::Gauge,
        metrics::Key::from_parts(
            "parquet_s3_channel_available",
            vec![
                metrics::Label::new("source", "zeek"),
                metrics::Label::new("target", "slow"),
            ],
        ),
    );

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut both_present = false;
    while tokio::time::Instant::now() < deadline {
        let map = snapshotter.snapshot().into_hashmap();
        both_present = map.contains_key(&buffer_rows_key) && map.contains_key(&channel_available_key);
        if both_present {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        both_present,
        "expected both parquet_s3_buffer_rows{{source=zeek,target=slow,partition=conn}} and \
         parquet_s3_channel_available{{source=zeek,target=slow}} to appear within 5s of the ticker firing"
    );
}
```

- [ ] **Step 7: Run the integration test to verify it fails, then passes**

Run: `cargo test --test buffered_writer_flush_decoupling_integration channel_and_buffer_gauges_appear_after_a_tick -- --nocapture`
Expected: FAILs before Step 5's edit is applied (the gauges are never set), PASSes after.

- [ ] **Step 8: Extend the e2e test**

In `tests/zeek_flush_decoupling_e2e.rs`, the existing test `zeek_tcp_ingest_does_not_drop_records_at_the_channel_during_a_slow_flush` already installs a `DebuggingRecorder` and a `snapshotter` at the top. After its existing `parquet_s3_dropped` assertion (the last lines of the function, around line 200-203), add:

```rust
    let buffer_rows_key = CompositeKey::new(
        MetricKind::Gauge,
        metrics::Key::from_parts(
            "parquet_s3_buffer_rows",
            vec![
                metrics::Label::new("source", "zeek"),
                metrics::Label::new("target", "slow"),
            ],
        ),
    );
    let has_buffer_rows_gauge = snapshotter
        .snapshot()
        .into_hashmap()
        .keys()
        .any(|k| k.key().name() == "parquet_s3_buffer_rows" && *k == buffer_rows_key || k.key().name() == "parquet_s3_buffer_rows");
    assert!(
        has_buffer_rows_gauge,
        "expected at least one parquet_s3_buffer_rows series with source=zeek,target=slow through the real TCP ingest path"
    );
```

Note: this test's `flush_interval_secs: 3600` (see its `cfg` literal) means the ticker fires at most once every `flush_check_interval(3600s)` = 3600s in real time — far longer than this test's ~1.5s runtime, so the ticker branch (and hence the new gauges) will NOT actually fire during this specific existing test as currently configured. **Do not just add the assertion above as-is against the unmodified config** — instead, change this one test's `flush_interval_secs` from `3600` to `1` and its `policy.interval` from `Duration::from_secs(3600)` to `Duration::from_secs(1)` (this does not affect the property the test already proves — `max_buffer_rows: 1` still drives the row-count-triggered flush the test is about; the interval only governs the unrelated ticker-driven flush path), so the ticker realistically fires at least once during the test's ~1.5s of real sleeps, then use the same bounded-poll pattern as Task 2 Step 6 (not a bare post-hoc snapshot check) to avoid flakiness:

```rust
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let mut has_buffer_rows_gauge = false;
    while tokio::time::Instant::now() < deadline {
        has_buffer_rows_gauge = snapshotter
            .snapshot()
            .into_hashmap()
            .keys()
            .any(|k| k.key().name() == "parquet_s3_buffer_rows");
        if has_buffer_rows_gauge {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        has_buffer_rows_gauge,
        "expected at least one parquet_s3_buffer_rows series through the real TCP ingest path"
    );
```

Add the necessary imports (`use metrics_util::CompositeKey;` / `MetricKind` are already imported at the top of the existing test function — reuse them, do not re-import).

- [ ] **Step 9: Run the e2e test to verify it fails, then passes**

Run: `cargo test --test zeek_flush_decoupling_e2e -- --nocapture`
Expected: FAILs before Step 5's production-code edit (or before the `flush_interval_secs` config change in Step 8) is in place, PASSes after both are applied.

- [ ] **Step 10: Run the full existing test suite for this file to confirm no regression**

Run: `cargo test --lib forwarding::buffered_writer`
Run: `cargo test --test buffered_writer_flush_decoupling_integration`
Run: `cargo test --test zeek_flush_decoupling_e2e`
Expected: all pass, including everything from Task 1 and this task.

- [ ] **Step 11: Benchmark regression check**

Run:
```bash
cargo run --release --example flush_decoupling_benchmark -- mode=realistic duration_secs=30 target_rate=4000 upload_delay_ms=150
cargo run --release --example flush_decoupling_benchmark -- mode=stress duration_secs=30 target_rate=4000 upload_delay_ms=150
```
Expected: within noise of Task 0's baseline and Task 1's readings — the new gauges are ticker-only, never on the `push()` hot path, so no throughput change expected. Append output to `docs/superpowers/specs/2026-07-24-benchmark-results-task2-gauges.md`, with a one-line comparison note.

- [ ] **Step 12: Commit**

```bash
git add src/forwarding/buffered_writer.rs tests/buffered_writer_flush_decoupling_integration.rs tests/zeek_flush_decoupling_e2e.rs docs/superpowers/specs/2026-07-24-benchmark-results-task2-gauges.md
git commit -m "feat(forwarding): add parquet_s3_channel_available and parquet_s3_buffer_rows gauges"
```

---

## Task 3: 2.2 — Remove per-record HashSet allocation in `build_extra`

**Depends on:** Task 0 only. Runs in parallel with Tasks 1/2, in a **separate worktree** (independent file, no conflict risk).

**Files:**
- Modify: `src/zeek/schema.rs`

**Interfaces:**
- Consumes: nothing from Tasks 1/2.
- Produces: nothing consumed by Tasks 1/2.

This is a behavior-preserving refactor (same membership semantics for a small static list), not new behavior — no new tests are added; existing tests are run unchanged to confirm no regression, per this project's test policy (§CLAUDE.md: modified-but-not-new behavior needs existing tests re-run, not new ones written).

- [ ] **Step 1: Confirm the current code matches the plan's assumption**

Run: `grep -n "promoted_set" src/zeek/schema.rs`
Expected output includes:
```
225:    let promoted_set: std::collections::HashSet<&str> = promoted.iter().copied().collect();
229:            if !promoted_set.contains(k.as_str()) || mismatch_keys.contains(&k.as_str()) {
```
If the line numbers or exact text differ from this, stop and re-read the function before proceeding (the file may have changed since this plan was written).

- [ ] **Step 2: Run the existing `_extra`-asserting unit tests to establish a passing baseline**

Run: `cargo test --lib zeek::schema::tests`
Expected: all pass (this establishes the pre-change baseline for this file's own test module before the edit).

- [ ] **Step 3: Make the change**

In `src/zeek/schema.rs`, `build_extra` (lines 224-235), change:

```rust
fn build_extra(value: &serde_json::Value, promoted: &[&str], mismatch_keys: &[&str]) -> String {
    let promoted_set: std::collections::HashSet<&str> = promoted.iter().copied().collect();
    let mut extra = serde_json::Map::new();
    if let Some(obj) = value.as_object() {
        for (k, v) in obj {
            if !promoted_set.contains(k.as_str()) || mismatch_keys.contains(&k.as_str()) {
                extra.insert(k.clone(), v.clone());
            }
        }
    }
    serde_json::Value::Object(extra).to_string()
}
```

to:

```rust
fn build_extra(value: &serde_json::Value, promoted: &[&str], mismatch_keys: &[&str]) -> String {
    let mut extra = serde_json::Map::new();
    if let Some(obj) = value.as_object() {
        for (k, v) in obj {
            if !promoted.contains(&k.as_str()) || mismatch_keys.contains(&k.as_str()) {
                extra.insert(k.clone(), v.clone());
            }
        }
    }
    serde_json::Value::Object(extra).to_string()
}
```

- [ ] **Step 4: Run the same unit tests again to confirm identical pass results**

Run: `cargo test --lib zeek::schema::tests`
Expected: all pass, identical set of passing tests to Step 2 (proves the change is behavior-preserving).

- [ ] **Step 5: Run the integration and e2e tests that exercise `build_extra` transitively**

Run: `cargo test --test zeek_local_integration`
Run: `cargo test --test zeek_s3_integration`
Run: `cargo test --test zeek_flush_decoupling_e2e`
Expected: all pass unchanged.

- [ ] **Step 6: Benchmark — attribution check (this is the one item with a plausible measurable hot-path effect)**

Run each mode twice:
```bash
cargo run --release --example flush_decoupling_benchmark -- mode=realistic duration_secs=30 target_rate=4000 upload_delay_ms=150
cargo run --release --example flush_decoupling_benchmark -- mode=realistic duration_secs=30 target_rate=4000 upload_delay_ms=150
cargo run --release --example flush_decoupling_benchmark -- mode=stress duration_secs=30 target_rate=4000 upload_delay_ms=150
cargo run --release --example flush_decoupling_benchmark -- mode=stress duration_secs=30 target_rate=4000 upload_delay_ms=150
```
Compare all 4 runs against Task 0's 4 baseline runs (same modes). Write `docs/superpowers/specs/2026-07-24-benchmark-results-task3-hashset-removal.md` containing: all 4 new runs' full output, and an explicit comparison table against Task 0's baseline figures (records_written, dropped, buffer_dropped, measured throughput) with a plain-language verdict — "regression", "no meaningful change", or "measurable improvement", stated honestly even if the delta is within noise (do not claim an improvement smaller than the observed baseline-to-baseline variance from Task 0's own two runs per mode).

- [ ] **Step 7: Commit**

```bash
git add src/zeek/schema.rs docs/superpowers/specs/2026-07-24-benchmark-results-task3-hashset-removal.md
git commit -m "perf(zeek): remove per-record HashSet allocation in build_extra"
```

---

## Task 4: Merge, final combined benchmark, and summary

**Depends on:** Task 2 and Task 3 both complete (merge both branches/worktrees back into `perf/do-next-items`).

**Files:**
- Create: `docs/superpowers/specs/2026-07-24-benchmark-results-summary.md`

- [ ] **Step 1: Merge both lines of work into `perf/do-next-items`**

Merge the Task 1+2 worktree branch and the Task 3 worktree branch into `perf/do-next-items` (no file overlap between them, so this should be a clean fast-forward or trivial merge — if it is not clean, stop and investigate before forcing anything).

- [ ] **Step 2: Run the full test suite**

Run: `cargo test`
Expected: all tests pass, across the whole crate, with all 3 items' changes present together.

- [ ] **Step 3: Run `cargo clippy` to confirm no new lints**

Run: `cargo clippy --all-targets -- -D warnings`
Expected: clean (matches this project's existing clippy discipline — see recent commit `3d8a927 style: fix clippy collapsible_if in flush_decoupling_benchmark`).

- [ ] **Step 4: Final combined benchmark run**

Run both modes once each:
```bash
cargo run --release --example flush_decoupling_benchmark -- mode=realistic duration_secs=30 target_rate=4000 upload_delay_ms=150
cargo run --release --example flush_decoupling_benchmark -- mode=stress duration_secs=30 target_rate=4000 upload_delay_ms=150
```

- [ ] **Step 5: Write the summary doc**

Create `docs/superpowers/specs/2026-07-24-benchmark-results-summary.md` consolidating: the baseline (Task 0), the per-item regression/attribution checks (Tasks 1, 2, 3), and this final combined run — one table per mode (realistic/stress) with columns for baseline / after-2.7 / after-2.4 / after-2.2 / final-combined, and a one-paragraph plain-language conclusion.

- [ ] **Step 6: Commit**

```bash
git add docs/superpowers/specs/2026-07-24-benchmark-results-summary.md
git commit -m "docs: summarize benchmark results across all 3 do-next items"
```

---

## Self-Review Notes

- **Spec coverage:** every requirement in `2026-07-24-perf-do-next-items-design.md` maps to a task: 2.7 → Task 1, 2.4 → Task 2, 2.2 → Task 3, benchmarking cadence (baseline / per-item / final) → Tasks 0/1/2/3/4, the WEF cardinality known-limitation → already documented in the design spec itself (no code task needed, per that spec's own explicit decision not to build in-change mitigation).
- **Dead-code sites (1032, 1053):** explicitly not tested, with an explicit in-code comment explaining why, per Task 1 Step 8 — matches CLAUDE.md's "say so explicitly rather than skipping silently."
- **Type/name consistency:** `update_buffer_gauges(&self)` (Task 2 Step 3) is the same signature referenced in Task 2 Step 5's ticker-branch wiring and Task 2 Step 1's unit test. `PanicUploadSink`/`CaptureLayer`/`CapturedEvent`/`FieldVisitor`/`TestTracingCapture` are deliberately redefined per-file (Task 1 Step 1 for the in-lib unit tests, Task 1 Step 6 for the integration test) rather than shared, matching this codebase's existing fixture-duplication convention.
