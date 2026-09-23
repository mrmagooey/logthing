# Review fixes (2026-09-22) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the four verified defects from the 2026-09-22 codebase review: a Zeek flush that jams, unmetered record skips, WEF batch truncation, and TCP accept spin.

**Architecture:** Four independent, small changes, landed strictly in order Task 1 → 2 → 3 → 4, each as its own commit series on `fix/review-2026-09-22`. Each task fixes the root cause in a shared function (not per caller) and carries unit, integration and e2e tests.

**Tech Stack:** Rust 2024, tokio, axum, arrow/parquet 53, quick-xml 0.31, `metrics` 0.22 (+ `metrics-util` debugging recorder in tests), libc.

**Spec:** `docs/superpowers/specs/2026-09-22-review-fixes-design.md`

## Global Constraints

- Work ONLY in the worktree `/home/dev/projects/logthing-fix-review` on branch `fix/review-2026-09-22`. Never touch `master` or `/home/dev/projects/logthing`.
- Build env (both linker lines are required): `source ~/.cargo/env; export CC=/usr/bin/gcc CXX=/usr/bin/g++ CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc CARGO_TARGET_DIR=/home/dev/projects/logthing/target`
- Run every cargo command in the FOREGROUND and let the Bash call block (use timeout 600000). Never background a build and poll for it. To check whether cargo is still running use exactly `ps -eo comm | grep -c "^cargo$"` (never `pgrep -f`, which matches itself).
- Before finishing a task: `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, and the task's tests plus `cargo test --lib` must all be green.
- Every new metric needs a HELP entry in `src/metrics_descriptions.rs` `DESCRIPTIONS`; the guard tests `describes_every_metric_emitted_in_src` / `stale_descriptions_do_not_accumulate` enforce this.
- Metric labels must be `&'static str` from a fixed set, never wire-derived.
- Tests that install a global metrics recorder (`Server::run`, `set_global_recorder`) must be the ONLY `#[tokio::test]` in their test file.
- Follow AGENTS.md: 100-column lines, `///` docs on public items, `#[derive(Debug)]`, conventional commits.
- Commit trailer (required on every commit):
  ```
  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01Xsi6CGg4qvtb6NWh87KYGY
  ```
- Do not touch: `FlushIntervalRegistry`, `*_start`/`*_local_start` pairs, Kerberos layer ordering, the aggregate 2 s sleep.
- Verify each regression test by mutation: temporarily revert the fix, confirm the test FAILS, then restore. Report this in the task summary.

## Review Focus

1. Zeek `_path` with mixed case AND a rotation suffix (`"CONN.2026-08-14-16-08-44"`) must land in the typed conn schema: Task 1, `get_schema_entry_resolves_case_and_rotation_variants`.
2. Non-ASCII / hostile `_path` (`"Ｃonn"`, `"../Conn"`, `""`) must never panic and must resolve to the envelope unless the sanitized key is a real registry key: Task 1, same test.
3. A WEF batch whose FIRST event is malformed (nothing parsed yet) must keep the whole body from that event onward as raw: Task 3, `parse_events_error_in_first_event_keeps_everything_raw`.
4. A WEF batch whose events all parse but has trailing junk after the last `</Event>` (e.g. `</Events></Bogus>`) must NOT produce a spurious raw event: Task 3, `parse_events_trailing_junk_after_last_event_adds_no_raw_row`. (Refinement of the spec: when the error is outside any event and the remainder contains no `<Event` substring, there is no event data to keep.)
5. While an accept pause is active, a `select!` shutdown arm must still end the listener promptly: Task 4, `accept_backoff_pause_does_not_block_other_select_arms`.

---

### Task 1: Zeek `_path` case mismatch (spec #1)

**Files:**
- Modify: `src/zeek/schema.rs` (`get_schema_entry`, ~line 1788; tests module)
- Modify: `src/forwarding/buffered_writer.rs` (`PartitionedParquetWriter::push`, the two `Ok(b) => { ... buf.buffer.push_back(...) }` arms at ~1007-1014 and ~1041-1046)
- Modify: `src/forwarding/zeek_s3.rs` tests (~line 785, `mismatched_raw_log_path_falls_back_to_envelope_not_conn_accumulator`)
- Create: `tests/zeek_mixed_case_path_e2e.rs`

**Interfaces:**
- Consumes: `crate::forwarding::buffered_writer::sanitize_log_path(&str) -> String` (pub(crate)).
- Produces: `get_schema_entry` now resolves `sanitize_log_path(raw)` keys; `push()` rejects sink batches whose `schema()` differs from the buffer schema (Task 2 re-routes that rejection through its helper).

- [ ] **Step 1: Write the failing unit test** in `src/zeek/schema.rs` `mod tests`:

```rust
#[test]
fn get_schema_entry_resolves_case_and_rotation_variants() {
    let conn = get_schema_entry("conn");
    for raw in ["Conn", "CONN", "cOnN"] {
        assert!(
            Arc::ptr_eq(&get_schema_entry(raw).schema, &conn.schema),
            "{raw} must resolve to the typed conn schema"
        );
    }
    // The listener runs normalize_log_path first; the pair must compose.
    let rotated = crate::zeek::normalize_log_path("CONN.2026-08-14-16-08-44");
    assert!(Arc::ptr_eq(&get_schema_entry(rotated).schema, &conn.schema));
    // Hostile / non-ASCII inputs: no panic, envelope unless the sanitized key is real.
    for raw in ["Ｃonn", "../Conn", "", "weird"] {
        let e = get_schema_entry(raw);
        assert!(e.schema.field_with_name("payload").is_ok(), "{raw:?} must be envelope");
    }
}
```

(If `REGISTRY` entries are rebuilt per call rather than shared `Arc`s, compare `*a.schema == *b.schema` instead of `Arc::ptr_eq`; check `REGISTRY`'s definition first.)

- [ ] **Step 2: Run it and confirm it fails.** `cargo test --lib get_schema_entry_resolves_case_and_rotation_variants`. Expected: FAIL on `"Conn"`.

- [ ] **Step 3: Implement the root fix** in `get_schema_entry`:

```rust
pub fn get_schema_entry(log_path: &str) -> Arc<SchemaEntry> {
    if let Some(entry) = REGISTRY.get(log_path) {
        return entry.clone();
    }
    // `ZeekSink::partition()` keys buffers by `sanitize_log_path`, so resolve
    // the mapper by that same key: `"Conn"` must map with the conn schema its
    // buffer holds, not the envelope, or the buffer can never flush.
    if let Some(entry) = REGISTRY.get(sanitize_log_path(log_path).as_str()) {
        return entry.clone();
    }
    // For unknown paths, build a fresh SchemaEntry with the actual log_path captured.
    let path = log_path.to_string();
    Arc::new(SchemaEntry {
        schema: envelope_schema(),
        mapper: Arc::new(move |v, received_at| map_envelope(v, &path, received_at)),
    })
}
```

Add `use crate::forwarding::buffered_writer::sanitize_log_path;` with the other internal imports. Update the doc comment above the function to mention the sanitized fallback.

- [ ] **Step 4: Run the unit test.** Expected: PASS.

- [ ] **Step 5: Write the failing push-guard unit test** in `buffered_writer.rs` `mod tests`. Use the existing test helpers there (`test_schema()` at ~2297 and the test `ParquetSink` impls near it; read them first). Add a tiny sink whose `schema()` returns `test_schema()` but whose `to_record_batch` returns a batch built with a DIFFERENT schema (e.g. one `Int64` column `"other"`), and whose `new_batch` returns `None`. Push one record and assert:

```rust
let buf = writer.buffer_by_partition("").expect("buffer exists");
assert_eq!(buf.buffer.len(), 0, "a batch whose schema differs from the buffer's must not be buffered");
assert_eq!(buf.row_count, 0);
```

and that `writer.flush_all().await` returns `Ok` (nothing poisoned). Run it: expected FAIL (the batch is buffered today).

- [ ] **Step 6: Implement the guard** in both mapped-batch arms of `push()`:

```rust
Ok(b) if b.schema() != schema => {
    // A sink handed back a batch that doesn't match this buffer's schema.
    // Buffering it would make every later flush of this buffer fail in
    // `concat_batches` and retry forever, so skip just this record.
    tracing::warn!(
        source = self.sink.source(),
        "record batch schema does not match buffer schema, skipping record"
    );
    return Ok(());
}
```

placed before the existing `Ok(b) => { ... }` arm. `Arc<Schema>` equality short-circuits on pointer identity (`Schema: Eq`), so this costs ~nothing on the normal path. Task 2 replaces this `warn!` with the shared skip helper.

- [ ] **Step 7: Audit every sink.** For each `impl ParquetSink for` (`grep -rn "impl ParquetSink for" src`), confirm `to_record_batch` / `day_and_batch` build batches with the `schema` argument (or `RecordBatch::try_new(schema.clone(), ..)`), so the guard never rejects legitimate records. Run `cargo test --lib forwarding::` and `cargo test --test '*_integration'`. Expected: all green. Any failure here means an adapter builds an equal-but-different schema: fix the adapter to use the passed `schema`, not the guard.

- [ ] **Step 8: Extend the existing zeek test into a flush regression.** Rename `mismatched_raw_log_path_falls_back_to_envelope_not_conn_accumulator` (zeek_s3.rs ~785) to `mixed_case_log_path_joins_conn_buffer_and_flushes`. Use a `LocalDiskSink` on a `tempfile::tempdir()` (pattern: `zeek_local_start_wires_handler_and_join_handle`, ~933). Push one `"conn"` and one `"Conn"` record, `flush_all().await.unwrap()`, `drain_pending_flushes().await`, then read every Parquet file under `zeek/conn/` with `parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder` and assert the total row count == 2 and the schema has `_extra` (typed conn), and that the conn buffer is empty after the flush. Mutation-check: revert Step 3 and confirm this test fails.

- [ ] **Step 9: Write the e2e test** `tests/zeek_mixed_case_path_e2e.rs`: real `ZeekListener` (config pattern from `tests/zeek_received_metric_e2e.rs`, `reserve_port()` helper) with a `zeek_local_start` handler writing to a tempdir via `MultiZeekHandler`. Send over real TCP three NDJSON lines with `_path` `"conn"`, `"Conn"`, `"CONN.2026-08-14-16-08-44"`, close the socket, drop the handler, await the writer join handle (5 s timeout), then assert the Parquet files under `zeek/conn/` hold exactly 3 rows. No global recorder is needed, so no Server.

- [ ] **Step 10: Full verification** (fmt, clippy, `cargo test --lib`, the new e2e, `cargo test --test zeek_local_integration --test zeek_s3_integration`). Commit:

```bash
git add src/zeek/schema.rs src/forwarding/buffered_writer.rs src/forwarding/zeek_s3.rs tests/zeek_mixed_case_path_e2e.rs
git commit -m "fix(zeek): resolve schema by sanitized _path so mixed-case paths can't jam a flush"
```

---

### Task 2: Count and throttle `push()` record skips (spec #4)

**Files:**
- Modify: `src/forwarding/buffered_writer.rs` (`PartitionedParquetWriter` struct ~789, its constructors ~847/864, `push()` skip branches ~952, ~1015, ~1024, ~1046 and the Task 1 guard arms)
- Modify: `src/metrics_descriptions.rs`
- Create: `tests/parquet_records_skipped_integration.rs`

**Interfaces:**
- Consumes: Task 1's guard arms in `push()`.
- Produces: counter `parquet_s3_records_skipped{source,target}`; private `fn record_skipped(&mut self, reason: &'static str, err: &dyn std::fmt::Display)`.

- [ ] **Step 1: Write the failing unit test** in `buffered_writer.rs` tests: a sink whose `to_record_batch` always returns `Err(anyhow!("boom"))` and `new_batch` returns `None`. Under a `DebuggingRecorder` installed with `metrics::set_default_local_recorder` (pattern: `handler_overflow_increments_dropped_counter` in `zeek_s3.rs` ~825), push 3 records and assert the counter `parquet_s3_records_skipped{source=<sink source>,target=<label>}` == 3. Also assert `writer.last_skip_warn` is `Some` after the first push and the SAME `Instant` after the third (throttled). Run: expected FAIL (compile error / counter missing).

- [ ] **Step 2: Implement.** Add to the struct:

```rust
/// When `record_skipped` last logged; gates its warn line to one per 30 s.
last_skip_warn: Option<Instant>,
/// Records `push()` could not buffer over this writer's lifetime.
skipped_total: u64,
```

initialize both (`None`, `0`) in every constructor, and add:

```rust
/// Count one record `push()` could not buffer, logging at most every 30 s.
/// Same cadence as `drop_oldest_to_cap`'s `last_drop_warn`: a per-record
/// unthrottled warn on this path is what `drop_log.rs` measured at ~21% of
/// ingest throughput.
fn record_skipped(&mut self, reason: &'static str, err: &dyn std::fmt::Display) {
    let source = self.sink.source();
    let target = self.s3.target_label();
    metrics::counter!("parquet_s3_records_skipped", "source" => source, "target" => target)
        .increment(1);
    self.skipped_total += 1;
    if self.last_skip_warn.is_none_or(|t| t.elapsed().as_secs() >= 30) {
        tracing::warn!(
            source,
            target,
            skipped_total = self.skipped_total,
            "parquet_s3: skipping record ({reason}): {err}"
        );
        self.last_skip_warn = Some(Instant::now());
    }
}
```

Replace each of the four skip branches' `tracing::warn!(...); return Ok(());` with `self.record_skipped("<reason>", &e); return Ok(());`, using reasons `"day_and_batch failed"`, `"to_record_batch failed"`, `"live builder append failed"`. Replace Task 1's guard warn with `self.record_skipped("schema mismatch", &"batch schema differs from buffer schema"); return Ok(());`. If the borrow checker objects because `buf` is still borrowed, end the `buf` borrow first (each branch returns immediately, so NLL normally allows it); do not clone buffers to work around it.

Add to `DESCRIPTIONS` in `src/metrics_descriptions.rs`, next to `parquet_s3_dropped`:

```rust
(
    "parquet_s3_records_skipped",
    "Records the writer could not convert into its buffer's schema and skipped.",
),
```

- [ ] **Step 3: Run the unit test plus the metrics guard tests.** `cargo test --lib records_skipped metrics_descriptions`. Expected: PASS.

- [ ] **Step 4: Integration test** `tests/parquet_records_skipped_integration.rs`: if the failing test sink from Step 1 isn't reachable from `tests/` (crate-private), put this test in `buffered_writer.rs` tests instead and name it `*_integration_*`. Use a real `LocalDiskSink` on a tempdir and a sink that fails `to_record_batch` for records flagged bad but maps good ones normally. Push good, bad, good; flush; assert the Parquet on disk has exactly 2 rows and the counter == 1.

- [ ] **Step 5: E2E decision.** After Task 1 no wire input reaches these branches (every production adapter's `to_record_batch` is total). Record this in the commit body: "e2e: not applicable — no outer-interface input can trigger a skip after the Zeek fix; covered at unit + integration level." Do NOT add production code to create a trigger.

- [ ] **Step 6: Verify and commit** (fmt, clippy, `cargo test --lib`):

```bash
git commit -am "fix(forwarding): count and throttle records skipped in push()"
```

(`git add` the new test file first if one was created.)

---

### Task 3: WEF batch keeps the remainder on XML error (spec #2)

**Files:**
- Modify: `src/protocol/mod.rs` (`parse_events` `Err` arm ~170; tests module)
- Modify: `src/metrics_descriptions.rs`
- Create: `tests/wef_malformed_batch_integration.rs`, `tests/wef_malformed_batch_e2e.rs`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: counter `wef_xml_parse_errors` (no labels); `parse_events` never drops unparsed input.

- [ ] **Step 1: Write the failing unit tests** in `src/protocol/mod.rs` tests (helper builds `<Envelope><Body><Events>{events}</Events></Body></Envelope>`; event `n` = `<Event><System><Provider>P</Provider><EventID>{n}</EventID><Level>4</Level></System></Event>`; the malformed event inserts `</Mismatch>` inside `<System>`):

```rust
#[test]
fn parse_events_malformed_middle_event_keeps_remainder_raw() {
    // events 1 ok, 2 malformed, 3 ok
    let WefMessage::Events(ev) = parser.parse_message(&body, "h".into()).unwrap() else { panic!() };
    assert_eq!(ev.len(), 2);
    assert!(ev[0].raw_xml.contains("<EventID>1</EventID>"));
    assert!(ev[1].raw_xml.contains("</Mismatch>"));
    assert!(ev[1].raw_xml.contains("<EventID>3</EventID>"), "events after the error must be kept");
}

#[test]
fn parse_events_error_in_first_event_keeps_everything_raw() {
    // event 1 malformed, 2 ok -> one raw event containing both EventIDs
}

#[test]
fn parse_events_trailing_junk_after_last_event_adds_no_raw_row() {
    // events 1, 2 ok, then "</Events></Bogus></Body></Envelope>" -> exactly 2 events
}
```

Write all three concretely (full bodies, `assert_eq!` on lengths and `contains` checks as above). Check that `WindowsEvent`'s raw field is `raw_xml` (src/models) and adjust if not. Run: expected FAIL on the first two.

- [ ] **Step 2: Implement** the `Err` arm of `parse_events`:

```rust
Err(e) => {
    metrics::counter!("wef_xml_parse_errors").increment(1);
    error!("XML parsing error: {}", e);
    // The handler acks this batch with 200, so the forwarder will never
    // resend it: keep everything not yet emitted as one raw event instead
    // of dropping it. Outside an event, a remainder with no `<Event` in it
    // is envelope junk with no event data to keep.
    let from = if in_event { event_start_pos.unwrap_or(pos) } else { pos };
    if let Some(rest) = body.get(from..)
        && !rest.trim().is_empty()
        && (in_event || rest.contains("<Event"))
    {
        events.push(WindowsEvent::new(source_host.clone(), rest.to_string()));
    }
    break;
}
```

(`body.get` instead of indexing: quick-xml positions are markup boundaries, but this path is attacker-reachable and must not panic.) Add HELP to `DESCRIPTIONS`:

```rust
(
    "wef_xml_parse_errors",
    "WEF batches whose XML failed to parse; the unparsed remainder is kept as one raw event.",
),
```

- [ ] **Step 3: Run the unit tests.** Expected: PASS. Mutation-check by restoring the old `break`-only arm.

- [ ] **Step 4: Integration test** `tests/wef_malformed_batch_integration.rs`: `WefParser::new().parse_message(malformed_body, ..)` → push every resulting `WindowsEvent` through `wef_local_start` (pattern: `tests/wef_local_integration.rs`) → drop the handler, await the join handle → read the Parquet and assert the total row count == 2 and one row's raw XML column contains `<EventID>3</EventID>`.

- [ ] **Step 5: E2E test** `tests/wef_malformed_batch_e2e.rs` (single `#[tokio::test]`): real `Server` with metrics enabled and a WEF local destination, following `tests/field_cardinality_metric_wef_e2e.rs` for setup, `reserve_port`, and the `/wsman/events` POST. POST the malformed 3-event batch → assert HTTP 200; scrape `/metrics` and assert `wef_xml_parse_errors` == 1; shut down and assert the local Parquet contains a row whose raw XML contains `<EventID>3</EventID>`.

- [ ] **Step 6: Verify and commit:**

```bash
git add src/protocol/mod.rs src/metrics_descriptions.rs tests/wef_malformed_batch_integration.rs tests/wef_malformed_batch_e2e.rs
git commit -m "fix(wef): keep the unparsed remainder of a batch as raw on XML error"
```

---

### Task 4: Back off TCP accept loops on persistent errors (spec #3)

**Files:**
- Modify: `src/net.rs` (add `AcceptBackoff`, `ACCEPT_ERROR_BACKOFF`, `is_connection_error`; tests)
- Modify: `src/syslog/listener.rs` (accept sites ~436, ~541, ~759, ~1031)
- Modify: `src/zeek/listener.rs` (~231, ~289)
- Modify: `src/suricata/listener.rs` (~258, ~316)
- Modify: `src/metrics_descriptions.rs`
- Create: `tests/accept_backoff_emfile_integration.rs`, `tests/accept_backoff_emfile_e2e.rs`

**Interfaces:**
- Produces: `pub struct AcceptBackoff`, `AcceptBackoff::new(protocol: &'static str) -> Self`, `pub async fn accept(&mut self, listener: &tokio::net::TcpListener) -> std::io::Result<(tokio::net::TcpStream, std::net::SocketAddr)>`, `pub const ACCEPT_ERROR_BACKOFF: Duration`, counter `listener_accept_errors{protocol}`.

- [ ] **Step 1: Write failing unit tests** in `src/net.rs` tests:

```rust
#[test]
fn is_connection_error_matches_per_connection_kinds_only() {
    use std::io::{Error, ErrorKind};
    for k in [ErrorKind::ConnectionRefused, ErrorKind::ConnectionAborted, ErrorKind::ConnectionReset] {
        assert!(is_connection_error(&Error::from(k)));
    }
    assert!(!is_connection_error(&Error::from_raw_os_error(libc::EMFILE)));
    assert!(!is_connection_error(&Error::from_raw_os_error(libc::ENFILE)));
}

#[tokio::test(start_paused = true)]
async fn accept_backoff_pause_survives_cancellation() {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut b = AcceptBackoff::new("test");
    b.paused_until = Some(tokio::time::Instant::now() + ACCEPT_ERROR_BACKOFF);
    // Cancelled mid-pause (as a select! would): pause must persist.
    let r = tokio::time::timeout(Duration::from_millis(500), b.accept(&l)).await;
    assert!(r.is_err(), "accept must still be paused");
    assert!(b.paused_until.is_some(), "a dropped future must not clear the pause");
}

#[tokio::test(start_paused = true)]
async fn accept_backoff_pause_does_not_block_other_select_arms() {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut b = AcceptBackoff::new("test");
    b.paused_until = Some(tokio::time::Instant::now() + ACCEPT_ERROR_BACKOFF);
    let (tx, mut rx) = tokio::sync::watch::channel(false);
    tx.send(true).unwrap();
    let start = tokio::time::Instant::now();
    tokio::select! {
        _ = b.accept(&l) => panic!("accept must not win while paused"),
        _ = rx.changed() => {}
    }
    assert!(start.elapsed() < Duration::from_millis(100));
}
```

Run: expected FAIL (types missing).

- [ ] **Step 2: Implement** in `src/net.rs` (keep the imports per AGENTS.md ordering; `std::io` is already imported around line 90, so make sure it isn't behind a platform `cfg` that would hide it from this code):

```rust
/// Pause before the next `accept` after a non-per-connection accept error.
pub const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_secs(1);

/// `TcpListener::accept` wrapper that stops a listener spinning on a
/// persistent accept error.
///
/// Errors like EMFILE leave the listener readable, so re-polling `accept()`
/// returns the same error at once: a 100% CPU loop with a log line per spin.
/// After such an error the next `accept` first waits out
/// [`ACCEPT_ERROR_BACKOFF`]. Per-connection errors (refused/aborted/reset)
/// don't pause, matching `axum::serve`.
///
/// Cancel-safe: the pause is cleared only after its sleep completes, so a
/// `select!` that drops this future mid-pause resumes the same pause on the
/// next call, while the other arms (UDP receive, shutdown) stay live.
#[derive(Debug)]
pub struct AcceptBackoff {
    protocol: &'static str,
    paused_until: Option<tokio::time::Instant>,
}

impl AcceptBackoff {
    /// `protocol` labels `listener_accept_errors`; use the same value as the
    /// site's `listener_source_rejected` label.
    pub fn new(protocol: &'static str) -> Self {
        Self { protocol, paused_until: None }
    }

    /// Accept one connection, honouring any pending pause first.
    pub async fn accept(
        &mut self,
        listener: &tokio::net::TcpListener,
    ) -> io::Result<(tokio::net::TcpStream, SocketAddr)> {
        if let Some(until) = self.paused_until {
            tokio::time::sleep_until(until).await;
            self.paused_until = None;
        }
        let result = listener.accept().await;
        if let Err(e) = &result {
            metrics::counter!("listener_accept_errors", "protocol" => self.protocol).increment(1);
            if !is_connection_error(e) {
                self.paused_until = Some(tokio::time::Instant::now() + ACCEPT_ERROR_BACKOFF);
            }
        }
        result
    }
}

fn is_connection_error(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    )
}
```

HELP entry:

```rust
(
    "listener_accept_errors",
    "TCP accept errors per listener; non-per-connection errors (e.g. fd exhaustion) pause accepts for 1s.",
),
```

- [ ] **Step 3: Run the unit tests.** Expected: PASS.

- [ ] **Step 4: Wire all eight sites.** At each loop: create `let mut accept_backoff = crate::net::AcceptBackoff::new("<label>");` before the `loop`, and replace `listener.accept()` / `tcp_listener.accept()` with `accept_backoff.accept(&listener)` (in `select!` arms: `result = accept_backoff.accept(&tcp_listener) => {`). Labels: syslog sites `"syslog_tcp"`, zeek `"zeek"`, suricata `"suricata"` (confirm against each site's `listener_source_rejected` label). Leave the existing `Err(e) => { error!(...) }` bodies unchanged: the pause now bounds them to about 1/s. Verify with `grep -n '\.accept()' src/syslog/listener.rs src/zeek/listener.rs src/suricata/listener.rs`, which must list only test code afterwards.

- [ ] **Step 5: Integration test** `tests/accept_backoff_emfile_integration.rs`, single test, `#[tokio::test(flavor = "current_thread")]`:
  1. Install a `DebuggingRecorder` with `metrics::set_global_recorder` (keep its snapshotter).
  2. Bind a `TcpListener` on 127.0.0.1:0 and spawn a loop `loop { let _ = backoff.accept(&l).await; }` holding accepted streams in a Vec (so they keep fds).
  3. Lower `RLIMIT_NOFILE` soft limit with `libc::setrlimit` to the current open-fd count (`std::fs::read_dir("/proc/self/fd").count()`) + 8, then open `/dev/null` repeatedly until EMFILE, close exactly ONE, and `std::net::TcpStream::connect` to the listener (the client takes that last fd; the kernel completes the handshake, so the server's accept hits EMFILE).
  4. Sleep 2.5 s real time; read `listener_accept_errors{protocol="test"}`: assert `1 <= n <= 4`. Without the fix this is thousands; mutation-check by making `accept` skip setting `paused_until`.
  5. Drop the `/dev/null` handles; within 3 s assert a new client connection is accepted (e.g. the accepted-streams count grows via an `Arc<AtomicUsize>`).

- [ ] **Step 6: E2E test** `tests/accept_backoff_emfile_e2e.rs`, single test, spawning the real binary (pattern: `tests/listener_ip_whitelist_e2e.rs`: toml in a tempdir, `ChildGuard`, `wait_for_tcp`) with only `[syslog]` TCP enabled plus metrics. Give the child a low fd limit via `std::os::unix::process::CommandExt::pre_exec` calling `libc::setrlimit(RLIMIT_NOFILE, 256)`. Open TCP connections to the syslog TCP port until connects stop being accepted (the server has run out of fds: it holds one per accepted connection; the kernel backlog still completes handshakes). Then sample the child's CPU from `/proc/<pid>/stat` (fields 14+15, utime+stime in clock ticks, `libc::sysconf(libc::_SC_CLK_TCK)`) at t0 and t0+2 s: assert CPU used < 25% of wall time. Without the fix this is ~100%; mutation-check it. Close the held connections and assert a fresh connection plus one syslog line is accepted (`syslog_messages_received` on `/metrics` increases) within 5 s. If the syslog TCP connection semaphore (`MAX_SYSLOG_TCP_CONNECTIONS`) is below 256, lower the child limit below it instead so fd exhaustion, not the semaphore, is what stops accepts.

- [ ] **Step 7: Verify and commit:**

```bash
git add src/net.rs src/syslog/listener.rs src/zeek/listener.rs src/suricata/listener.rs src/metrics_descriptions.rs tests/accept_backoff_emfile_integration.rs tests/accept_backoff_emfile_e2e.rs
git commit -m "fix(net): back off TCP accept loops after persistent accept errors"
```

---

## After all tasks

- Add a `## [Unreleased]` CHANGELOG entry listing the four fixes and the three new metrics, and update AGENTS.md/README only if they list metrics. Commit as `docs:`.
- Run the full `cargo test` (all targets) once on the branch tip.
- Hand the merge decision to the user; do not merge to master.
