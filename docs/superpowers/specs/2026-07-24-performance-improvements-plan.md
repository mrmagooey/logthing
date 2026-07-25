# Performance Improvements Plan — Post Flush-Decoupling

**Date:** 2026-07-24
**Status:** Draft — for review
**Related:** [2026-07-24-decoupled-flush-buffered-writer-design.md](2026-07-24-decoupled-flush-buffered-writer-design.md) (the fix this plan follows on from, `BENCHMARK_RESULTS.md` at repo root for its throughput measurements); [2026-07-05-performance-testing-strategy-design.md](2026-07-05-performance-testing-strategy-design.md) (unimplemented perf-testing-harness draft, partially superseded — see §0); [2026-06-23-generic-buffered-writer-design.md](2026-06-23-generic-buffered-writer-design.md) (the writer's original design, source of the "single-row batches are the baseline" note this plan's top candidate follows up on).

## 0. What changed since the two source documents were written

Both leads named in this task's brief needed a status check against current `master` (tag `v0.9.0`) before being evaluated, and both turned out to be partially stale:

- **`LocalDiskSink` per-source wiring.** The 2026-07-05 draft states "`LocalDiskSink` is only wired for Zeek so far" and treats wiring the other 6 sources as a prerequisite work item. This is no longer true. `git log` shows the remaining sources landed afterward: `feat(config): add WefLocalConfig` / `feat(forwarding): add wef_local_start` / `feat(server): wire wef.local construction` (WEF), and the equivalent `hec_local_start` + `feat(server): wire hec.local construction, OTLP dispatch` commits (HEC/generic, which OTLP rides on top of via `map_otlp_request` → `GenericRecord`). Verified directly: `src/main.rs` wires `.local` for syslog (144), ipfix (241), zeek (313), suricata (385), sflow (461); `src/server/mod.rs` wires it for wef (224) and hec (286). All 7 sources have a `.local` path today. **This item is done — nothing to plan here.**
- **Buffer/channel observability.** The task brief's lead #2 (gauges for buffer occupancy / channel depth) partially exists already: `parquet_s3_flushes_in_flight{source,target}` (a gauge) was added by the flush-decoupling fix itself (`src/forwarding/buffered_writer.rs:602,633`). What's still missing is occupancy/queue-depth, not in-flight-flush-count — see §2.1.

Everything else in both source documents (the criterion/`tools/loadgen` harness, the per-format cost-profile table, the Prometheus metrics inventory) is still accurate and still unimplemented — confirmed by `grep -c criterion Cargo.toml` (0 matches) and `ls benches/` (does not exist).

## 1. Method

Every candidate below is grounded in something read directly in this session: a specific file/line, a specific measurement in `BENCHMARK_RESULTS.md`, or a specific commit. Candidates without that grounding are listed in §5 as "considered, no evidence found" rather than included as recommendations. Each candidate gets an explicit verdict — do next, worth doing eventually, or declined — not just a description.

## 2. Candidates

### 2.1 Batch multiple records per `RecordBatch` instead of one-row-per-batch — **Tier: worth doing eventually (needs its own design spec first)**

**What it is.** Every `ParquetSink::to_record_batch` implementation is called once per `push()` — i.e., once per ingested record — and constructs a **fresh set of Arrow `*Builder`s, appends exactly one value to each, and immediately `.finish()`s them** into a single-row `RecordBatch`. Confirmed systemic, not Zeek-specific:

| File | `Builder::new()` call sites |
|---|---:|
| `src/zeek/schema.rs` | 85 |
| `src/forwarding/sflow_s3.rs` | 26 |
| `src/forwarding/ipfix_s3.rs` | 18 |
| `src/suricata/schema.rs` | 4 (+ shared helpers) |

Concretely, `map_conn` (`src/zeek/schema.rs:241-382`) allocates 16 builders (`Float64Builder`, `StringBuilder` ×10, `UInt16Builder` ×2, `UInt64Builder` ×3) to encode **one** conn record, then at flush time `encode_and_upload` (`src/forwarding/buffered_writer.rs:758,766`) clones every buffered single-row batch into a `Vec<RecordBatch>` and merges up to `max_buffer_rows` (100,000 by default) of them via `arrow::compute::concat_batches` in one `spawn_blocking` call. The buffered-writer design doc itself flags this as deliberate but temporary: *"An adapter may batch multiple records per `RecordBatch` later as an optimization, but single-row batches preserve current behavior and are the baseline"* (`docs/superpowers/specs/2026-06-23-generic-buffered-writer-design.md:66`).

**Why it matters.** This session's benchmark work measured real `ZeekSink::to_record_batch` cost (the per-`push()` cost, independent of the writer/flush machinery) at **~500µs–1.3ms per record** — this is the dominant per-record cost in the whole ingest path for Zeek, well above the writer/channel overhead the flush-decoupling fix targeted. At the production-default 4,000 rec/s sustained load the benchmark used, that per-record cost is the actual throughput ceiling long before the writer's channel or flush machinery becomes the bottleneck. Batching N records into one shared set of builders (append N times, finish once) instead of allocating+finishing per record would amortize builder-allocation cost across N records and eliminate `concat_batches`'s O(total buffered rows) merge work at flush time (which currently re-copies every column's data once per flush purely to stitch single-row batches back together).

**Scope/effort.** This is **not** a small change: `ParquetSink::to_record_batch(&self, record: &Self::Record, schema: &Arc<Schema>) -> RecordBatch` is a trait method implemented by 7 sink adapters (zeek, suricata, sflow, ipfix, syslog, generic/HEC, wef), each with its own hand-written builder set. Moving to an amortized-builder model means either (a) changing the trait to an `append(&mut self, record, builder_state)`-shaped method that mutates a live per-partition builder set instead of returning a batch, which ripples through `PartitionBuffer`'s `VecDeque<(RecordBatch, usize)>` storage model, `drop_oldest_to_cap`'s row-popping logic (currently pops whole batches off a deque; an amortized builder can't "pop" a row out of the middle), and every one of the ~14+ call sites' tests; or (b) a narrower per-adapter opt-in that batches N records client-side before calling `to_record_batch` once, which avoids touching the generic writer's contract but pushes complexity into each adapter individually and only pays off for adapters that opt in. Both shapes are real design decisions, not mechanical.

**Recommendation: worth doing, but scope it as its own design spec before touching code** — same weight of exercise as `2026-06-23-generic-buffered-writer-design.md` itself, because it changes the same trait contract that doc established and needs the same trade-off analysis of `drop_oldest_to_cap`'s row-level semantics under partial (not whole-batch) buffers. Do not fold this into a "quick win" PR. Given the measured 500µs-1.3ms/record cost, this is the single highest-value performance improvement identified in this investigation — but it is deliberately **not** tier 1 ("do next") because doing it hastily risks silently changing hard-cap/backpressure behavior that existing tests (`push_enforces_hard_cap_on_flush_failure`, `writer_bounded_under_s3_outage`) specifically pin down. Prerequisite reading for whoever scopes it: this doc's evidence above, plus `2026-06-23-generic-buffered-writer-design.md` in full.

### 2.2 `build_extra`'s per-record `HashSet` allocation and JSON re-serialization — **Tier: do next**

**What it is.** `build_extra` (`src/zeek/schema.rs:224-235`), called once per record by every Zeek mapper function, does:
```rust
let promoted_set: std::collections::HashSet<&str> = promoted.iter().copied().collect();
```
— reconstructing a `HashSet` from a small static slice (13-16 entries depending on the log type) **on every single record**, purely to do membership tests against a list that never changes for a given log type. It then deep-clones every non-promoted key/value pair into a fresh `serde_json::Map` and serializes it with `.to_string()`.

**Why it matters.** Hashing + heap-allocating a `HashSet` for a ≤16-element lookup is strictly worse than a linear scan over the same static `&[&str]` slice for this size — no allocation, no hashing, likely faster in practice for N this small, and it's paid on every record for every one of the 6 typed Zeek log types (conn/dns/http/ssl/files/notice) plus the envelope fallback. This is a small piece of the ~500µs-1.3ms/record budget in §2.1, but unlike §2.1 it is a self-contained, single-function change with no trait/contract implications and no interaction with the hard-cap/backpressure logic — the deep-clone-and-serialize part of `build_extra` is unavoidable given the current per-record JSON model, but the `HashSet` reconstruction is pure waste.

**Scope/effort.** Small: replace `promoted_set.contains(k.as_str())` with `promoted.contains(&k.as_str())` (slice `contains`, no set construction) in `build_extra`, or precompute the check differently per call site. Touches one function; existing Zeek schema unit tests (`src/zeek/schema.rs`'s own `#[cfg(test)] mod tests`) already assert `_extra` contents and would catch a regression.

**Recommendation: do next.** Low risk, clearly grounded (line-level), no architectural entanglement, and it's a "free" partial win on the same hot path §2.1 identifies without waiting for that larger redesign.

### 2.3 Per-record `Schema` equality check in `ZeekSink::to_record_batch` — **Tier: worth doing eventually**

**What it is.** `src/forwarding/zeek_s3.rs:117`: `if entry.schema == *schema` runs on every record. `entry.schema` and `schema` are both `Arc<arrow_schema::Schema>`, but the comparison dereferences to a full structural `Schema::eq` — field-by-field comparison of name, `DataType`, nullability, and a per-field metadata `HashMap`, for the 15-16 fields in a typed Zeek schema. In the overwhelmingly common case (record's log path matches an already-known partition), both `Arc`s point at the exact same `LazyLock`-produced singleton (`conn_schema()` etc., `src/zeek/schema.rs:31-53`), so an `Arc::ptr_eq` fast path would resolve the common case without walking any fields at all.

**Why it matters.** This is a real, currently-paid cost on every record, but it's smaller and less certain than §2.1/§2.2 — Arrow's `Schema::eq`/`Field::eq` on ~15 simple (non-nested, small-metadata) fields is not expensive in absolute terms; this is a micro-optimization, not a structural one. Grounded in the code, not measured directly in this session (no isolated micro-benchmark was run for this specific comparison).

**Recommendation: worth doing eventually**, bundled with §2.2 (same file family, similar risk profile) rather than as its own PR: add an `Arc::ptr_eq(&entry.schema, schema)` short-circuit before the structural comparison. Do not treat this as urgent on its own — it's a nice-to-have alongside a change that's already touching this function, not independently worth a PR.

### 2.4 Missing buffer-occupancy / channel-queue-depth gauges — **Tier: do next**

**What it is.** Per the task brief's lead #2: no gauge exists today for a partition's live buffer row count or a writer's channel queue depth — only *after-the-fact* counters (`parquet_s3_dropped`, `parquet_s3_buffer_dropped`). Verified: `grep -n "gauge!"` in `buffered_writer.rs` finds exactly one gauge, `parquet_s3_flushes_in_flight` (added by the flush-decoupling fix, `buffered_writer.rs:602,633`), which reports concurrent-flush count, not backpressure buildup. `PartitionBuffer.row_count` (`buffered_writer.rs:264`) is tracked in-process but never exported; `ParquetWriterHandle`'s `tx: mpsc::Sender<S::Record>` (`buffered_writer.rs`, `start_with_stats`) has `.capacity()` available (standard `tokio::sync::mpsc` API) but nothing reads it.

**Why it matters.** The whole point of the benchmark's `stress`-mode finding (§2.5 below) is that drops can still occur even post-fix, via the hard cap — and today an operator has zero warning before that happens: `parquet_s3_buffer_dropped` only increments *after* data is already lost. A gauge is a **leading** indicator: `parquet_s3_channel_available{source,target}` (from `tx.capacity()`) trending toward 0, or `parquet_s3_buffer_rows{source,target,partition}` climbing toward `max_buffer_rows`, gives an operator (or an alert rule) a chance to react — raise `max_buffer_rows`, investigate a slow/failing sink, etc. — before the hard cap starts silently dropping rows. This is exactly the class of gap the flush-decoupling fix's own new `parquet_s3_flushes_in_flight` gauge was added to help with, just for a different signal.

**Scope/effort.** Small and low-risk: this codebase already uses the `metrics::gauge!` macro directly with no pre-registration (confirmed: no `describe_gauge!` calls anywhere in the codebase), so adding a new gauge is a one-line macro call at an existing observation point, following the exact pattern `parquet_s3_flushes_in_flight` already established. Two concrete additions:
- `parquet_s3_channel_available{source,target}` — read `tx.capacity()` in the outer task's existing `ticker.tick()` branch (`buffered_writer.rs:1048`), which already fires periodically; no new timer needed.
- `parquet_s3_buffer_rows{source,target,partition}` — set in `push()` after `buf.row_count += n_rows` (`buffered_writer.rs:468`). **Caveat, and the reason this isn't "trivial":** `push()` is the single hottest call in this whole file (once per ingested record), so an *unconditional* gauge write here adds a small fixed cost (an atomic store into the metrics registry) to every record, on top of the counter increments `push()` already does conditionally (partition-cap). Given §2.1/§2.2's evidence that per-record cost is already the bottleneck, prefer updating this gauge from the same periodic ticker branch as the channel gauge (iterate `self.buffers`, one gauge-set per partition per tick) rather than on every `push()` — same leading-indicator value, without adding per-record overhead. This periodic-not-per-push placement is the one design choice worth deciding deliberately, not the existence of the gauge itself.

**Recommendation: do next.** Directly actionable, cheap, matches an established pattern in the same file, and closes a real "no warning before data loss" gap — but implement both gauges off the periodic ticker, not inline in `push()`.

### 2.5 Allowing more than one in-flight flush for a single hot partition — **Tier: declined**

**What it is.** The task brief's lead #3: the benchmark's `stress`-mode results (`BENCHMARK_RESULTS.md` §4, §6) show that even post-fix, most records in that mode are still dropped — via the pre-existing hard cap (`drop_oldest_to_cap`), not the channel-full bug the fix addressed — because only one flush can be in-flight per partition (`2026-07-24-decoupled-flush-buffered-writer-design.md` decision #2), so a single hot partition's durable-write ceiling is `max_buffer_rows / (encode + upload latency)`. In the benchmark's artificial `stress` config that's `50 rows / 150ms ≈ 333 rec/s` against 4,000 rec/s offered load.

**Why it matters (or doesn't).** The benchmark's own §6 interpretation is explicit that this is expected, by-design behavior under **artificially tiny thresholds** (`max_buffer_rows=50`), not a realistic production configuration — and the `realistic`-mode results (production defaults: `max_buffer_rows=100,000`) show only 26 channel-full drops and *zero* hard-cap drops out of 120,000 records. The hard cap only binds when a single partition's flush-cycle throughput genuinely can't keep pace with its ingest rate at the *configured* buffer size — which is precisely the situation `max_buffer_rows` exists to be tuned for. Allowing >1 concurrent flush for one partition would require either (a) accepting out-of-order Parquet files within a partition (probably fine for log data, which is typically read back partition+time-range, not in strict append order) or (b) inventing new per-partition sub-buffering/ordering machinery — real design work, for a scenario the evidence shows is a *configuration* problem (buffer size too small for sustained per-partition rate), not an architectural ceiling.

**Recommendation: decline.** The fix that just landed already made the deliberate, documented choice of "at most 1 in-flight per partition" specifically to reuse existing hard-cap machinery instead of inventing new backpressure (`2026-07-24-decoupled-flush-buffered-writer-design.md` decision #2) — re-opening that now, on the strength of a deliberately-adversarial `stress`-mode benchmark parameter, would be solving a problem that operationally is "raise `max_buffer_rows`" rather than "add concurrency." If a *real* production deployment is later observed hitting the hard cap under *realistic* (not artificially-shrunk) thresholds, that's new evidence and worth revisiting — but nothing in hand today supports it. The one thing worth doing cheaply here: §2.4's `parquet_s3_buffer_rows` gauge would make it observable if a real deployment ever does approach this ceiling, which is a strictly better first response than adding concurrency pre-emptively.

### 2.6 `tools/loadgen` + `criterion` performance-testing harness — **Tier: worth doing eventually, sequencing note only**

**What it is.** `2026-07-05-performance-testing-strategy-design.md` in full — an unimplemented draft for a proper cross-format load-testing crate plus `criterion` microbenchmarks plus a manually-triggered CI workflow. Confirmed still fully unimplemented: no `criterion` in `Cargo.toml`, no `benches/` directory, no `tools/loadgen` directory.

**Why it matters.** This is testing infrastructure, not a performance fix in itself — but two of its stated blockers are relevant here. First, its "prerequisite" claim about `LocalDiskSink` wiring is now moot (§0 — already done for all 7 sources), which actually *removes* a blocker this draft thought it had, making the harness cheaper to start today than it was on 2026-07-05. Second, its own §5 explicitly recommends `criterion` microbenchmarks as a *separate, CI-eligible* sibling tier specifically for function-level questions like "how fast is `to_record_batch` for a Zeek conn record" — which is exactly the measurement this session made manually (ad hoc, via the flush-decoupling benchmark work) to produce the 500µs-1.3ms/record figure cited in §2.1. A real `criterion` benchmark for `ZeekSink::to_record_batch` (and its counterparts for the other 6 sinks) would turn that one-off measurement into a regression-tracked, CI-eligible signal — and would be the natural way to *prove* §2.1's eventual redesign actually delivers the improvement it's predicted to.

**Recommendation: worth doing eventually, not urgent on its own** — this plan does not re-litigate the draft's own design (it's thorough and this investigation found nothing wrong with it), but flags one sequencing point: **start with the `criterion` microbenchmark slice of that plan specifically for `ParquetSink::to_record_batch` across all 7 sinks, before scoping §2.1's redesign** — it directly produces the "before" numbers §2.1's design doc will need to justify its approach and later prove it worked, and per the draft's own reasoning (§5) is far cheaper to stand up than the full `tools/loadgen` UDP/TCP/HTTP load generator (no listener, no channel, no real I/O — pure in-process function timing). The full `loadgen` crate + manually-triggered CI workflow remains worth doing but is not blocking anything in this plan and can proceed independently on its own timeline.

### 2.7 `MultiZeekHandler`/`MultiSuricataHandler` per-record clone on dual-destination fan-out — **Tier: declined**

**What it is.** `src/forwarding/zeek_s3.rs:172` and `src/forwarding/suricata_s3.rs:136`: when both `.s3` and `.local` are configured for the same source, `MultiZeekHandler::handle_record` clones the full record (`String` log_path + `serde_json::Value` fields, deep-cloned) once per configured destination.

**Why it matters (or doesn't).** This only fires when an operator has deliberately configured *both* S3 and local-disk persistence for the same source simultaneously — an opt-in, dual-write configuration, not the default or common case. The clone is a genuine cost (a `serde_json::Value` clone is a deep clone of the whole parsed record), but it is bounded by, and proportional to, a choice the operator explicitly made to write every record twice to two independent destinations — some per-copy cost is inherent to that choice, not a bug.

**Recommendation: decline.** No evidence this is a bottleneck for the common (single-destination) configuration, which is unaffected. Revisit only if an operator reports dual-destination throughput specifically, with evidence — not worth speculative optimization now.

## 3. The three deferred decision-log items (this plan's required verdicts)

Per the flush-decoupling design's decision log (`2026-07-24-decoupled-flush-buffered-writer-design.md`, rows 3, 6, 7):

### Row 3 — Global cross-source concurrency cap (deferred as YAGNI, observability added)

**Verdict: still declined, but not unconditionally — revisit only if the new gauge shows saturation.**

The per-writer semaphore (`MAX_CONCURRENT_FLUSHES_PER_WRITER = 4`, `buffered_writer.rs:328`) bounds concurrency *within* one writer, but a deployment running many sources simultaneously (up to 7 sources × up to 2 targets = up to 14 independent `ParquetWriterHandle` instances, each with its own 4-permit semaphore) has no *process-wide* cap — worst case, up to 56 concurrent `encode_and_upload` calls, each holding a `concat_batches`-merged `RecordBatch` (up to `max_buffer_rows` rows) in memory simultaneously plus its Parquet-encoded output buffer. Realistically most deployments configure a handful of sources, not all 7×2, so this worst case is unlikely to occur in practice — and the design's own reasoning (each source/destination keeps fully independent state, matching this codebase's existing philosophy) is sound. Inventing a process-wide semaphore now, with no observed OOM or memory-pressure incident to justify it, would be solving a hypothetical.

What I'd actually do: **nothing new to build** — the `parquet_s3_flushes_in_flight` gauge already added by the fix, combined with §2.4's proposed buffer-occupancy gauges, is enough for an operator or SRE to *see* concurrent-flush pressure building across all configured writers via `sum(parquet_s3_flushes_in_flight)` in Prometheus. If that ever demonstrably approaches a memory-pressure incident in a real multi-source deployment, a process-wide semaphore is a small, well-understood addition to bolt on at that point — but building it pre-emptively fails the same YAGNI test the original design applied, and I don't have new evidence to overturn that call.

### Row 6 — `push()`'s `-> anyhow::Result<()>` signature kept unnecessarily broad

**Verdict: still not worth an isolated PR — bundle it opportunistically.**

Confirmed directly: `push()` (`buffered_writer.rs:416`) always returns `Ok(())` now; every call site that checks its `Result` (`buffered_writer.rs:1031`, plus `flush_all_if_needed`'s equivalent at `:1052`) has a comment stating the branch is currently unreachable. Narrowing the signature to `()` is genuinely mechanical and safe, but touches ~14+ call sites and their tests for zero behavior change — pure code-smell cleanup with no user-visible or performance benefit. I agree with the original design's own assessment ("a mild code smell, not a functional problem"). **Recommendation: do not open a dedicated PR for this.** Fold it into whichever future change already has a reason to touch `push()`'s call sites — §2.1's eventual redesign is the most likely candidate, since it will already be changing this exact function's contract for a real reason.

### Row 7 — Source/target logging-attribution gap on generic writer-task warnings

**Verdict: do next — this is the cheapest, clearest-value item in this whole plan.**

Confirmed directly, six call sites missing `source`/`target` tracing fields despite the values being in scope (or trivially reachable) at every one of them:

| Location | Missing fields | Are they in scope already? |
|---|---|---|
| `buffered_writer.rs:649` (`apply_flush_outcome` failure) | source, target | Yes — both computed 2 lines above (`:631-632`) |
| `buffered_writer.rs:686` (`drain_pending_flushes` panic) | source, target | Reachable via `self.sink.source()` / `self.s3.target_label()`, not currently called |
| `buffered_writer.rs:1032` (outer task, push error — dead branch) | source, target | Yes — captured as locals at `:1002-1003`, in scope for the whole closure |
| `buffered_writer.rs:1042` (outer task, shutdown flush_all error) | source, target | Same as above |
| `buffered_writer.rs:1053` (outer task, flush_all_if_needed error — dead branch) | source, target | Same as above |
| `buffered_writer.rs:1067` (outer task, flush task panic) | source, target | Same as above |

With 7 sources sharing this one file, a bare `"parquet_s3 writer push error: {e}"` in a production log stream is currently indistinguishable across every source and every target (S3 vs local) — exactly the debuggability gap that made the original Zeek production incident (this plan's own starting point) harder to diagnose in the first place. This is a pure `tracing::warn!` call-site edit (add `source, target` structured fields, following the existing pattern already used correctly at `drop_oldest_to_cap`'s warning, `buffered_writer.rs:717-722`), no logic change, no test-breaking risk beyond any log-content assertions (grep shows none check these specific message strings). **Recommendation: do next**, and do it on its own — it doesn't need to wait for or bundle with anything else in this plan.

## 4. Considered, no evidence found (not recommended)

Explored per the task's "general exploration" instruction; none produced a concrete, grounded finding, so none are included as recommendations:

- **Lock/mutex contention on the ingest hot path.** Grepped every production (non-test) use of `Mutex`/`RwLock` under `src/ipfix`, `src/syslog`, `src/forwarding`, `src/stats` — the only production locks found are `FlushIntervalRegistry` (admin-API-triggered, not per-record) and `SourceHourlyStats`, which uses a sharded `DashMap` (`src/stats/mod.rs:12`), not a single lock, and is written to by exactly one writer task per source (no cross-task contention on a given source's key). No evidence of contention on any per-record path.
- **Syslog's multi-parser sub-dispatch chain cost** (`src/syslog/payload/mod.rs:117-143`). This was flagged in the task brief as a lead worth checking. On inspection: CEF/LEEF do fast prefix rejection, all regex-based sub-parsers (DHCP, RADIUS, web_access, auditd) already compile their `Regex` once via `std::sync::LazyLock` (confirmed in all 4 files), not per-call. No evidence of a per-record recompilation or other hot-path waste here.
- **IPFIX template-cache lookup cost.** Named in the performance-testing draft's cost-profile table as the dominant IPFIX cost, but this investigation did not find (or look for, beyond a structural read) a specific inefficiency in `src/ipfix/decoder.rs`'s cache implementation — flagging as an open question for whoever eventually builds the `criterion` benchmark suite (§2.6) to actually measure, rather than asserting a fix without evidence either way.

## 5. Prioritized summary

| # | Candidate | Tier | Verdict |
|---|---|---|---|
| 2.7 (row 7) | Source/target fields on 6 generic-writer `warn!` call sites | **Do next** | Fix now — trivial, zero-risk, closes a real debuggability gap |
| 2.4 | `parquet_s3_channel_available` + `parquet_s3_buffer_rows` gauges (off the ticker, not per-`push()`) | **Do next** | Fix now — cheap, established pattern, leading indicator before drops occur |
| 2.2 | Remove per-record `HashSet` allocation in `build_extra` | **Do next** | Fix now — small, self-contained, measurable |
| 2.3 | `Arc::ptr_eq` fast path before `Schema::eq` in `ZeekSink::to_record_batch` | Worth doing eventually | Bundle with 2.2, not urgent alone |
| 2.6 (partial) | `criterion` microbenchmark for `to_record_batch` across all 7 sinks | Worth doing eventually | Do before scoping 2.1 — produces its "before" numbers |
| 2.1 | Batch multiple records per `RecordBatch` (amortized builders) | Worth doing eventually | Highest measured impact (500µs-1.3ms/record) but needs its own design spec — do not rush |
| 2.6 (full) | `tools/loadgen` crate + manually-triggered perf CI workflow | Worth doing eventually | Sound existing draft, not blocking, proceed independently |
| Row 3 | Global cross-source flush concurrency cap | **Declined** (conditionally) | YAGNI stands; revisit only if `parquet_s3_flushes_in_flight` shows real saturation |
| Row 6 | Narrow `push()`'s `Result` signature | **Declined** (as standalone work) | Bundle into 2.1 when that lands; not worth its own PR |
| 2.5 | Allow >1 in-flight flush per hot partition | **Declined** | Evidence points to a config problem (`max_buffer_rows` too low), not an architectural ceiling |
| 2.7 | Per-record clone in dual-destination (`.s3`+`.local`) fan-out | **Declined** | Opt-in cost proportional to an opt-in configuration; no evidence of real impact |
