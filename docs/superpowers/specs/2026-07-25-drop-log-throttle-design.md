# Per-Drop Log Storm — Throttle Design

**Date:** 2026-07-25
**Status:** Approved (autonomous design via `auto-develop`; independent coherence review, 4 rounds)
**Related:** [`2026-07-25-cpu-profiling-instrumentation-design.md`](2026-07-25-cpu-profiling-instrumentation-design.md), [`docs/performance/2026-07-25-syslog-udp-cpu-profile.md`](../../performance/2026-07-25-syslog-udp-cpu-profile.md)

## 1. The problem

Nineteen `tracing::warn!`/`error!` call sites fire **once per dropped record** when a
writer's bounded channel is full or closed. Under overload this is a log storm.

### 1.1 Measured cost

Two runs per condition, 50,000 syslog datagrams/sec, 30s, same binary, only the log level
differing, no profiler active:

| | CPU-sec | received | µs / received datagram |
|---|---|---|---|
| `info` run 1 | 85.97 | 852,799 | 100.8 |
| `info` run 2 | 84.17 | 839,702 | 100.2 |
| `error` run 1 | 88.04 | 1,054,868 | 83.5 |
| `error` run 2 | 86.23 | 991,117 | 87.0 |

Suppressing the drop logs saves **~15µs per received datagram (−15%)** and yields **~21%
more datagrams ingested** (846k → 1,023k mean). The `info` samples are tight (100.2 /
100.8), so this is signal, not noise.

**The mechanism is displacement, not raw CPU burn.** Absolute CPU barely moves (85.1 vs
87.1 CPU-sec) — slightly *higher* with logging off. The cost is that logging runs on the
**single-task UDP recv path**, so time spent formatting and locking stdout is time not
spent calling `recvfrom`, and more datagrams die in the kernel socket buffer before the
application sees them.

Honest corollary: drops *rose* with logging off (392k→559k, 261k→462k). More datagrams get
in, so more hit the full writer channel. The bottleneck moves downstream rather than
disappearing.

### 1.2 Volume

`1,176,360` log lines for `392,107` drops ≈ **3.0 lines per drop** — the `pretty` format is
multi-line.

### 1.3 It also crashes the profiler

At `info` with the `pprof` sampler active the process **segfaults (exit 139)**,
reproducibly. pprof's `SIGPROF` handler unwinds via `backtrace`, which is not
async-signal-safe against the allocator and stdout locks `tracing` holds. This forced
`scripts/profile-syslog-udp.sh` to pin logging to `error`, which in turn means the CPU
profile it produces excludes logging cost.

### 1.4 The logs are redundant

Every one of the 19 sites reacts to `ParquetWriterHandle::try_send`
(`buffered_writer.rs:1267-1278`), which **already** increments
`parquet_s3_dropped{source,target}` for every drop — a labelled, aggregatable, alertable
counter that carries strictly more information than the log line.

## 2. Site inventory — 19 sites

Rounds 1 and 2 of review rejected this design on inventory misses. Root cause both times:
greps requiring the macro name and the message string on the **same source line**, which
silently skips multi-line macro invocations. Re-derived two independent ways — by grepping
the message strings alone, and by auditing every `try_send` call site's error arm.

| File:line | Level | Message | Extra context |
|---|---|---|---|
| `forwarding/sflow_s3.rs:247` | warn | sFlow S3 channel full | exporter addr |
| `forwarding/syslog_s3.rs:163` | warn | Syslog S3 channel full | — |
| `forwarding/suricata_s3.rs:114` | warn | Suricata S3 channel full | exporter addr |
| `forwarding/zeek_s3.rs:164` | warn | Zeek S3 channel full | exporter addr |
| `forwarding/ipfix_s3.rs:250` | warn | IPFIX S3 channel full | flow count + exporter addr |
| `syslog/listener.rs:108` | warn | structured_syslog S3 channel full | — |
| `syslog/listener.rs:138` | warn | structured_syslog channel full | — |
| `server/mod.rs:731` | warn | WEF Parquet S3 channel full | — |
| `server/mod.rs:734` | error | WEF Parquet S3 channel closed | — |
| `server/mod.rs:743` | warn | WEF Parquet local channel full | — |
| `server/mod.rs:746` | error | WEF Parquet local channel closed | — |
| `server/mod.rs:2740` | warn | OTLP generic_s3 channel full | — |
| `server/mod.rs:2743` | error | OTLP generic_s3 channel closed | — |
| `server/mod.rs:2752` | warn | OTLP generic_local channel full | — |
| `server/mod.rs:2755` | error | OTLP generic_local channel closed | — |
| `ingest/handlers.rs:90` | warn | HEC S3 channel full | context string |
| `ingest/handlers.rs:93` | error | HEC S3 channel closed | context string |
| `ingest/handlers.rs:103` | warn | HEC local channel full | context string |
| `ingest/handlers.rs:106` | error | HEC local channel closed | context string |

### 2.1 Deliberate exclusions, each verified in source

- **`buffered_writer.rs:848-852`** (`drop_oldest_to_cap`) — already throttled:
  `last_drop_warn ... elapsed().as_secs() >= 30`. This is the in-repo precedent §4 row 3′
  follows.
- **`ipfix/decoder.rs:127`** — already warn-once via a `template_limit_warned` flag.
- **`forwarding/mod.rs:154`** — WEF's external HTTP forwarder uses blocking
  `.send().await`, which backpressures rather than dropping; its error fires on a closed
  channel at shutdown, not per record.

## 3. A correction this design had to make

Rounds 1-3 of the design asserted that "WEF and OTLP use raw `tokio::sync::mpsc::Sender`
and bypass `ParquetWriterHandle::try_send`". **That was false**, and its falseness changed
the architecture. Verified:

- `AppState.parquet_s3_sender` / `parquet_local_sender` are `ParquetWriterHandle<WefSink>`
  (`server/mod.rs:56-67`)
- `GenericS3Handler = ParquetWriterHandle<GenericSink>` (`generic_s3.rs:111`), used by both
  OTLP and HEC/NDJSON via `IngestState.generic_s3` / `generic_local` (`ingest/mod.rs:50,54`)
- `StructuredS3Handler = ParquetWriterHandle<StructuredSyslogSink>`
  (`structured_syslog_s3.rs:110`)

The claim came from reading the variable name `sender` and the `TrySendError::Full/Closed`
match without checking the type — `ParquetWriterHandle::try_send` returns that same error
type. **All 19 sites funnel through one method**, which is what makes centralising the
throttle possible.

## 4. Decision log

| # | Question | Chosen | Why |
|---|---|---|---|
| 1′ | Where does throttle state live? | inside `ParquetWriterHandle` | all 19 sites funnel through `try_send`; centralising means future call sites inherit throttling instead of needing a remembered hand-edit — the exact failure mode that caused three rounds of inventory misses |
| 2′ | What does a line report? | cumulative total, **never reset** | eliminates reset races: only `fetch_add`, `load`, one `compare_exchange`. Every line is true, only possibly stale |
| 3′ | Interval | **30s**, matching `drop_oldest_to_cap` | follow in-repo precedent; one throttle cadence, not two |
| 4 | Mechanism | two `AtomicU64` per throttle, no allocation on the drop path | must not add hot-path cost — that is the whole point |
| 5′ | Clock | injectable `check_at(now_nanos)`; `last_log_nanos` initialised to `u64::MAX` as an explicit "never logged" sentinel | otherwise untestable without sleeps, and a test clock starting near 0 would make "first call always logs" clock-dependent |
| 6′ | Module | `src/forwarding/drop_log.rs` | `buffered_writer.rs` is already 3,342 lines; a separate module keeps the type unit-testable in isolation |
| 7′ | API | `handle.drop_log_due(site, kind) -> Option<u64>` | sites keep their message text and exporter context verbatim and merely ask whether to emit |
| 8 | Delete the logs entirely? | no | loses first-occurrence visibility and the exporter address |
| 9 | Remove redundant `hec_events_dropped`? | no — out of scope | metrics are user-visible; changing them is a separate decision |
| 10 | Log levels | keep (warn = Full, error = Closed) | unrequested behaviour change otherwise |
| 11′ | Full vs Closed | two independent throttles | a writer-died `Closed` must never be suppressed because a `Full` fired 5s earlier — that transition is the critical operator signal |
| 13 | Site inventory | 19, verified two independent ways | see §2 |
| 14 | Short-burst visibility | accept and document | a burst shorter than the interval emits only its first line, so the log understates. `parquet_s3_dropped` is authoritative. A reaper task plus a throttle registry is real machinery for a signal Prometheus already carries exactly |
| 15′ | pprof crash | **reduced, not eliminated** | ~190,000× fewer emissions makes a SIGPROF/stdout-lock collision very unlikely but not impossible; must not be oversold |
| 16 | Exclusions | explicit and verified | see §2.1 |
| 17 | Clone hazard | `Arc`-shared throttle state | `ParquetWriterHandle` is `#[derive(Clone)]` (`buffered_writer.rs:1118`) and `IngestState` clones its `GenericS3Handler` fields per request (`AppState` is held behind `Arc<AppState>` and is not itself `Clone`; `ParquetWriterHandle<WefSink>` isn't `Clone` either, since `WefSink` isn't `Clone`). Plain `AtomicU64` fields would give every clone its own throttle, silently resetting it and restoring the storm. Precedent in the same struct: `flush_interval: LiveInterval` already wraps `Arc<AtomicU64>` |
| 18 | Shared-handle conflation | throttles keyed by a closed `DropSite` enum | `generic_s3`/`generic_local` are the **same handles** for OTLP and HEC/NDJSON (`GenericSink::source()` is hardcoded `"hec"`). Per-handle-only keying would let an OTLP burst mute HEC's textually-distinct first-occurrence line for 30s, contradicting the design's own goal for 8 of 19 sites |
| 19 | E2E scope | also re-measure µs/datagram and throughput | otherwise nothing closes the loop on the ~15µs/−21% claim that motivated the work |
| 11″ | Full/Closed look-alike lines | accept and document | at the 7 sites whose text doesn't distinguish the two, a one-time Full→Closed transition may emit two similar-looking lines. Bounded to a single occurrence, not a recurring storm |

## 5. Design

### 5.1 `src/forwarding/drop_log.rs`

```rust
pub enum DropKind { Full, Closed }          // From<&TrySendError<R>>
pub enum DropSite { Wef, Hec, Otlp, Sflow, Zeek, Suricata, Ipfix, Syslog, StructuredSyslog }

pub struct DropLogThrottle {
    total: AtomicU64,           // monotonic, NEVER reset
    last_log_nanos: AtomicU64,  // u64::MAX == never logged
}

pub struct DropLogThrottles { /* [DropLogThrottle; N_SITES * 2] */ }
```

`check_at(now_nanos) -> Option<u64>`: `fetch_add(1)` on `total`; if the sentinel is set or
≥30s has elapsed, claim the slot via `compare_exchange` on `last_log_nanos` and return
`Some(total)` — the running total including this drop. Otherwise `None`. A lost CAS returns
`None`.

Because `total` is never reset, a lost race or a missed window cannot corrupt or lose the
count; the next emitted line simply reports a larger, still-correct total.

`DropLogThrottles` is a fixed array indexed by `site as usize * 2 + kind as usize` — no map,
no allocation, lock-free. At 9 sites × 2 kinds × 16 bytes that is 288 bytes per handle.

### 5.2 `ParquetWriterHandle`

Gains `drop_log: Arc<DropLogThrottles>`, built in `start_with_stats` and shared across
clones (row 17), plus:

```rust
pub fn drop_log_due(&self, site: DropSite, kind: DropKind) -> Option<u64>
```

### 5.3 Call sites

Each of the 19 becomes, e.g.:

```rust
Err(e) => {
    if let Some(dropped_total) = self.drop_log_due(DropSite::Sflow, DropKind::from(&e)) {
        tracing::warn!(dropped_total, "sFlow S3 channel full; dropped record from {source}");
    }
}
```

Message text and levels are preserved **verbatim**; only the `dropped_total` field is added.
`parquet_s3_dropped{source,target}` remains the precise per-drop record; the log becomes a
human-facing summary.

Per-drop cost: `check_at`'s `fetch_add`, atomic load, and `compare_exchange` attempt, plus
`process_nanos()`'s clock read — a `OnceLock` load, an `Instant::now()` call
(`clock_gettime(CLOCK_MONOTONIC)`, ~20-25ns via vDSO where available, a real syscall otherwise),
and a `u128` → `u64` narrowing conversion. Still no allocation and no locking, and still roughly
three orders of magnitude below a formatted, stdout-locking, ~3-line `tracing` write — but more
than "one `fetch_add` plus one atomic load" alone.

## 6. Testing

Per `CLAUDE.md`, all three levels apply.

**Unit** (`drop_log.rs`): first call always logs (via the `u64::MAX` sentinel, clock-value
independent); suppression within the interval; emission after it; `total` monotonic across
many calls; N threads hammering `check_at` leave `total` exactly equal to the call count;
`Full` and `Closed` throttles independent; two different `DropSite`s independent.

**Integration**: burst N drops through a real call site with a capturing `tracing`
subscriber; assert exactly one line with the correct `dropped_total`. **Plus a test that a
cloned `ParquetWriterHandle` shares throttle state** — the row-17 hazard, which would
otherwise silently restore the storm.

**E2E**: loadgen at 50k comparing emitted log lines before/after (expect ~1.18M → single
digits), **and** re-measuring µs/received-datagram and throughput to confirm the ~15µs/−21%
win (row 19), **and** N repeated `info` + pprof-sampler trials comparing crash rate (row
15′).

## 7. Known limitations

- **Short bursts understate.** A drop burst shorter than 30s emits only its first line; the
  accumulated total is not emitted until the next drop after the window. `parquet_s3_dropped`
  is authoritative (row 14).
- **The pprof crash is reduced, not eliminated** (row 15′).
- **Full/Closed look-alike lines** at 7 sites, bounded to one occurrence per transition
  (row 11″).
