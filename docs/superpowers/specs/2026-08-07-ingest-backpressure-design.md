# Ingest backpressure + 100 MiB channel budget — design

**Date:** 2026-08-07
**Status:** approved (auto-develop coherence review, round 2)
**Branch:** `feat/ingest-backpressure`
**Base:** `a972aba`

## 1. Problem

A production Zeek sensor is losing records at ~1,500/hour (~0.02% of offered
load). The symptom is the throttled warning:

```
Zeek S3 channel full; dropped 1 record from 192.168.7.102:33764
```

S3 uploads to Garage complete normally for every Zeek log type. The pipeline
is not stalled — it is dropping inbound records when the bounded channel
between TCP reception and the Parquet writer fills.

Two independent causes:

1. **The channel is tiny.** `default_zeek_channel_capacity()`
   (`src/config/mod.rs:304`) is **256 records** — roughly 60–250 ms of burst
   headroom at realistic sensor rates. Any scheduler hiccup on the single
   writer task (a `spawn_blocking` zstd encode occupying a worker, a metrics
   scrape, a burst of connection tasks) overflows it. Note that the generic
   default in `buffered_writer.rs:246` is **8192**, commented "Large enough to
   absorb bursts without dropping at the channel layer" — every per-source
   config overrides it *downward*.

2. **Overflow is handled by discarding data.** `ParquetWriterHandle::try_send`
   (`buffered_writer.rs:1278`) is the only send path in the codebase. Nothing,
   anywhere, applies backpressure. For UDP sources that is correct — there is
   no backpressure to apply. For a TCP source it is simply wrong: not reading
   the socket would close the TCP window and push the queue back to the Zeek
   sensor, which has its own disk-backed spool.

This is **not** the previously-fixed flush-coupling bug. Flush/upload is
already decoupled from the drain loop (spawned tasks + a 4-permit semaphore),
and `BENCHMARK_RESULTS.md` records the residual post-fix drop rate as 0.022%
at 4,000 rec/s with `channel_capacity=256` — which matches the production
rate almost exactly. This design targets that residual.

## 2. Scope

In scope:

- Backpressure for **Zeek and Suricata** ingest.
- Raising **every** source's `channel_capacity` default to a ~100 MiB budget.

Explicitly out of scope (see §7): syslog, sFlow, IPFIX, HEC, WEF and OTLP
backpressure; the HEC 200-OK-after-drop defect; writer sharding; extending
`RecordBatchAccumulator` beyond `conn`.

## 3. Part 1 — backpressure for TCP-framed sources

### 3.1 Which sources, and why only these

| Source | Transport | Receive shape | Backpressure? |
|---|---|---|---|
| Zeek | TCP only | per-connection spawned task (`zeek/listener.rs:258`) | **yes** |
| Suricata | TCP only | per-connection spawned task (`suricata/listener.rs:258`) | **yes** |
| Syslog | UDP **and** TCP | one `select!` task, UDP arm awaits the handler inline (`syslog/listener.rs:245-283`) | no |
| sFlow, IPFIX | UDP only | — | no |
| HEC, WEF, OTLP | HTTP | axum request handler | no |

Zeek and Suricata are the only sources whose records arrive on a *dedicated
per-connection task* over a *pure stream transport*. Blocking there stops
reading that one socket, closes the TCP window, and applies flow control to
exactly one sender. Nothing else is affected.

Syslog is deliberately excluded even though it has a TCP listener: its UDP
`recv_from` arm and its TCP accept arm share **one** task, and the
`SyslogHandler` trait cannot tell which transport delivered a message.
Blocking inside the handler would stall UDP reception (where blocking buys
nothing — the kernel drops datagrams regardless) *and* stall TCP accepts.
Fixing that requires splitting the listener loop, which is a larger change
than this incident warrants.

HTTP sources are excluded because the correct backpressure signal there is a
`503`/`429` response, not a blocked handler; blocking holds server resources
while the client times out and drops anyway.

### 3.2 Mechanism

In the `ZeekHandler` impl (`forwarding/zeek_s3.rs:161`) and the
`SuricataHandler` impl (`forwarding/suricata_s3.rs:110`), replace
`try_send(record)` with `send_timeout(record, self.send_timeout)`.

- `send_timeout` is `tokio::sync::mpsc::Sender::send_timeout`, gated on
  tokio's `time` feature, which `Cargo.toml:23` already enables via `full`.
- On **success**: nothing else changes.
- On **timeout or closed**: fall through to today's exact drop path —
  `parquet_s3_dropped` incremented, throttled warn via `drop_log_due`. The
  safety valve and all current observability survive unchanged. A drop now
  means "the writer was unavailable for a full timeout", not "a burst
  arrived", which makes the existing warning far more meaningful.

Rejected alternatives: an unbounded `send().await` wedges a connection
forever if the writer task dies; a manual `try_send`-plus-retry loop is
`send_timeout` reimplemented worse.

### 3.3 Timeout value and injectability

`SEND_TIMEOUT_DEFAULT = 5s`, stored as a `send_timeout: Duration` field on
`ParquetWriterHandle` rather than a bare constant, with a setter used by
tests.

Rationale: 5 s is far longer than any plausible writer hiccup and far shorter
than sensor/TCP timeouts. It is *not* promoted to a config key (YAGNI — no
evidence anyone needs to tune it, and a field is trivially promotable later).
It must be a field rather than a `const` because the existing tests that
deliberately overfill a capacity-1 channel to assert drop behaviour
(`zeek_s3.rs:919`, `tests/zeek_local_integration.rs:228`) would otherwise
stall for 5 real seconds per record, and the new integration test for
drop-after-timeout needs to wedge the writer and observe a drop quickly.

### 3.4 Multi-destination fan-out

`MultiZeekHandler` and `MultiSuricataHandler` currently fan out **sequentially**
(`zeek_s3.rs:189-193`, `suricata_s3.rs:130-142`):

```rust
for handler in &self.0 { handler.handle_record(record.clone(), source).await; }
```

Once sends block, that stacks: a stalled S3 destination would add up to 5 s of
latency *per record* to a healthy local-disk destination. That is a new
failure mode introduced into a currently-working path, so it is fixed here
rather than accepted: fan out concurrently with `futures::future::join_all`
(`futures = "0.3"` is already a dependency, `Cargo.toml:75`), making total
latency `max()` instead of `sum()`.

Each destination owns an independent channel and writer with no shared mutable
state, so concurrent polling introduces no ordering or data-race concern, and
panic/cancellation semantics are unchanged.

## 4. Part 2 — 100 MiB channel budget

### 4.1 Units

`channel_capacity` stays in **records**. A new `CHANNEL_BUDGET_BYTES = 100 MiB`
constant is divided by a per-record byte figure to derive each source's
default count.

Rejected: a byte-weighted semaphore, or a new `channel_capacity_bytes` config
key. Both are new machinery and config churn for a number that only needs to
be right within a factor of ~2, and (a) keeps every existing TOML valid.

### 4.2 Per-source derivation

Per-message footprint spans two orders of magnitude across sources, so one
shared record count would mean 100 MiB for one source and gigabytes for
another. Each `default_*_channel_capacity()` in `config/mod.rs` (lines 304,
406, 468, 548, 745, 806, 911 — each shared by that source's `.s3` and
`.local` variants) becomes `CHANNEL_BUDGET_BYTES / <measured bytes>`, rounded
to a clean number, with the measured figure recorded in the doc comment.

### 4.3 Measurement methodology

A committed test measures each record type's real heap footprint and fails if
a documented estimate has drifted by more than ~2×. A memory *ceiling* built
on an unverified divisor is fiction, and adding a field to a record type would
otherwise silently inflate the budget.

"Footprint" means the heap owned by, and reachable from, one channel item —
following indirection, not `size_of` alone:

- `ZeekRecord` / `SuricataRecord` / `GenericRecord` / `SyslogMessage`: walk the
  `serde_json::Value` / `String` / `HashMap` heap.
- `Arc<WindowsEvent>` (WEF): measure the **pointee**. The channel slot is an
  8-byte pointer, but each queued `Arc` is a distinct event and the `Arc` is a
  transfer mechanism, not sharing. WEF fan-out to `.s3` and `.local` clones the
  same `Arc` into both channels, so counting it per-channel overcounts — the
  safe direction.
- `Vec<FlowRecord>` (IPFIX): `size_of::<FlowRecord>()` × a representative
  flows-per-datagram taken from the existing IPFIX test fixtures. **This is
  average-case, not a ceiling** — datagrams denser than the fixture average
  will exceed the budget. Documented as a known limitation.

### 4.4 Aggregate memory

Worst case is (enabled sources) × 100 MiB. Two mitigating facts:

- tokio's bounded mpsc allocates its buffer lazily in blocks, so an idle or
  healthy channel costs nearly nothing; the budget is a ceiling, not a
  reservation.
- Only Zeek and Suricata get backpressure, so only those two are *designed* to
  dwell near capacity under load — roughly 200 MiB expected steady state. The
  remaining sources still drop on overflow, so their channels fill only
  transiently. (This rests on an assumption about those sources' traffic
  patterns that is not verified in-repo.)

Operators should alert on the existing `parquet_s3_channel_available` gauge.

## 5. Shutdown interaction

`main.rs:596-628` gives each listener 2 s (then aborts it), then gives **all**
writer tasks a single shared **10 s** deadline, after which it warns "some data
may not have been written".

Deepening every channel interacts with that budget. Splitting the two costs:

- **Drain** is CPU-only — the writer's channel-closed arm pops each record
  through `push()` (`buffered_writer.rs:473`), which does record→RecordBatch
  conversion with no I/O. At µs-scale per record, even a 50,000-record channel
  drains in well under a second.
- **Flush** is the I/O. A deeper channel means up to a channel's worth of
  *extra rows* reaching the partition buffers, and therefore extra
  encode+upload work in `flush_all()` — inside the same 10 s.

Decision: **keep the 10 s deadline**, and verify rather than assume. Raising it
to 30 s was rejected because it would meet or exceed a typical Kubernetes
`terminationGracePeriodSeconds` and risk SIGKILL mid-upload, which is worse
than the current documented partial flush. (No manifest in this repo
establishes that grace period; this is an outside-the-repo assumption.)

Two additions:

1. A regression test that a budget-full channel completes drain **and** flush
   within the deadline. **If it cannot, the budget comes down** — the delivered
   capacity is whatever passes this test, which may be less than 100 MiB.
2. Log the residual queued-record count when the deadline expires, so the
   "some data may not have been written" warning says *how much*. The operator
   in this incident had to infer drop volume from a cumulative counter.

## 6. Testing

Per the repo's three-level requirement:

- **Unit** — capacity arithmetic; `send_timeout` default; per-record footprint
  measurements with the ~2× drift assertion; each changed config default.
- **Integration** — a blocked send succeeds once the writer drains; a wedged
  writer produces a drop after the timeout (with a shortened timeout);
  `MultiZeekHandler` fan-out does not serialise a healthy destination behind a
  stalled one; a budget-full channel completes shutdown within the deadline.
- **E2E** — a real Zeek TCP client outrunning a deliberately slow sink yields
  **zero** `parquet_s3_dropped`, and the client's own socket writes block —
  proving backpressure reached the wire rather than being absorbed silently.

## 7. Deliberately not done

- **Syslog / sFlow / IPFIX backpressure** — UDP cannot backpressure; syslog's
  shared UDP+TCP loop makes blocking actively harmful (§3.1).
- **HEC/WEF/OTLP backpressure**, and the related defect that
  `dispatch_generic_record` (`ingest/handlers.rs:80`) drops a record while
  `handle_hec_event` still returns **200 OK** — silent data loss with a client
  that believes it succeeded. Real bug, reported to the user; fixing it changes
  a client-visible HTTP contract and is beyond this change.
- **Writer sharding** and **extending `RecordBatchAccumulator` past `conn`** —
  throughput work that needs a profile first; only `conn` currently amortises,
  so every other Zeek log type builds a one-row `RecordBatch` per record.
