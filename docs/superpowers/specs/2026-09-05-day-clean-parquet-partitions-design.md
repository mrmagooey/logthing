# Day-Clean Parquet Partitions — Design

**Date:** 2026-09-05
**Status:** approved (user-directed)
**Supersedes/extends:** `2026-09-03-parquet-timestamp-typing-design.md` (v0.15.0)

## Problem

The downstream Iceberg integration is a real catalog-writing process. It reads
the `IcebergDescriptor` sidecar (`src/forwarding/iceberg_descriptor.rs`) —
per-column Parquet-native `min`/`max` plus `physical_type` — and computes each
data file's partition tuple from the decoded timestamp bound.

Iceberg requires **every row in a data file to belong to that file's declared
partition tuple**. A buffer that fills across midnight produces a Parquet file
whose rows span two UTC days: `min(ts)` and `max(ts)` decode to different days,
no single `day()` value is true for all rows, and registration must either be
refused or produce a table whose partition pruning silently drops rows.

With per-sink `flush_interval_secs` in the 900s range, roughly one straddling
file is produced per active partition per day. Zeek runs up to 256 partitions.

## Rejected approach: midnight-aligned flush

Forcing a flush at the UTC day boundary was considered and rejected. It
approximates the event day from wall-clock timing, and four independent code
paths defeat that approximation:

1. **Key stamping runs after encode.** `build_key(..., Utc::now())`
   (`buffered_writer.rs:989`) executes after the zstd encode completes in
   `spawn_blocking`. A flush triggered at 00:00:00 stamps on day N+1, so the
   batch holding day N's tail is systematically misfiled — inverting the intent.
2. **The timer has no calendar.** The trigger is `buf.last_flush.elapsed() >=
   interval` on a monotonic `Instant`. `s3_sink::flush_check_interval` clamps the
   poll cadence to the flush interval itself, so landing near midnight requires a
   new wall-clock trigger *and* a cadence change.
3. **The retry path re-dates data.** On failure `apply_flush_outcome`
   (`buffered_writer.rs:792-797`) pushes batches back into the live buffer and
   re-stales `last_flush`; they are re-encoded later alongside newer records
   under a fresh `Utc::now()`.
4. **Late arrivals are immune to flush timing.** Arrival != event time. Zeek
   rotation boundaries (`zeek/listener.rs:397`) bulk-deliver already-old data.

Even with all of (1)-(3) fixed, the result stays approximate. "Almost always
right" is the worst property for a partition filter: it drops rows silently
rather than visibly.

## Chosen approach: split the batch by event day at flush time

Bucket rows by UTC day from the data itself, at the point of flush. Exact by
construction, and immune to all four objections above — none of them concern the
data's own timestamps.

### Mechanism: day as part of the buffer key

Records are mapped to a single-row `RecordBatch` **at push time** (`ParquetSink::
to_record_batch`), and the writer holds buffers in a map keyed by partition
segment. So the event day is knowable at push, from the just-mapped batch.

Therefore: **make the UTC day part of the buffer key**, rather than splitting a
mixed batch at flush time.

```
buffers: HashMap<String, Buf>   ->   buffers: HashMap<BufKey, Buf>
                                     BufKey { partition: Option<String>, day: NaiveDate }
```

Each buffer is then day-clean by construction, and everything downstream is
untouched: one buffer -> one file -> one descriptor -> one `FlushOutcome`.

This was chosen over splitting the concatenated batch inside `encode_and_upload`
for one decisive reason: **partial failure**. A flush-time split producing N
files has no correct `FlushOutcome` when file 3 of 5 fails to upload — returning
`Failure` with all batches re-uploads the four that succeeded (duplicate rows
visible in the Iceberg table), and returning only the failed subset means
reconstructing `batches`/`row_count`/`byte_count` from buckets and rewriting the
retry accounting in `apply_flush_outcome`. Keying the buffer sidesteps the
problem entirely: `encode_and_upload` still handles exactly one file and its
existing retry semantics stay correct with no change.

### Deriving the day

`ParquetSink` gains a `time_column()` seam (below). At push, the writer reads
that column from the freshly-mapped single-row batch to compute the day.

Because the mapped batch is the single source of the day, syslog's `Utc::now()`
`received_at` stamp and the buffer key can never disagree — the key is derived
from the stamped value itself, not from a second clock read.

**Amortized-builder path.** `ParquetSink::new_batch` (`buffered_writer.rs:95`)
returns a `RecordBatchAccumulator` producing *multi-row* batches, which could
straddle a day. The implementer must handle this: check each record's day before
appending and finish the accumulator when the day changes, so an accumulator
never spans two days. Sinks that opt out of `new_batch` are unaffected.

### Key stamping

Once the bucket's day is known, `build_key` takes that day instead of
`Utc::now()`. The Hive-style `year=/month=/day=` path segments stop disagreeing
with the data. Cosmetic for a real catalog writer (Iceberg tracks files by
explicit manifest path, never by directory name), but free given the day is
already in hand, and it removes a standing source of confusion.

### Memory

Buffer count becomes partition x active-days. In steady state active days is 1,
briefly 2 around midnight. `max_buffer_rows` is per-buffer, so the worst-case
memory bound scales with the number of concurrently-live days — acceptable in
steady state, and the same fan-out a flush-time split would produce anyway, just
held slightly longer.

**Empty day-buffers must be reaped** once flushed, or a long-running process
accumulates one dead buffer per partition per day elapsed.

## Syslog `received_at`

`syslog_s3.rs` is the only sink with no `received_at` column; its sole time
column is a **nullable** `timestamp` (`syslog_s3.rs:29-33`). Rows whose
timestamp failed to parse would have no event day.

**Decision (user-directed):** add a non-null `received_at` column to the syslog
schema, making it consistent with every other sink and guaranteeing an
always-present partition source.

`SyslogMessage` (`src/syslog/mod.rs`) is deliberately NOT given a new field: it
is `Serialize`/`Deserialize` (adding a field changes JSON forwarding output) and
is consumed by `aggregate/fields.rs` and `channel_budget.rs`. Instead the value
is stamped at the sink's row-mapping boundary with `Utc::now()`, mirroring
`StructuredSyslogRecord::from`, which stamps `received_at: Utc::now()` at record
construction (`src/syslog/payload/mod.rs:98`).

Row mapping occurs per-push, so the stamped value is receipt-accurate. **The
implementer must verify this holds on the amortized `new_batch` builder fast
path as well** (`ParquetSink::new_batch`, `buffered_writer.rs:95`); if that path
batches records before mapping, the stamp must move to the push site.

Partition source for syslog is then `timestamp`, falling back to `received_at`
when null.

## Per-sink partition column

| Sink | Column | Notes |
|---|---|---|
| zeek (7 schemas) | `ts` | |
| syslog | `timestamp` -> `received_at` | fallback when null |
| structured_syslog | `timestamp` -> `received_at` | fallback when null |
| generic/HEC | `time` -> `received_at` | fallback when null |
| suricata | `received_at` | non-null |
| sflow (flow + counter) | `received_at` | non-null |
| ipfix | `export_time` | non-null; `flow_start`/`flow_end` nullable |
| WEF | `timestamp` | already fed `received_at` |
| aggregate | `window_start` | |

## Accepted costs

- **Backfill fan-out.** A bulk replay spanning many days splits one flush into
  many small files. Bounded by the data, and unavoidable: a file spanning 365
  days is unregisterable regardless.
- **Per-push day extraction.** Reading one timestamp value from a single-row
  batch, negligible against mapping and encoding.
- **More live buffers.** See Memory above.

## Out of scope

- Iceberg manifest/catalog writing — remains entirely the external committer's job.
- Hour-granularity partitioning. Flush sizing (128MiB / 100k rows / ~900s) makes
  one-file-one-partition-tuple routinely unachievable at hour granularity.
- Any materialised date/time column. The descriptor's min/max stats plus
  v0.15.0's real `Timestamp(Microsecond, UTC)` types already give the committer
  everything it needs; a stored column would be a redundant fourth copy.

## Testing

Per repo policy, all three levels:

- **Unit** — day bucketing (single bucket, multi bucket, null fallback, empty),
  `build_key` taking an explicit day, syslog schema shape and `received_at`
  nullability.
- **Integration** — flush producing N files + N descriptors for a straddling
  buffer; descriptor min/max landing in the same day per file; retry path
  re-splitting correctly.
- **E2E** — ingest spanning a day boundary through a sink, assert every written
  Parquet file is day-clean.
