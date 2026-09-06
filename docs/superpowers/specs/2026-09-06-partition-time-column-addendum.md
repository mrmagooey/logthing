# Addendum: materialised `partition_time` column

**Date:** 2026-09-06
**Status:** approved (user-directed)
**Amends:** `2026-09-05-day-clean-parquet-partitions-design.md`

## Why the original design was wrong

The parent spec made the buffer day-clean with respect to
`coalesce(time_column, received_at)`. **That quantity is not a column**, and an
Iceberg partition transform takes exactly one source field — so no transform
names the value the file is actually clean on.

Two rows in one buffer can reach the same day via different columns:

- Row A: `timestamp` = today 10:00 -> day = today
- Row B (CEF; `SyslogMessage::parse` returns `timestamp: None`, `src/syslog/mod.rs:313`):
  `received_at` = today -> day = today

One file, declared `day=today`, but `day(timestamp)` over it yields
`{today, null}` — two partition values in one data file. Iceberg must refuse it.

Partitioning the committer on `received_at` instead does not rescue it: buffer
`{"", 09-05}` can hold `timestamp`=09-05 23:59 (arriving 09-06 00:00:30,
`received_at`=09-06) beside a null-`timestamp` row with `received_at`=09-05.
`day(received_at)` = `{09-06, 09-05}` — the original straddling bug exactly.

Broken for **syslog, structured_syslog, generic/HEC, and Zeek's envelope path**.
Correct already for suricata, sflow, ipfix, WEF, aggregate — all five name a
non-null column, so every row in a buffer genuinely shares that column's day.

## The fix: materialise the derived instant

Every sink's schema gains one **non-null** column:

```rust
Field::new(
    "partition_time",
    DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
    false,
)
```

It holds **exactly the instant the buffer day was derived from**, so
`day(partition_time)` equals the file's declared day by construction, for every
row, unconditionally. `time_column()` returns `Some("partition_time")` for all
nine sinks, and `day_from_batch` collapses to a single non-null column read (its
`received_at` / `now` arms remain only as defensive fallbacks and become
unreachable for opted-in sinks).

This is what the originating ticket asked for. The parent spec rejected it on the
grounds that descriptor min/max stats "already give the committer everything it
needs" — true only when the partition column is non-null, which is precisely the
condition that fails here.

**Cost is near zero.** `partition_time` is constant within a file (it IS the
buffer key), so Parquet's encoding compresses it to almost nothing.

## Derivation: a pure function of the record, no clock read

Every record type already carries a non-null receipt instant —
`ZeekRecord::received_at` (`src/zeek/mod.rs:15`), `SuricataRecord`, `SflowRecord`,
`WindowsEvent`, `GenericRecord`, `StructuredSyslogRecord` — even where the schema
does not expose it as a column (Zeek's 6 typed schemas). So:

```
partition_time(event: Option<DateTime<Utc>>, received_at: DateTime<Utc>) -> DateTime<Utc>
```

- `None` -> `received_at`
- `Some(t)` outside the clamp window -> `received_at`
- otherwise -> `t`

No `Utc::now()` anywhere in the derivation. It is deterministic and directly
unit-testable, and it removes the last path where two clock reads either side of
midnight could disagree.

`SyslogMessage` is the one type with no `received_at` field (deliberately — it is
`Serialize`/`Deserialize` and consumed by `aggregate/fields.rs` and
`channel_budget.rs`). Its mapper already stamps `Utc::now()` once for the
`received_at` column; `partition_time` uses that same stamped value, so the two
cannot disagree.

## Clamp window (closes the untrusted-fan-out finding)

Day fan-out was driven by untrusted input with no ceiling: a sender emitting N
distinct dates minted N live buffers, each becoming its own small Parquet PUT plus
descriptor PUT. Reachable via syslog timestamps, IPFIX `export_time` (32-bit,
unauthenticated UDP) and HEC `time`. Structurally impossible before the parent
branch, which produced one file per flush regardless of timestamps.

The clamp is relative to `received_at`, which logthing stamps itself and a remote
sender cannot influence:

```rust
/// Widest backfill accepted from a record's own timestamp. Beyond this the
/// record is bucketed by receipt time instead, bounding live buffers to
/// roughly this many days per partition no matter what a sender claims.
const MAX_BACKFILL: chrono::TimeDelta = chrono::TimeDelta::days(30);
const MAX_SKEW: chrono::TimeDelta = chrono::TimeDelta::days(1);
```

Accept `received_at - MAX_BACKFILL ..= received_at + MAX_SKEW`; otherwise use
`received_at`.

**Known tradeoff:** a genuine backfill deeper than 30 days is bucketed by receipt
time rather than event time. It is not dropped and not mis-typed — the event
timestamp remains queryable in its own column — but such files partition by when
they were ingested. Widen `MAX_BACKFILL` if deep replay matters more than the
fan-out bound.

## Also in scope (final-review findings 3-5)

- `WefSink::schema` builds a fresh `Arc<Schema>` per call; `push()` now calls
  `schema()` unconditionally per record, so this is ~7 heap allocations per
  Windows event that did not exist before. Make it a `LazyLock` like every other
  sink.
- `known_partitions.insert(effective_partition.clone())` runs on every push
  including the ~100% already-known case, and the `contains` two lines above
  already computed the answer. Guard the insert.
- A buffer inserted before a `to_record_batch` failure keeps `row_count == 0`,
  so `flush_all_if_needed` skips it and it never reaches the reaping in
  `apply_flush_outcome`'s success arm. Pre-branch this leaked at most one entry
  per partition; it now leaks one per `(partition, day)`, plus a fully-allocated
  accumulator for `new_batch` sinks.

## Testing

- **Unit:** the derivation function — null event, event inside window, event past
  the backfill bound, event beyond the skew bound, and exact boundaries.
- **Integration:** a buffer mixing null-event and non-null-event rows flushes to a
  file whose `partition_time` column holds exactly one distinct day. This is the
  case the parent branch's tests never constructed and is the regression test for
  this addendum.
- **E2E:** mixed RFC 5424 + payload-parsed (null-timestamp) syslog through
  `handle_message`; every written file day-clean on `partition_time`.

Version stays **0.16.0** — already an unreleased breaking schema change on this
branch, and this only widens it.
