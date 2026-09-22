# Review fixes (2026-09-22) — design

Fixes the four verified defects from the 2026-09-22 whole-codebase review of
master `baf529f` (v0.20.1). Produced via auto-develop; the decision log below
was checked by an independent coherence reviewer (verdict: coherent).

Branch: `fix/review-2026-09-22`. The fixes land strictly in the order
**#1 → #4 → #2 → #3**, one commit series each. Merging to master is left to
the user.

## #1 (high) Zeek `_path` case mismatch jams a partition's flush

**Bug.** `ZeekSink::partition()`/`schema()` key buffers by
`sanitize_log_path(raw)` (lowercases and maps non-`[a-z0-9_]` to `_`), but
`ZeekSink::to_record_batch` and the six typed accumulators' `try_append`
resolve the mapper via `get_schema_entry(&record.log_path)` on the **raw**
path, and the `REGISTRY` lookup is case-sensitive. So `"_path":"Conn"` is
routed to the `conn` buffer (conn schema), mapped to an envelope batch, and
pushed onto `buf.buffer` unchecked. Every flush of that buffer then fails in
`concat_batches` and is retried forever, until `drop_oldest_to_cap` discards
legitimate rows.

**Fix (root cause).** `get_schema_entry(log_path)`: after the exact
`REGISTRY.get(log_path)` misses, retry with
`REGISTRY.get(sanitize_log_path(log_path))` before falling back to the
envelope. This is one shared function, so all seven callers are fixed. The
fast path is unchanged (no allocation for already-canonical paths). Unknown
paths still build the envelope mapper with the **raw** `log_path`, so the
stored `log_path` column value is unchanged.

**Fix (defence in depth).** In `PartitionedParquetWriter::push`, before a
sink-produced fallback batch is pushed onto `buf.buffer` (the `Ok(false)`
fallback and the no-accumulator `else` branch), reject it if
`batch.schema() != schema`: skip the record rather than poison the buffer.
`Arc<Schema>` equality short-circuits on pointer identity (`Schema: Eq`), so
the normal path costs about nothing. **Required audit:** every
`ParquetSink::to_record_batch` implementation must build its batch with the
`schema` it was given (or a structurally identical one, metadata included);
otherwise the guard would reject all of that sink's records. The full test
suite must stay green.

## #4 (medium) `push()` skip branches are unmetered and unthrottled

**Bug.** The four "skip this record" branches in `push()` (`day_and_batch`
error, two `to_record_batch` errors, live-builder `try_append` error) each emit
an unthrottled `tracing::warn!` and increment no metric.

**Fix.** One private helper on `PartitionedParquetWriter` used by all four
branches **and** #1's schema guard:
- increments a new counter `parquet_s3_records_skipped{source,target}`
  (HELP text added to `src/metrics_descriptions.rs`, where the guard tests
  require it);
- logs at most once per 30 s per writer, carrying the error and the running
  skipped count. This is the same 30 s `Instant`-gate pattern as
  `drop_oldest_to_cap`'s `last_drop_warn`, but stored on the writer (skips are
  not tied to one buffer).

`DropLogThrottles` is not reused: it is keyed by call site × channel
Full/Closed kind, which is a different failure category.

## #2 (medium) WEF batch truncated on XML error but acknowledged 200

**Bug.** `WefParser::parse_events` does `Err(e) => { error!; break; }` on a
quick-xml reader error and returns `Ok(partial)`. The handlers answer 200, so
the forwarder never resends and the rest of the batch is lost.

**Fix.** On a reader error, keep the **entire unparsed remainder** of the body
as one raw `WindowsEvent`, then stop. The remainder runs from the start of the
event currently being parsed if we are inside one, else from the error
position; it is skipped if empty or whitespace-only. This follows the file's
existing rule that unparseable events are kept raw ("Still add raw event").
Increment a new counter `wef_xml_parse_errors` and keep the log line. Nothing
is dropped, so 200 is accurate.

Rejected alternatives: returning 4xx/5xx makes a permanently malformed batch
retry forever and block that forwarder; resyncing at the next `<Event` needs a
hand-rolled scanner that can false-positive on `<Event` text inside CDATA.
Accepted trade-off: well-formed events *after* the malformed one land as one
unparsed raw row rather than as individually parsed events. Windows produces
well-formed XML, so this path is effectively only hit by broken or hostile
clients.

## #3 (medium) TCP accept loops spin on persistent accept errors

**Bug.** Eight TCP accept sites (syslog ×4, zeek ×2, suricata ×2) log an
accept `Err` and immediately re-poll. For errors like EMFILE, tokio does not
clear readiness, so the loop spins at 100% CPU with a log flood.

**Fix.** Add `AcceptBackoff` to `src/net.rs`:

```rust
let mut backoff = AcceptBackoff::new("syslog_tcp");
// in loop / select!:
result = backoff.accept(&listener) => { ...unchanged Ok/Err handling... }
```

`accept()` first sleeps until any stored pause deadline, then clears it, then
calls `listener.accept()`. The deadline is cleared only **after** the sleep
completes, so if `select!` drops the future mid-sleep the pause survives:
this is cancel-safe, and it keeps co-resident arms (syslog's UDP receive,
shutdown) live. That is why a plain `sleep` in the error arm is rejected.
Policy follows `axum::serve`/hyper: `ConnectionRefused`,
`ConnectionAborted` and `ConnectionReset` are per-connection errors and get no
pause; any other error sets a 1 s pause. Each error increments
`listener_accept_errors{protocol}`, with the protocol label a `&'static str`
from the same fixed set `listener_source_rejected` uses (`syslog_tcp`,
`zeek`, `suricata`, verified per site). Existing per-site log lines stay; the
pause bounds them to about 1 per second.

## Tests (all three levels, per fix)

| Fix | Unit | Integration | E2E |
|---|---|---|---|
| #1 | `get_schema_entry("Conn")` resolves typed conn; push guard rejects a mismatched batch | writer: push `"Conn"` + `"conn"` records, flush to local disk, flush **succeeds**, conn Parquet holds both rows (extend/replace `mismatched_raw_log_path_falls_back_to_envelope_not_conn_accumulator`) | real `ZeekListener` over TCP → `zeek_local_start` → mixed-case `_path` lines land in a readable conn Parquet file |
| #4 | helper increments counter and throttles log (injected clock or two calls within 30 s) | writer with a sink whose `to_record_batch` fails: counter equals skipped count, other records still flush | real server `/metrics` exposes `parquet_s3_records_skipped` after a forced skip, or an explicit justification if no outer-interface trigger exists |
| #2 | `parse_events` with a malformed middle event: preceding events parsed, remainder kept raw, nothing lost | handler via router: 200 and the sink receives prefix events + raw remainder | real `Server` over HTTP `/wsman` with a malformed batch → 200, local Parquet contains the raw remainder; `wef_xml_parse_errors` visible on `/metrics` |
| #3 | error classification + pause deadline set/cleared; cancel-safety (drop mid-sleep, pause persists) with paused tokio time | real listener loop + induced accept errors: bounded error count per second | dedicated single-test binary: lower `RLIMIT_NOFILE`, exhaust fds, connect to a real listener → `listener_accept_errors` grows ≤ ~2/s, and the listener recovers once fds are freed |

Guards are verified by mutation: revert the fix, confirm the test goes red.

## Out of scope

- IPFIX variable-length fields (0xFFFF).
- UDP receive-error arms (no persistent error there).
- `metric_log_path` casing.
- Follow-up found during review: in `ZeekSink::to_record_batch`'s else-branch,
  an `_overflow`-routed record's envelope `log_path` column gets the
  placeholder `"_overflow_nonexistent_"` instead of the real path.
- Deliberately untouched: `FlushIntervalRegistry`, `*_start`/`*_local_start`
  pairs, Kerberos ordering, aggregate 2 s sleep.
