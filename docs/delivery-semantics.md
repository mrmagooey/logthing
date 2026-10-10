# Delivery semantics

What logthing guarantees about a record between "the sender got a success response" and "the
record is durable in object storage", what it does not, and how to tune the gap. For the
`[spool]` keys see [configuration.md](configuration.md#spool); for metrics see
[metrics.md](metrics.md).

## Per-source guarantees

What the sender observes when logthing is overloaded (the writer channel is full), and which
metric shows loss:

| Source | Behaviour on a full channel | Sender observes | Loss metric |
|---|---|---|---|
| HEC (`/services/collector/*`), NDJSON (`/ingest`), OTLP over HTTP | Request rejected | `503` + `Retry-After: 1` (HEC code 9 "Server is busy"); the client is expected to retry | `hec_events_dropped`, `otlp_events_dropped` count records not enqueued |
| WEF (`/wsman/subscriptions/<uuid>`) | Event dropped, request still Acked | `200` with an Ack (WEF is **not** backpressured: Windows advances its bookmark and does not resend, so the loss is silent). Bookmarks are held in memory, so after a restart clients have no bookmark and resume from now, or from the earliest event if `read_existing_events = true` (duplicates or gaps) | `parquet_s3_dropped{source="wef"}` |
| Syslog UDP, IPFIX, sFlow | Kernel socket buffer overflows before logthing reads | Nothing (UDP has no feedback) | `syslog_udp_socket_drops`, `ipfix_socket_drops`, `sflow_socket_drops`; `parquet_s3_dropped{source}` for records that were read but not enqueued |
| Syslog TCP | Record dropped when the channel is full (non-blocking enqueue) | Nothing; the connection stays open | `parquet_s3_dropped{source="syslog"}` |
| Zeek, Suricata (TCP) | The connection task waits up to 5 s for channel space, so the sensor sees TCP backpressure; after the wait the record is dropped | Slow socket, then silence | `parquet_s3_dropped{source="zeek"\|"suricata"}` |

Retried HTTP requests get fresh `event_uuid`s, so a client retry after a `503` that accepted
part of a batch produces duplicate rows (see [At-least-once](#at-least-once-and-duplicates)).

## Where data lives before it is durable

```
accepted -> channel -> in-memory partition buffer -> encode (Parquet) -> sink
```

A record is only in memory from the moment it is accepted until its partition is flushed.
Flushes fire on `flush_interval_secs`, `max_buffer_rows` or `flush_threshold_bytes`, whichever
comes first. Only one flush per partition is in flight at a time: rows that cross
`max_buffer_rows` / `flush_threshold_bytes` while a flush is running are flushed as soon as
that flush completes, while rows below the thresholds wait for the next trigger, up to one
flush interval (checked on the periodic tick and on each arriving record). A
crash, `SIGKILL` or power loss loses everything in that window; the spool does not change
this, because it sits **after** the flush. To shrink the window, lower `flush_interval_secs`
and `flush_threshold_bytes`. The trade-off is more, smaller Parquet files and more work for the
Iceberg committer.

A graceful stop (`SIGTERM`/Ctrl-C) flushes every buffer first, with one exception. A writer
only finishes once every sender of its channel is gone. Zeek and Suricata connections run in
detached tasks that keep a sender, so while a sensor is still connected at shutdown those
writers do not finish: the 10 s writer deadline expires (`S3 writer flush timed out`), the
process exits, and rows buffered since the last periodic flush are lost (they never reach the
spool). Other sources release their senders when their listeners are aborted.

## Local sink

Local-disk sinks write `<file>.tmp`, fsync it, rename it into place and fsync the directory,
so a crash leaves either the whole file or none. A failed directory fsync is counted in
`local_sink_dir_fsync_errors` (the file exists; crash durability is not guaranteed). fsync
itself is not observable from a test, so the tests check the observable result (no partial
files, content readable) rather than the syscalls.

## Spool

Without `[spool]`, a failed S3 upload is retried from memory: the rows go back into the
writer's buffer, capped at `max_buffer_rows * 4`; beyond the cap the oldest rows are dropped
(`parquet_s3_buffer_dropped`). A long outage or a restart loses them.

With `[spool]`, every S3 flush is first written to local disk and acknowledged to the writer,
then uploaded in the background:

```toml
[spool]
dir = "/var/lib/logthing/spool"   # DEDICATED directory
max_bytes = 10737418240           # default 1 GiB
```

**Entry format.** One entry per flush: `<id>.parquet`, an optional `<id>.json` (the Iceberg
descriptor) and `<id>.meta`, the commit marker. `<id>` is `{unix_micros:020}-{uuid}`, so
lexical order is age order and the uploader works oldest first.

**Commit protocol.** Each file is written as `<name>.tmp`, fsynced and renamed; the directory
is fsynced after the data renames, then the `.meta` is written the same way and the
directory fsynced again. An entry exists only once its `.meta` does, so a crash never leaves a
committed entry with missing data. Deletion removes the `.meta` first.

**Uploader.** For each entry: PUT the Parquet, then the descriptor, always under the **same
keys**; the entry is deleted only after the descriptor PUT succeeds. Once the Parquet PUT has
succeeded, retries (after a descriptor failure) upload only the descriptor, so a descriptor
outage does not re-PUT the Parquet each time; this is remembered in memory only, so a restart
in the middle of retries may PUT the Parquet once more. Failures retry with exponential
backoff, 1 s doubling to 60 s (`spool_upload_errors`).

**Concurrency.** Up to 4 entries upload at the same time, in the steady-state uploader and in
the shutdown drain. Entries are started oldest first; one entry is never attempted twice at
once; within an entry the Parquet always precedes the descriptor. Backoff is per entry. A
drain of K entries against a slow sink takes about ceil(K/4) attempt durations instead of K,
and the drain deadline still bounds every started attempt.

**Startup replay.** On start the spool directory is scanned and every committed entry is
uploaded. Entries whose files are missing, whose size or sha256 does not match the `.meta`, or
whose `.meta` version is unknown are moved to `<dir>/corrupt/` (`spool_corrupt`). An entry
that cannot be read right now (EIO, permissions) is left in place, counted in
`spool_unreadable` and `spool_bytes`, and retried **only at the next start**, not while
running. Entries for a sink id that no longer exists (after a config change) are left on disk
untouched.

**The spool directory must be dedicated.** `open()` deletes every `*.tmp` file and every
`*.parquet` / `*.json` file that has no matching `.meta` (uncommitted orphans of a crash).
Pointing `dir` at a directory with other Parquet or JSON files destroys them.

**Spool full or write error.** If committing would exceed `max_bytes`, or the write fails, the
flush falls back to the pre-spool behaviour: a direct upload, and if that fails, the
in-memory requeue described above. `spool_rejected{reason="full"|"io"}` counts these.

**Shutdown.** The final flush of every writer lands in the spool (a local write, fast even
with S3 down). The uploader is then given whatever remains of the 10 s writer deadline, but
at least 2 s, to drain; anything left replays on the next start. The real worst-case shutdown
time is therefore about the writer deadline plus the 2 s drain floor (about 12 s), not 10 s.
A drain that is cut short logs `spool not fully drained at shutdown`.

**An upload cancelled after its PUT** (shutdown, timeout) leaves the entry on disk; the next
attempt re-uploads the same keys, which is an idempotent overwrite.

**What the spool does not protect:** records still in the channel or the in-memory buffer at
`SIGKILL`; entries on a lost or corrupted disk; entries of unknown sink ids.

**Sizing and alerting.** Set `max_bytes` to at least (flush rate x bytes per flush) x the
longest outage you want to ride out. Alert on `spool_entries > 0` for 15 minutes,
`increase(spool_upload_errors_total[10m])`, `increase(spool_rejected_total[5m]) > 0` and
`increase(spool_corrupt_total[1h]) > 0`.

## At-least-once and duplicates

Delivery is at-least-once. Replay re-uploads the same keys, so a repeat is an idempotent
overwrite of an identical object. A crash between the Parquet and descriptor PUTs repeats both
on replay; the committer is idempotent on `file_path`, so the table sees one file.

Duplicates that **do** reach the table are client-driven: a retried HEC/NDJSON/OTLP request,
or a `503` after partial acceptance, produces rows with distinct `event_uuid`s.
`event_uuid` (UUIDv7) identifies a stored row, not a client event; de-duplicate downstream on
an application-level id carried in the event, never on `event_uuid`.

## Object Lock interplay

On a bucket with Object Lock, every upload creates a new locked object version, so a replayed
entry adds a new version (and a new retention period) rather than overwriting. A restart
while a descriptor upload is failing may re-PUT the Parquet once. See
[object-lock.md](object-lock.md).
