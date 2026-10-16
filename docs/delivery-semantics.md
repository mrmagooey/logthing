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
flush interval (checked on each arriving record and on a periodic tick of a quarter of the
flush interval, between 1 and 30 seconds, so an idle buffer is flushed within one interval
plus one tick). A crash, `SIGKILL` or power loss loses everything in that window; the spool
does not change this, because it sits **after** the flush. To shrink the window, lower
`flush_interval_secs` and `flush_threshold_bytes`. The trade-off is more, smaller Parquet files
and more work for the Iceberg committer.

A graceful stop (`SIGTERM`/Ctrl-C) flushes every buffer first. A writer only finishes once
every sender of its channel is gone, so on shutdown each listener also stops its per-connection
tasks (Zeek, Suricata and syslog TCP) and waits up to 5 s for them. A connection that is still
open and idle at that moment is not an obstacle: the lines it has already received, including
any the client has sent that are still queued on the socket, are dispatched and flushed. An
unterminated final line (a client that was mid-write) cannot be completed and is dropped; it
is counted in `zeek_partial_lines_dropped_at_shutdown`,
`suricata_partial_lines_dropped_at_shutdown` or `syslog_partial_lines_dropped_at_shutdown`.
A dropped shutdown channel is treated the same as a shutdown signal, so a listener can never
keep running (or spin) after the rest of the process has stopped.

The order is: the HTTP server and the listeners drain concurrently (HTTP up to 10 s; listeners
share one 6 s deadline, the 5 s connection drain plus 1 s margin, after which stragglers are
aborted), then the writers (shared 10 s deadline), then the spool. If the HTTP server or a
listener stops on its own, or the HTTP server task panics during the drain, the same sequence
runs and the process exits non-zero. A drain timeout alone still exits 0 with a warning.

When the HTTP drain times out and the server task is aborted, axum's per-connection tasks may
still hold the application state and so the writers' senders. The writers then reach their
own 10 s deadline without seeing end-of-stream, and rows received since the last periodic
flush can be lost. Only requests still in flight 10 s after the shutdown signal trigger this.

UDP listeners (syslog, IPFIX, sFlow) that hit a persistent receive error pause 10 ms, doubling
to at most 1 s, between attempts instead of spinning, and log the error at most once every
10 s with a count of the repeats suppressed.

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

A failed flush is retried with exponential backoff: 1 s, 2 s, 4 s and so on, capped at 60 s and
at `flush_interval_secs`. No flush starts inside the backoff window, whatever the row and byte
thresholds say; the hard cap above still applies. A successful flush resets the backoff. If a
flush task panics (a bug in a sink), its rows are put back and retried the same way, and
`parquet_s3_flush_panics` is incremented. A task that panics after its
upload succeeded is retried too, so that object can be written twice (at-least-once). At
shutdown the final flush makes a single descriptor attempt per partition, so a descriptor
outage cannot delay the Parquet uploads of later partitions.

When `[iceberg]` descriptors are enabled and the Parquet object was uploaded directly (not
spooled), a failed descriptor upload is retried three more times, after 200 ms, 1 s and 5 s.
Only then is `iceberg_descriptor_upload_errors` incremented. Without `[spool]` the Parquet
object is uploaded either way, but if the descriptor still fails (including the single attempt
made at shutdown) the Parquet is never committed to Iceberg; `iceberg_descriptor_upload_errors`
is the only sign. With `[spool]` the descriptor is retried until it is delivered (see Spool).

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

An entry that carries a descriptor is never deleted without delivering it. If the descriptor
sink is not configured (for example `[iceberg]` was removed from the config), the Parquet is
still uploaded once, but the entry stays on disk and is retried with the normal backoff
(`spool_descriptor_sink_missing`, `spool_upload_errors`) until the descriptor sink is
configured again; then the descriptor is uploaded and the entry removed. Entries written by
earlier releases follow the same rule. Alert on any increase of
`spool_descriptor_sink_missing`: the spool then grows until `max_bytes`, after which flushes
fall back to direct upload.

*Discarding entries stuck on a missing descriptor sink.* If the descriptor sink is gone for
good, stop logthing, then for each stuck entry delete `<id>.meta` first and then
`<id>.parquet` and `<id>.json` (an entry is `<id>.parquet`, `<id>.json` and `<id>.meta`;
stuck entries are the ones that have a `.json`). Start logthing again; the spool rescans on
open. Deleting the `.meta` un-commits the entry, so a half-finished deletion is cleaned up as
an orphan at the next start. The consequence: the Parquet objects were already uploaded to the
data bucket but are never committed to Iceberg, so those rows will not appear in the tables
until you register the objects yourself. Leave entries that have no `.json` alone; they do
not depend on the descriptor sink.

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
time is therefore bounded by 10 s (HTTP and listeners, concurrently) + 10 s (writers) + 2 s
(spool floor) = about 22 s; normally the first stage takes well under a second. **Give the
container at least that long to stop**: Docker's default stop timeout is 10 s, which is shorter,
so set `stop_grace_period: 30s` (Compose) or `--stop-timeout 30`; in Kubernetes keep
`terminationGracePeriodSeconds` at 30 (the default) or higher. A SIGKILL before the writers
finish loses whatever they had not yet flushed.
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
