# committer — Iceberg descriptor committer

logthing writes Parquet files to S3-compatible object storage and, for every
file, drops a small JSON *descriptor* next to it under a descriptor prefix
(default `_iceberg_descriptors/`), describing what it wrote: source,
optional partition, the file's location, row/byte counts, and per-column
Parquet statistics (see logthing's `src/forwarding/iceberg_descriptor.rs`).

`commit.py` drains that prefix as a work queue: for every descriptor it
resolves the referenced Parquet file, derives an Iceberg table name, and
registers the file into that table via `add_files` — **no rewrite**, the
data file is adopted in place and simply becomes table-owned. Descriptors
are moved to `DONE_PREFIX` once committed, or to `QUARANTINE_PREFIX` if
they're broken beyond repair.

Each run is idempotent: a descriptor naming a file already registered in its
target table is skipped and moved straight to `DONE_PREFIX`, so a crash
between committing a batch and moving its descriptors is harmless on the
next run.

Intended to run as a periodic job (cron, a Kubernetes CronJob, etc.) against
any Iceberg REST catalog and any S3-compatible object store.

## What it does, per run

1. List `DESC_PREFIX`, one page at a time.
2. For each descriptor: parse its `file_path` down to a bucket-relative key,
   and derive the target table name from `source` (and, for a few sources,
   `partition` — see [Table naming](#table-naming) below).
3. Group descriptors by target table and commit each table's pending group
   in chunks of at most `BATCH_SIZE` — one `add_files` call per chunk, not
   per file.
4. Create a table if it doesn't exist yet (schema inferred from the first
   file's Parquet footer), partitioned by `day(partition_time)`. Existing
   tables are checked for that partition spec on every load, not just once
   at creation, and get it added if missing.
5. Move each chunk's descriptors to `DONE_PREFIX` once that chunk's commit
   succeeds.

A descriptor whose failure is attributable to itself (a schema mismatch, a
missing data file, a malformed descriptor) is quarantined to
`QUARANTINE_PREFIX` and the run continues with the rest of the queue. A
failure that isn't attributable to any one descriptor — the catalog or S3 is
unreachable or returning 5xx, an Iceberg commit conflict, or a
credentials/bucket-config problem that would hit every descriptor the same
way — aborts the run instead, leaving every not-yet-committed descriptor in
the queue — see [Error classification](#error-classification).

## Table naming

Table names come from descriptor fields (`source`, `partition`), never from
the Parquet key path, so table identity survives any future change to
logthing's key layout:

| `source` | `partition` | Table |
| --- | --- | --- |
| `zeek` | `conn`, `dns`, ... | `zeek_<partition>` |
| `aggregate` | `<rule name>` | `agg_<rule name>` |
| `sflow` | `flow`, `counter` | `sflow_<partition>` |
| anything else | (ignored) | `<source>` |

`zeek`, `aggregate` and `sflow` are special-cased because their sinks emit a
genuinely different Arrow schema per partition (a Zeek stream's typed
schema, one schema per aggregation rule, and sFlow's disjoint flow/counter
column sets, respectively — see each sink's `ParquetSink::schema(&self,
partition)` in logthing's `src/forwarding/`). Folding partitions with
different schemas into one table would fail `add_files` with a schema
mismatch after the first partition. Every other sink returns one fixed
schema regardless of partition, so it's safe — and simpler — to share one
table across all of that source's partitions.

Table/partition segments are sanitized to `[a-z0-9_]` and capped at 64
characters; a missing partition for `zeek`/`aggregate`/`sflow` becomes
`unknown`.

## file_path parsing

`file_path` is required; there is no fallback field name and no
reconstructing a data path from the descriptor's own key. Only
`storage_target: "s3"` descriptors can be committed (Iceberg needs an object
store; `storage_target: "local"` descriptors are rejected as a permanent
error).

Three URL shapes are accepted:

- **Path-style**: `http(s)://host[:port]/<bucket>/<key>` — what logthing's
  own S3 sink always emits (it forces path-style addressing), and the
  natural default for MinIO, Garage and most other S3-compatible stores.
- **Virtual-hosted style**: `https://<bucket>.<host>/<key>`.
- **`s3://<bucket>/<key>`**, directly.

A `file_path` naming any bucket other than `DATA_BUCKET` is a permanent
error.

## Error classification

`should_abort(exc)` decides whether a failure aborts the run, leaving every
not-yet-committed descriptor queued, or quarantines just the one
descriptor/file that hit it. Abort covers two kinds of failure that both
make quarantining the wrong move: **transient** (retrying later might
succeed) and **systemic** (a config/credentials problem that will hit every
descriptor the same way — quarantining "the" bad one would silently drain
the whole queue into `QUARANTINE_PREFIX` for a problem that has nothing to
do with any of them).

**Abort** (leave descriptors queued):
- the Iceberg catalog is unreachable, times out, or returns any
  `pyiceberg.exceptions.RESTError` other than `BadRequestError` — this
  covers 5xx (`ServerError`/`ServiceUnavailableError`), auth/config errors
  (`UnauthorizedError` 401, `ForbiddenError` 403, `AuthorizationExpiredError`
  419, `OAuthError`), and `CommitStateUnknownException` (an ambiguous commit
  outcome — safer to not assume it failed). `BadRequestError` (400) stays
  permanent: that's a bad request for one specific table/commit, not
  something wrong with the whole run;
- a `requests` connection/timeout error before any response arrives;
- `CommitFailedException` (a commit conflict);
- S3 connection errors (`botocore.exceptions.EndpointConnectionError` /
  `ConnectionClosedError`), or a `ClientError` with a 5xx status, a
  throttling error code, an HTTP 401/403, or a code that means the
  credentials/bucket themselves are wrong (`AccessDenied`,
  `InvalidAccessKeyId`, `SignatureDoesNotMatch`, `NoSuchBucket`,
  `ExpiredToken`);
- an `OSError` from pyarrow's S3 filesystem that isn't a
  `FileNotFoundError` (DNS failure, connection refused/reset, timeout,
  permission denied).

**Permanent** (quarantine just this one, everything else not listed above):
schema mismatch, a missing data file (`NoSuchKey`/404 on that one object, or
pyarrow's `FileNotFoundError`), a malformed descriptor, an unsupported
storage target, or a catalog `BadRequestError` for one table's request.

When genuinely unsure, `should_abort` leans toward abort: quarantine means a
human has to go triage it, a wrongly-aborted run just costs one retry on the
next invocation.

Within one chunk commit, a permanent failure triggers a one-file-at-a-time
retry of that chunk, so only the actually-broken file is quarantined and the
rest of the chunk still commits.

## Configuration (environment)

| Variable | Required | Default | Purpose |
| --- | --- | --- | --- |
| `DATA_BUCKET` | yes | — | Bucket holding both data files and descriptors |
| `S3_ENDPOINT` | yes | — | S3-compatible endpoint URL (`http://` or `https://`) |
| `S3_ACCESS_KEY` | yes | — | Access key |
| `S3_SECRET_KEY` | yes | — | Secret key |
| `CATALOG_URI` | yes | — | Iceberg REST catalog URI |
| `S3_REGION` | no | `us-east-1` | |
| `WAREHOUSE` | no | `warehouse` | Catalog warehouse name |
| `ICEBERG_NAMESPACE` | no | `logs` | Target namespace, created if absent |
| `DESC_PREFIX` | no | `_iceberg_descriptors/` | Work queue |
| `DONE_PREFIX` | no | `_committed/` | Successfully committed descriptors |
| `QUARANTINE_PREFIX` | no | `_quarantine/` | Descriptors needing manual triage |
| `BATCH_SIZE` | no | `500` | Max descriptors per `add_files` commit, per table |

No credentials are baked into the script; everything comes from the
environment. `main()` (real S3 client, real `RestCatalog`, real pyarrow
`S3FileSystem`) is the only place that reads the environment or builds a
network client — `run(cfg, s3, catalog, pa_fs)` takes them as arguments,
which is what makes it possible to test against local fakes/real-but-local
collaborators instead.

## Notable implementation constraints

- **`PyArrowFileIO` is forced on every table.** A REST catalog hands back
  tables using `FsspecFileIO`, which needs `s3fs` — whose `aiobotocore` pin
  routinely conflicts with pyiceberg's own `boto3` requirement.
  `PyArrowFileIO` needs no extra dependency and writes to any
  S3-compatible store fine via the `s3.*` properties. The catalog's own
  `py-io-impl` property is ignored for REST-loaded tables, so the FileIO is
  overridden explicitly before a table is read or written.
- **`s3.force-virtual-addressing` is set to the string `"False"`, not the
  Python value `False`.** pyiceberg's catalog/FileIO properties are typed as
  `Dict[str, str]`, and its own `property_as_bool()` treats a falsy value —
  including the Python bool `False` — as "absent" rather than "false".
  Every boolean-valued property is passed in its string form for this
  reason.
- **Day partitioning only.** `add_files` infers a file's partition value
  from Parquet column min/max stats and raises if they straddle a boundary.
  logthing keys its write buffers by (partition, UTC day), so every file is
  day-clean by construction — do not widen this to `hours()`, which would
  not hold.
- **`add_field()` by column name**, not a `PartitionSpec` passed to
  `create_table()`. With a raw `pa.Schema`, the catalog's schema-conversion
  path assigns every field id `-1`, and partition-spec id assignment then
  resolves `source_id → name` against that all-`-1` schema with a
  last-wins map — correct here only because `partition_time` happens to be
  the last column. Not a style choice.
- **The day spec is re-checked on load, not just on create.**
  `create_table()` and `update_spec()` are two separate catalog commits with
  no compensation: if the first succeeds and the second doesn't (a
  transient REST error, a commit conflict), a table would otherwise be
  permanently unpartitioned. Re-checking on load makes that self-healing.
- **Batching keeps queue memory bounded.** Descriptors are listed one S3
  page at a time and grouped only as small `(descriptor_key, uri)` pairs —
  the Parquet data itself is never loaded into memory by this script. This
  bounds memory against queue size, not against table size: the per-table
  already-committed-file cache (`committed_file_set`) holds one path per
  file already registered in that table, so it scales with how many files
  the table already has, independent of how many descriptors are queued.

## Running the tests

```sh
python3 -m venv committer/.venv
committer/.venv/bin/pip install -r committer/requirements-dev.txt
committer/.venv/bin/pytest committer/tests -q
```

- `tests/test_unit.py` — pure functions only: table naming, `file_path`
  parsing, `should_abort`, exit-code logic. No network, no S3, no catalog.
- `tests/test_integration.py` — real collaborators: moto's
  `ThreadedMotoServer` as a local S3 (used by both `boto3` and pyarrow's
  `S3FileSystem`), and pyiceberg's `SqlCatalog` backed by SQLite in a temp
  directory standing in for the production `RestCatalog`. Writes real,
  day-clean Parquet files and drives `run()` end to end, then verifies
  results by scanning the resulting Iceberg tables. Slower than the unit
  tests (real HTTP round trips against local moto) but exercises the real
  add_files/partitioning/batching/idempotency/error-handling behavior.
