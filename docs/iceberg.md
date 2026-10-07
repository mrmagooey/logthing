# Iceberg descriptor output

Optionally, logthing can emit a small JSON "descriptor" file alongside
every Parquet file it writes, describing the file (row count, byte size,
partition, per-column stats, fully-qualified location) for an external
Apache Iceberg committer process — logthing itself has no Iceberg
dependency and never talks to a catalog. Enable it with `[iceberg.s3]` or
`[iceberg.local]` in `logthing.toml` (mirroring every other source's
`.s3`/`.local` shape), or via `LOGTHING__ICEBERG__S3__BUCKET` etc. Configuring
both `iceberg.s3` and `iceberg.local` simultaneously is a startup error —
unlike other sources, the descriptor sink supports exactly one
destination.

## Suggested deployment pattern

logthing only ever writes Parquet + descriptor files — it never talks to
an Iceberg catalog. Turning those descriptors into real Iceberg tables is
the job of a separate, standalone **committer** process that you run
alongside logthing:

```
logthing ──writes──▶ Parquet files   (existing [<source>.s3]/[<source>.local])
         └─writes──▶ descriptor JSON  ([iceberg.s3]/[iceberg.local])
                            │
                            ▼
                    committer (external, not part of logthing)
                            │
                            ▼
                      Iceberg catalog + tables
```

- **Committer**: `committer/` in this repo ships a ready-to-run one, built
  on PyIceberg's `add_files` — drains the descriptor queue and registers
  each Parquet file into an Iceberg REST catalog table (partitioned by
  `day(partition_time)`), with idempotent re-runs and a clear
  abort-vs-quarantine error policy. Run it as the published container image,
  `ghcr.io/<owner>/logthing-committer:<version>`, on a schedule (cron, a
  Kubernetes CronJob, etc.) pointed at the same bucket logthing writes to and
  an Iceberg REST catalog. See [`committer/README.md`](../committer/README.md)
  for the full environment-variable reference, container usage, and how to
  run its end-to-end test. The alternative — a custom
  committer on `iceberg-rust`'s low-level primitives, populated directly
  from the descriptor JSON's stats instead of re-reading each Parquet
  footer — remains a valid path if `add_files`'s per-file footer read ever
  becomes the bottleneck, but nothing in this repo builds it today.

  The committer evolves tables additively: when a new logthing release appends columns
  (for example the `hec` table's `event_uuid`), files carrying them are committed after
  `union_by_name`, older rows read NULL; a type change quarantines the file. OTLP files all land
  in one `otlp` table regardless of the per-service Parquet path segment.
- **Catalog**: [Lakekeeper](https://github.com/lakekeeper/lakekeeper) (a
  single-binary, no-JVM, self-hosted REST catalog) for self-hosted/dev
  deployments; AWS Glue Data Catalog for AWS deployments — both require
  no new infrastructure beyond what you likely already run.

This keeps logthing decoupled from Iceberg's release cadence: the
committer and catalog can be swapped or upgraded independently, and a
logthing deploy never blocks on either.

For a ready-to-run docker compose / Helm stack wiring all of this together (plus Trino and
Hue), see [deploy/analytics/](../deploy/analytics/README.md).

## Table maintenance

Neither PyIceberg nor `iceberg-rust` currently ships an atomic file-rewrite
action, so treat small-file compaction and snapshot cleanup as periodic
batch jobs, independent of the committer, run with an engine that has them
(Trino, Spark):

- **Compact small files** periodically, e.g. in Trino:
  `ALTER TABLE <table> EXECUTE optimize(file_size_threshold => '128MB')`.
- **Expire old snapshots** periodically, e.g.:
  `ALTER TABLE <table> EXECUTE expire_snapshots(retention_threshold => '7d')`.
  Trino enforces a minimum retention via the catalog property
  `iceberg.expire-snapshots.min-retention` (default `7d`) and rejects a
  shorter value outright — raise that property first if you need a tighter
  window.
- **Do not run `remove_orphan_files`** against logthing's data location.
  logthing writes a Parquet file and only later has the committer register
  it; any file written but not yet committed looks "orphaned" to that
  procedure and would be deleted out from under the queue. If you need
  orphan cleanup, point it at a location the committer has already fully
  drained, or exclude the path logthing writes to.
