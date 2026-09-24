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

- **Committer**: a small, independently-deployed job (batch or
  long-running) that lists new descriptor files and builds Iceberg
  manifests from their contents. Two options, with a real tradeoff between
  them:
  - **PyIceberg's `add_files`** — fastest to stand up, but it does not
    use the descriptor's pre-computed stats: it opens each Parquet file
    itself and reads its footer to derive row count, byte size, column
    stats, and partition values. This still works fine, but it re-reads
    every file (a footer-only range-read, not a full download, but still
    I/O against the Parquet object) and doesn't need the descriptor JSON
    at all — it could just as well list the S3 prefix directly.
  - **A custom committer** built on `iceberg-rust`'s low-level primitives
    (`DataFileBuilder`, `ManifestWriter`, `ManifestListWriter`), populated
    directly from the descriptor JSON's `record_count`/`file_size_in_bytes`/
    `column_stats` fields — this is the option that actually delivers on
    "never re-reads Parquet," since it never opens the Parquet file at
    all. More work to build than reaching for `add_files`, but it's the
    only path that uses the descriptor for what it was designed for.
- **Catalog**: [Lakekeeper](https://github.com/lakekeeper/lakekeeper) (a
  single-binary, no-JVM, self-hosted REST catalog) for self-hosted/dev
  deployments; AWS Glue Data Catalog for AWS deployments — both require
  no new infrastructure beyond what you likely already run.
- **Compaction**: run as a separate, periodic batch job (e.g. Trino/Spark
  `OPTIMIZE`) rather than folding it into the committer — neither
  PyIceberg nor `iceberg-rust` currently ships an atomic file-rewrite
  action, so merging small files is best treated as independent
  table-maintenance, not part of every commit.

This keeps logthing decoupled from Iceberg's release cadence: the
committer and catalog can be swapped or upgraded independently, and a
logthing deploy never blocks on either.
