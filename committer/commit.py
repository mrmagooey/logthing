#!/usr/bin/env python3
"""Iceberg descriptor committer for logthing.

logthing writes Parquet files to S3-compatible object storage and, for every
file, drops a small JSON "descriptor" next to it under a descriptor prefix
(default ``_iceberg_descriptors/``) describing what it wrote: source, an
optional partition segment, the file's location, row/byte counts, and
per-column Parquet statistics (see logthing's
``src/forwarding/iceberg_descriptor.rs``).

This script drains that prefix as a work queue. For each descriptor it
resolves the referenced Parquet file, derives an Iceberg table name, and
registers the file into that table via ``add_files`` -- the data file is
adopted in place with no rewrite. Descriptors are moved to ``DONE_PREFIX``
once committed, or to ``QUARANTINE_PREFIX`` if they turn out to be broken
beyond repair (see ``should_abort`` below for what counts as "broken").

Each run is idempotent: a descriptor that names a file already registered in
its target table is skipped and moved straight to ``DONE_PREFIX``, so a
crash between committing a batch and moving its descriptors is harmless on
the next run.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

import boto3
import pyarrow as pa
import pyarrow.fs as pafs
import pyarrow.parquet as pq
from botocore.exceptions import ClientError, ConnectionClosedError, EndpointConnectionError
from pyiceberg.catalog import Catalog
from pyiceberg.catalog.rest import RestCatalog
from pyiceberg.exceptions import (
    BadRequestError,
    CommitFailedException,
    NamespaceAlreadyExistsError,
    NoSuchTableError,
    RESTError,
    ValidationError,
)
from pyiceberg.io.pyarrow import PyArrowFileIO
from pyiceberg.table import Table
from pyiceberg.transforms import DayTransform
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import Timeout as RequestsTimeout

logger = logging.getLogger("iceberg_committer")

DEFAULT_DESC_PREFIX = "_iceberg_descriptors/"
DEFAULT_DONE_PREFIX = "_committed/"
DEFAULT_QUARANTINE_PREFIX = "_quarantine/"
DEFAULT_BATCH_SIZE = 500


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Config:
    """Everything the committer needs, read once at startup.

    No module-level code touches the environment or builds a network client
    -- everything is threaded through here so tests can construct a `Config`
    directly and inject fakes/real-but-local collaborators for `s3`,
    `catalog` and `pa_fs` instead of talking to production S3/Iceberg.
    """

    bucket: str
    s3_endpoint: str
    s3_access_key: str
    s3_secret_key: str
    catalog_uri: str
    s3_region: str = "us-east-1"
    warehouse: str = "warehouse"
    namespace: str = "logs"
    desc_prefix: str = DEFAULT_DESC_PREFIX
    done_prefix: str = DEFAULT_DONE_PREFIX
    quarantine_prefix: str = DEFAULT_QUARANTINE_PREFIX
    batch_size: int = DEFAULT_BATCH_SIZE

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            bucket=os.environ["DATA_BUCKET"],
            s3_endpoint=os.environ["S3_ENDPOINT"],
            s3_access_key=os.environ["S3_ACCESS_KEY"],
            s3_secret_key=os.environ["S3_SECRET_KEY"],
            catalog_uri=os.environ["CATALOG_URI"],
            s3_region=os.environ.get("S3_REGION", "us-east-1"),
            warehouse=os.environ.get("WAREHOUSE", "warehouse"),
            namespace=os.environ.get("ICEBERG_NAMESPACE", "logs"),
            desc_prefix=os.environ.get("DESC_PREFIX", DEFAULT_DESC_PREFIX),
            done_prefix=os.environ.get("DONE_PREFIX", DEFAULT_DONE_PREFIX),
            quarantine_prefix=os.environ.get("QUARANTINE_PREFIX", DEFAULT_QUARANTINE_PREFIX),
            batch_size=int(os.environ.get("BATCH_SIZE", str(DEFAULT_BATCH_SIZE))),
        )

    @property
    def s3_io_properties(self) -> dict[str, str]:
        # pyiceberg catalog/FileIO properties are typed as Dict[str, str], and
        # its own `property_as_bool()` treats a falsy value (including the
        # Python bool `False`) as "absent" rather than "false" -- so every
        # boolean-valued property here is passed as its string form.
        return {
            "s3.endpoint": self.s3_endpoint,
            "s3.access-key-id": self.s3_access_key,
            "s3.secret-access-key": self.s3_secret_key,
            "s3.region": self.s3_region,
            "s3.force-virtual-addressing": "False",
        }


def make_catalog(cfg: Config) -> Catalog:
    return RestCatalog(
        "iceberg",
        **{
            "uri": cfg.catalog_uri,
            "warehouse": cfg.warehouse,
            **cfg.s3_io_properties,
        },
    )


def make_s3_client(cfg: Config) -> Any:
    return boto3.client(
        "s3",
        endpoint_url=cfg.s3_endpoint,
        aws_access_key_id=cfg.s3_access_key,
        aws_secret_access_key=cfg.s3_secret_key,
        region_name=cfg.s3_region,
    )


def make_pyarrow_fs(cfg: Config) -> pafs.S3FileSystem:
    # Scheme is derived from the endpoint URL rather than hard-coded, so this
    # also works against a TLS-fronted S3-compatible store.
    scheme = "https" if cfg.s3_endpoint.startswith("https://") else "http"
    return pafs.S3FileSystem(
        endpoint_override=cfg.s3_endpoint,
        access_key=cfg.s3_access_key,
        secret_key=cfg.s3_secret_key,
        region=cfg.s3_region,
        scheme=scheme,
    )


# ---------------------------------------------------------------------------
# Error classification
# ---------------------------------------------------------------------------

# A single object that genuinely isn't there -- permanent, not connectivity,
# and not systemic: every *other* key can still be read fine.
_PERMANENT_S3_CODES = frozenset({"NoSuchKey", "404", "NotFound"})

# Credentials/config problems: every request fails the same way, so the whole
# run must abort rather than quarantine the descriptor that happened to hit
# it first.
_ABORT_S3_CODES = frozenset(
    {"AccessDenied", "InvalidAccessKeyId", "SignatureDoesNotMatch", "NoSuchBucket", "ExpiredToken"}
)

# S3 error codes for overload/throttling that a caller should treat the same
# as a 5xx: transient, retry later.
_TRANSIENT_S3_CODES = frozenset(
    {
        "SlowDown",
        "Throttling",
        "ThrottlingException",
        "RequestTimeout",
        "ServiceUnavailable",
        "InternalError",
    }
)


def should_abort(exc: BaseException) -> bool:
    """Classify an exception as abort (leave the descriptor queued, stop the
    run) or permanent (quarantine just this one descriptor/file).

    Abort covers two kinds of failure that both make quarantining the wrong
    move: transient (catalog/S3 unreachable or returning 5xx, throttling, an
    Iceberg commit conflict) and systemic (bad credentials, wrong bucket,
    expired auth) -- a systemic error hits every descriptor the same way, so
    quarantining "the" bad one would drain the whole queue into
    QUARANTINE_PREFIX for a problem that has nothing to do with any of them.

    Permanent (the default for anything not recognised below): a schema
    mismatch, a missing data file, a malformed descriptor, an unsupported
    storage target, or a catalog 400 on one table's request -- failures
    attributable to that one descriptor, not to the environment.

    When genuinely unsure, this leans toward abort -- quarantine means a
    human has to go triage it, a wrongly-aborted run just costs one retry on
    the next invocation.
    """
    if isinstance(exc, CommitFailedException):
        return True
    if isinstance(exc, RESTError) and not isinstance(exc, BadRequestError):
        # Covers ServerError/ServiceUnavailableError (5xx), UnauthorizedError
        # (401), ForbiddenError (403), AuthorizationExpiredError (419),
        # OAuthError, and CommitStateUnknownException (an ambiguous commit
        # outcome -- safer to not assume it failed). BadRequestError (400) is
        # excluded: that's a bad request for one specific table/commit, not a
        # systemic problem, so it stays permanent.
        return True
    if isinstance(exc, (RequestsConnectionError, RequestsTimeout)):
        return True
    if isinstance(exc, (EndpointConnectionError, ConnectionClosedError)):
        return True
    if isinstance(exc, ClientError):
        error = exc.response.get("Error", {}) or {}
        code = str(error.get("Code", ""))
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode") or 0
        if code in _PERMANENT_S3_CODES:
            return False
        if status in (401, 403) or code in _ABORT_S3_CODES:
            return True
        if status >= 500 or code in _TRANSIENT_S3_CODES:
            return True
        return False
    if isinstance(exc, FileNotFoundError):
        # pyarrow raises this (an OSError subclass) when a descriptor points at
        # a data file that simply isn't in the bucket -- a broken descriptor,
        # not a connectivity or permission problem.
        return False
    if isinstance(exc, OSError):
        # Every other OSError out of pyarrow's S3 filesystem (refused, reset,
        # DNS failure, timeout, permission denied) is connectivity or config.
        # Lean toward abort.
        return True
    return False


class _Abort(Exception):
    """Internal signal: `should_abort` said stop -- unwind the whole run immediately."""

    def __init__(self, cause: BaseException) -> None:
        super().__init__(str(cause))
        self.cause = cause


# ---------------------------------------------------------------------------
# Table naming
# ---------------------------------------------------------------------------

_SANITIZE_RE = re.compile(r"[^a-z0-9_]")
_NAME_CAP = 64

# Sources whose sink varies its Arrow schema by partition -- verified by
# reading each sink's `ParquetSink::schema(&self, partition)` in
# src/forwarding/*.rs and src/forwarding/aggregate/mod.rs:
#   - zeek (zeek_s3.rs): per-stream typed schema vs. the envelope fallback.
#   - aggregate (aggregate/mod.rs): one schema per compiled rule.
#   - sflow (sflow_s3.rs): "flow" and "counter" partitions are entirely
#     different column sets (FLOW_SCHEMA vs COUNTER_SCHEMA).
# Every other sink ignores its `partition` argument and returns one fixed
# schema, so folding all of a source's partitions into a single table is
# safe for them and would fail `add_files` with a schema mismatch for these
# three.
# `otlp` is deliberately NOT listed: its sink writes one fixed schema, and its per-service Parquet
# path segment is only a file-grouping key (the `service_name` column carries the service), so
# every service shares the single `otlp` table.
_PARTITIONED_TABLE_PREFIX = {
    "zeek": "zeek",
    "aggregate": "agg",
    "sflow": "sflow",
}


def _sanitize(segment: str) -> str:
    cleaned = _SANITIZE_RE.sub("_", segment.lower())[:_NAME_CAP]
    return cleaned or "unknown"


def table_name(source: str, partition: str | None) -> str:
    """Derive the target Iceberg table name from descriptor fields alone
    (never from the Parquet key path), so table identity survives any future
    change to logthing's key layout.
    """
    prefix = _PARTITIONED_TABLE_PREFIX.get(source)
    if prefix is not None:
        return f"{prefix}_{_sanitize(partition or 'unknown')}"
    return _sanitize(source)


# ---------------------------------------------------------------------------
# Descriptor file_path parsing
# ---------------------------------------------------------------------------


def parse_file_path(desc: dict[str, Any], bucket: str) -> str:
    """Resolve a descriptor's `file_path` to an `s3://<bucket>/<key>` URI.

    Accepts path-style (`http(s)://host[:port]/<bucket>/<key>`, what
    logthing's own S3 sink always emits, and also the natural default for
    MinIO/Garage and similar S3-compatible stores), virtual-hosted-style
    (`https://<bucket>.<host>/<key>`), and `s3://<bucket>/<key>` directly.

    Raises ValueError (permanent -- `should_abort` returns False for it) for
    anything that doesn't parse, names the wrong bucket, or isn't S3-backed.
    `file_path` is required; there is no legacy fallback field or
    descriptor-key-mirroring guess.
    """
    def wrong_bucket(found_bucket: str) -> ValueError:
        return ValueError(
            f"file_path bucket {found_bucket!r} does not match "
            f"DATA_BUCKET {bucket!r}: {file_path!r}"
        )

    storage_target = desc.get("storage_target")
    if storage_target != "s3":
        raise ValueError(
            f"unsupported storage_target {storage_target!r}: "
            "only 's3' descriptors can be committed to Iceberg"
        )

    file_path = desc.get("file_path")
    if not file_path or not isinstance(file_path, str):
        raise ValueError("descriptor is missing required field 'file_path'")

    if file_path.startswith("s3://"):
        rest = file_path[len("s3://") :]
        found_bucket, _, key = rest.partition("/")
        if found_bucket != bucket or not key:
            raise wrong_bucket(found_bucket)
        return f"s3://{bucket}/{key}"

    parsed = urllib.parse.urlparse(file_path)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(f"file_path is not a recognised S3 URL: {file_path!r}")

    host = parsed.hostname or ""
    path = parsed.path.lstrip("/")

    # Virtual-hosted style: https://<bucket>.<rest-of-host>/<key>
    host_label, _, host_rest = host.partition(".")
    if host_rest and host_label == bucket:
        if not path:
            raise ValueError(f"file_path has no key: {file_path!r}")
        return f"s3://{bucket}/{path}"

    # Path-style: http(s)://host[:port]/<bucket>/<key>
    found_bucket, _, key = path.partition("/")
    if found_bucket != bucket or not key:
        raise wrong_bucket(found_bucket)
    return f"s3://{bucket}/{key}"


# ---------------------------------------------------------------------------
# Table management
# ---------------------------------------------------------------------------


def force_pyarrow_io(tbl: Table, cfg: Config) -> Table:
    # A REST catalog hands back tables using FsspecFileIO, which needs s3fs
    # (whose aiobotocore pin routinely conflicts with pyiceberg's own boto3
    # requirement). PyArrowFileIO needs no extra dependency and writes to any
    # S3-compatible store fine via the properties above. The catalog's own
    # `py-io-impl` property is ignored for REST-loaded tables, so the FileIO
    # is overridden explicitly on every table before it's read or written.
    tbl.io = PyArrowFileIO(properties=cfg.s3_io_properties)
    return tbl


def ensure_day_spec(tbl: Table) -> Table:
    """Make sure `tbl` is partitioned by `day(partition_time)`, adding the
    partition field if it's missing. Run on BOTH the create and load paths.

    `add_files` infers each file's partition value from Parquet column
    min/max stats and raises if they straddle a boundary. That's only safe
    because logthing keys its write buffers by (partition, UTC day), so every
    file is day-clean by construction -- do not widen this to hours(), which
    would not hold.

    `add_field()` is called by column name rather than passing a
    `PartitionSpec` to `create_table()`: with a raw `pa.Schema`, the catalog's
    schema-conversion path assigns every field id -1, and partition-spec id
    assignment then resolves source_id -> name against that all--1 schema
    with a last-wins map, which only happens to work if the target column is
    last. Not a style choice.

    Checked again on load, not just on create: `create_table()` and
    `update_spec()` are two separate catalog commits with no compensation. If
    the first succeeds and the second doesn't (a transient REST error, a
    commit conflict), a later run would otherwise load an unpartitioned table
    and keep it that way forever. Re-checking here makes that self-healing.
    """
    if not tbl.spec().fields and "partition_time" in tbl.schema().column_names:
        with tbl.update_spec() as update:
            update.add_field("partition_time", DayTransform(), "partition_time_day")
    return tbl


def ensure_table(
    catalog: Catalog,
    pa_fs: pafs.S3FileSystem,
    cfg: Config,
    name: str,
    sample_uri: str,
) -> Table:
    """Load `name`, creating it (schema inferred from `sample_uri`'s Parquet
    footer) if it doesn't exist yet.
    """
    ident = (cfg.namespace, name)
    try:
        return ensure_day_spec(force_pyarrow_io(catalog.load_table(ident), cfg))
    except NoSuchTableError:
        key = sample_uri[len(f"s3://{cfg.bucket}/") :]
        schema = pq.read_schema(pa_fs.open_input_file(f"{cfg.bucket}/{key}"))
        return ensure_day_spec(force_pyarrow_io(catalog.create_table(ident, schema=schema), cfg))


def ensure_namespace(catalog: Catalog, namespace: str) -> None:
    existing = {tuple(n) for n in catalog.list_namespaces()}
    if (namespace,) not in existing:
        try:
            catalog.create_namespace(namespace)
        except NamespaceAlreadyExistsError:
            pass


def committed_file_set(tbl: Table) -> set[str]:
    """The set of file paths already registered in `tbl`, per its current
    snapshot. Exceptions are NOT swallowed here -- the caller decides via
    `should_abort` whether that's a reason to abort or to quarantine.
    """
    return set(tbl.inspect.files().column("file_path").to_pylist())


# ---------------------------------------------------------------------------
# Additive schema evolution
# ---------------------------------------------------------------------------

_EVOLVE_ATTEMPTS = 5


def _read_file_schema(pa_fs: pafs.S3FileSystem, cfg: Config, uri: str) -> pa.Schema:
    key = uri[len(f"s3://{cfg.bucket}/") :]
    return pq.read_schema(pa_fs.open_input_file(f"{cfg.bucket}/{key}"))


def _is_already_referenced(exc: BaseException) -> bool:
    """`add_files` raises a bare ValueError when a file is already registered in the table."""
    return isinstance(exc, ValueError) and "already referenced" in str(exc)


def _reload_table(catalog: Catalog, cfg: Config, name: str, committed_files: set[str]) -> Table:
    """Reload `name` and refresh `committed_files` IN PLACE (it is the run-wide cache entry)."""
    tbl = force_pyarrow_io(catalog.load_table((cfg.namespace, name)), cfg)
    committed_files.clear()
    committed_files.update(committed_file_set(tbl))
    return tbl


def evolve_schema(
    catalog: Catalog,
    cfg: Config,
    pa_fs: pafs.S3FileSystem,
    name: str,
    tbl: Table,
    committed_files: set[str],
    batch: list[tuple[str, str]],
) -> tuple[Table, list[tuple[str, str]], list[tuple[str, str]], list[tuple[str, str]]]:
    """Additively evolve `tbl` so every file in `batch` fits it.

    For each file whose Parquet footer has columns the table lacks, stage
    `update_schema().union_by_name(file_schema)` and then `commit()` it (stage-then-commit, never
    a `with` block: see the comment in the loop). A type conflict (`ValidationError`), a
    required-column `ValueError`, a catalog `BadRequestError` or an unreadable footer marks just
    that file `conflicted` (the caller quarantines it). A `CommitFailedException` (another
    committer changed the table) reloads the table, re-runs the committed-file filter, and
    retries up to `_EVOLVE_ATTEMPTS` times with backoff `0.2 * 2**attempt`; the last failure
    propagates (`should_abort` treats it as abort). Other abort-class errors raise `_Abort`.

    Returns `(table, to_add, already_done, conflicted)`: the (possibly reloaded) table, files that
    now fit, files another committer registered in the meantime, and files that cannot fit.
    """
    for attempt in range(_EVOLVE_ATTEMPTS):
        to_add = [(d, u) for d, u in batch if u not in committed_files]
        already_done = [(d, u) for d, u in batch if u in committed_files]
        fits: list[tuple[str, str]] = []
        conflicted: list[tuple[str, str]] = []
        try:
            for dkey, uri in to_add:
                try:
                    fschema = _read_file_schema(pa_fs, cfg, uri)
                except Exception as exc:  # noqa: BLE001 - classified immediately below
                    if should_abort(exc):
                        raise _Abort(exc) from exc
                    logger.error("cannot read footer of %s: %r", uri, exc)
                    conflicted.append((dkey, uri))
                    continue
                have = set(tbl.schema().column_names)
                if any(f.name not in have for f in fschema):
                    # Deliberately NOT `with tbl.update_schema() as upd:`. pyiceberg's
                    # `__exit__` commits even when the body raised, which would persist
                    # columns `union_by_name` had already staged before it hit the conflict,
                    # evolving the table on behalf of a file we are about to quarantine.
                    try:
                        upd = tbl.update_schema()
                        upd.union_by_name(fschema)
                        upd.commit()
                    except (ValidationError, ValueError, BadRequestError) as exc:
                        logger.error(
                            "schema of %s cannot evolve %s.%s: %r", uri, cfg.namespace, name, exc
                        )
                        conflicted.append((dkey, uri))
                        continue
                    except CommitFailedException:
                        raise
                    except Exception as exc:  # noqa: BLE001 - classified immediately below
                        if should_abort(exc):
                            raise _Abort(exc) from exc
                        raise
                fits.append((dkey, uri))
            return tbl, fits, already_done, conflicted
        except CommitFailedException:
            if attempt == _EVOLVE_ATTEMPTS - 1:
                raise
            time.sleep(0.2 * 2**attempt)
            tbl = _reload_table(catalog, cfg, name, committed_files)
    raise AssertionError("unreachable")  # pragma: no cover


# ---------------------------------------------------------------------------
# Descriptor relocation
# ---------------------------------------------------------------------------


def _relocate(s3: Any, cfg: Config, dkey: str, dest_prefix: str) -> None:
    """Copy a descriptor to `dest_prefix`, then delete the original -- same
    two-step move the original script used (S3 has no atomic rename).
    """
    suffix = dkey[len(cfg.desc_prefix) :] if dkey.startswith(cfg.desc_prefix) else dkey
    dest_key = dest_prefix + suffix
    s3.copy_object(Bucket=cfg.bucket, Key=dest_key, CopySource={"Bucket": cfg.bucket, "Key": dkey})
    s3.delete_object(Bucket=cfg.bucket, Key=dkey)


def _mark_done(s3: Any, cfg: Config, dkey: str) -> None:
    _relocate(s3, cfg, dkey, cfg.done_prefix)


def _mark_quarantined(s3: Any, cfg: Config, dkey: str) -> None:
    logger.warning("quarantining descriptor: %s", dkey)
    _relocate(s3, cfg, dkey, cfg.quarantine_prefix)


# ---------------------------------------------------------------------------
# Batch commit
# ---------------------------------------------------------------------------


@dataclass
class _Counts:
    committed: int = 0
    skipped: int = 0
    quarantined: int = 0


def _commit_batch(
    cfg: Config,
    s3: Any,
    catalog: Catalog,
    pa_fs: pafs.S3FileSystem,
    table_cache: dict[str, Table],
    committed_cache: dict[str, set[str]],
    name: str,
    batch: list[tuple[str, str]],
    allow_redo: bool = True,
) -> _Counts:
    """Commit one table's worth of queued descriptors (up to `batch_size`) in
    a single `add_files` call, then move each of their descriptors to
    `DONE_PREFIX`. Raises `_Abort` when `should_abort` says so -- callers
    must let that unwind the whole run.

    Before `add_files` the table is evolved additively for files carrying new columns (files that
    cannot evolve are quarantined individually). If `add_files` reports a file already referenced
    (another committer won the race) the table is reloaded and the batch re-deduped once
    (`allow_redo`), marking those files done instead of quarantining them.
    """
    counts = _Counts()

    if name in table_cache:
        tbl = table_cache[name]
        committed_files = committed_cache[name]
    else:
        try:
            tbl = ensure_table(catalog, pa_fs, cfg, name, batch[0][1])
            committed_files = committed_file_set(tbl)
        except Exception as exc:  # noqa: BLE001 - classified immediately below
            if should_abort(exc):
                raise _Abort(exc) from exc
            # The table itself can't be loaded/created/inspected -- nothing in
            # this batch can be committed to it. Quarantine the whole batch
            # rather than guessing which file is "the bad one".
            logger.error(
                "table %s.%s unusable, quarantining its whole batch: %r", cfg.namespace, name, exc
            )
            for dkey, _uri in batch:
                _mark_quarantined(s3, cfg, dkey)
            counts.quarantined += len(batch)
            return counts
        table_cache[name] = tbl
        committed_cache[name] = committed_files

    to_add = [(dkey, uri) for dkey, uri in batch if uri not in committed_files]
    already_done = [(dkey, uri) for dkey, uri in batch if uri in committed_files]

    for dkey, uri in already_done:
        logger.info("skip (already committed): %s", uri)
        _mark_done(s3, cfg, dkey)
        counts.skipped += 1

    if not to_add:
        return counts

    try:
        tbl, to_add, raced_done, conflicted = evolve_schema(
            catalog, cfg, pa_fs, name, tbl, committed_files, to_add
        )
    except Exception as exc:  # noqa: BLE001 - classified immediately below
        if isinstance(exc, _Abort):
            raise
        if should_abort(exc):
            raise _Abort(exc) from exc
        raise
    table_cache[name] = tbl
    for dkey, uri in raced_done:
        logger.info("skip (registered by another committer): %s", uri)
        _mark_done(s3, cfg, dkey)
        counts.skipped += 1
    for dkey, _uri in conflicted:
        _mark_quarantined(s3, cfg, dkey)
        counts.quarantined += 1
    if not to_add:
        return counts

    try:
        tbl.add_files([uri for _dkey, uri in to_add])
        for dkey, uri in to_add:
            _mark_done(s3, cfg, dkey)
            committed_files.add(uri)
            logger.info("committed %s -> %s.%s", uri, cfg.namespace, name)
        counts.committed += len(to_add)
        return counts
    except Exception as exc:  # noqa: BLE001 - classified immediately below
        if should_abort(exc):
            raise _Abort(exc) from exc
        if allow_redo and _is_already_referenced(exc):
            # Another committer registered one of these files between our dedupe and our
            # commit. Reload, re-dedupe, and finish the rest once instead of quarantining.
            logger.warning(
                "add_files hit already-registered file(s) in %s.%s; reloading and re-deduping",
                cfg.namespace,
                name,
            )
            try:
                table_cache[name] = _reload_table(catalog, cfg, name, committed_files)
            except Exception as reload_exc:  # noqa: BLE001 - classified immediately below
                if should_abort(reload_exc):
                    raise _Abort(reload_exc) from reload_exc
                raise
            sub = _commit_batch(
                cfg, s3, catalog, pa_fs, table_cache, committed_cache, name, to_add, False
            )
            counts.committed += sub.committed
            counts.skipped += sub.skipped
            counts.quarantined += sub.quarantined
            return counts
        # Permanent failure on the batched call doesn't tell us which file is
        # bad. Retry one at a time so only the actually-broken one quarantines
        # and the rest of the batch still commits.
        logger.warning(
            "batch commit to %s.%s failed (%r), retrying files individually",
            cfg.namespace,
            name,
            exc,
        )
        for dkey, uri in to_add:
            try:
                tbl.add_files([uri])
                _mark_done(s3, cfg, dkey)
                committed_files.add(uri)
                counts.committed += 1
                logger.info("committed %s -> %s.%s", uri, cfg.namespace, name)
            except Exception as exc2:  # noqa: BLE001 - classified immediately below
                if should_abort(exc2):
                    raise _Abort(exc2) from exc2
                logger.error("permanent error committing %s: %r", uri, exc2)
                _mark_quarantined(s3, cfg, dkey)
                counts.quarantined += 1
        return counts


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------


def exit_code(committed: int, skipped: int, quarantined: int, aborted: bool) -> int:
    """Exit 0 only for a clean run: nothing quarantined, and the run wasn't
    aborted partway through.
    """
    if aborted or quarantined > 0:
        return 1
    return 0


def run(cfg: Config, s3: Any, catalog: Catalog, pa_fs: pafs.S3FileSystem) -> int:
    """Drain `cfg.desc_prefix` and return the process exit code.

    Descriptors are listed one page at a time and grouped in memory only as
    small `(descriptor_key, uri)` pairs, never as Parquet bytes; a table's
    pending group is committed and cleared as soon as it reaches
    `cfg.batch_size`. That bounds memory against queue size -- it does not
    bound the per-table `committed_file_set` cache, which holds one path per
    file the table already has, independent of how many descriptors are
    queued.
    """
    table_cache: dict[str, Table] = {}
    committed_cache: dict[str, set[str]] = {}
    pending: dict[str, list[tuple[str, str]]] = defaultdict(list)

    totals = _Counts()
    seen = 0
    aborted = False

    def flush(name: str) -> None:
        batch = pending.pop(name)
        result = _commit_batch(cfg, s3, catalog, pa_fs, table_cache, committed_cache, name, batch)
        totals.committed += result.committed
        totals.skipped += result.skipped
        totals.quarantined += result.quarantined

    try:
        ensure_namespace(catalog, cfg.namespace)

        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=cfg.bucket, Prefix=cfg.desc_prefix):
            for obj in page.get("Contents", []):
                dkey = obj["Key"]
                if not dkey.endswith(".json"):
                    continue
                seen += 1
                try:
                    body = s3.get_object(Bucket=cfg.bucket, Key=dkey)["Body"].read()
                    desc = json.loads(body)
                    source = desc.get("source")
                    if not source or not isinstance(source, str):
                        raise ValueError("descriptor is missing required field 'source'")
                    uri = parse_file_path(desc, cfg.bucket)
                    name = table_name(source, desc.get("partition"))
                except Exception as exc:  # noqa: BLE001 - classified immediately below
                    if should_abort(exc):
                        raise _Abort(exc) from exc
                    logger.error("permanent error reading descriptor %s: %r", dkey, exc)
                    _mark_quarantined(s3, cfg, dkey)
                    totals.quarantined += 1
                    continue

                pending[name].append((dkey, uri))
                if len(pending[name]) >= cfg.batch_size:
                    flush(name)

        for name in list(pending.keys()):
            flush(name)
    except _Abort as abort:
        logger.error("aborting run: %r", abort.cause)
        aborted = True
    except Exception as exc:  # noqa: BLE001 - classified immediately below
        # A raw (not pre-classified) exception can only get here from listing
        # the queue itself or creating the namespace -- not attributable to any
        # one descriptor. If should_abort agrees, abort like any other
        # transient/systemic failure. Anything else is a real bug or
        # misconfiguration should_abort doesn't recognise: let it crash the
        # process rather than pretend the run completed.
        if not should_abort(exc):
            raise
        logger.error("aborting run: %r", exc)
        aborted = True

    remaining = seen - totals.committed - totals.skipped - totals.quarantined
    logger.info(
        "done; committed=%d skipped=%d quarantined=%d remaining=%d%s",
        totals.committed,
        totals.skipped,
        totals.quarantined,
        remaining,
        " (aborted)" if aborted else "",
    )
    return exit_code(totals.committed, totals.skipped, totals.quarantined, aborted)


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stdout,
    )
    try:
        cfg = Config.from_env()
    except KeyError as exc:
        # Config.from_env() reads required vars via os.environ[...], which
        # raises a bare KeyError naming the missing key -- clear enough in a
        # traceback, but this turns it into a one-line, non-traceback error
        # message and a distinct exit code (2) for a container/orchestrator
        # to recognise as "misconfigured" rather than "run failed".
        logger.error("missing required environment variable: %s", exc)
        return 2
    s3 = make_s3_client(cfg)
    catalog = make_catalog(cfg)
    pa_fs = make_pyarrow_fs(cfg)
    return run(cfg, s3, catalog, pa_fs)


if __name__ == "__main__":
    sys.exit(main())
