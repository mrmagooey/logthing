"""Integration tests for commit.py against real collaborators:

- moto's ThreadedMotoServer as a real (local, in-process) S3, used by both
  boto3 and pyarrow's S3FileSystem.
- pyiceberg's SqlCatalog, backed by SQLite in tmp_path, standing in for the
  production RestCatalog (commit.py never talks to the catalog through
  anything but the pyiceberg `Catalog` interface, so this is a faithful
  substitute).

No mocks of commit.py's own logic: `run()` is called for real, moto/SqlCatalog
back it for real, and results are verified by scanning the resulting Iceberg
tables.
"""

import io
import json
import sys
import uuid
from pathlib import Path

import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq
import pytest
from moto.server import ThreadedMotoServer
from pyiceberg.catalog.sql import SqlCatalog
from pyiceberg.exceptions import CommitFailedException, NoSuchTableError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import commit  # noqa: E402

PARTITION_TIME = pa.timestamp("us", tz="UTC")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def moto_endpoint():
    server = ThreadedMotoServer(port=0)
    server.start()
    host, port = server._server.server_address
    yield f"http://{host}:{port}"
    server.stop()


@pytest.fixture
def bucket_name():
    return "bucket-" + uuid.uuid4().hex[:12]


@pytest.fixture
def cfg(moto_endpoint, bucket_name, tmp_path):
    return commit.Config(
        bucket=bucket_name,
        s3_endpoint=moto_endpoint,
        s3_access_key="testkey",
        s3_secret_key="testsecret",
        catalog_uri="unused-in-tests",
        s3_region="us-east-1",
        warehouse=f"s3://{bucket_name}/warehouse",
        namespace="logs",
        desc_prefix="_iceberg_descriptors/",
        done_prefix="_committed/",
        quarantine_prefix="_quarantine/",
        batch_size=500,
    )


@pytest.fixture
def s3(cfg, bucket_name):
    client = commit.make_s3_client(cfg)
    client.create_bucket(Bucket=bucket_name)
    return client


@pytest.fixture
def pa_fs(cfg):
    return commit.make_pyarrow_fs(cfg)


@pytest.fixture
def catalog(cfg, tmp_path):
    return SqlCatalog(
        "test",
        **{
            "uri": f"sqlite:///{tmp_path}/catalog.db",
            "warehouse": cfg.warehouse,
            **cfg.s3_io_properties,
        },
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def write_parquet(s3, bucket, key, rows: dict, day: str) -> None:
    """Write a real, day-clean Parquet file with a non-null `partition_time`
    column plus whatever other columns `rows` describes.
    """
    ts = pa.array([f"{day}T12:00:00"] * len(next(iter(rows.values()))), type=pa.string())
    partition_time = pc.cast(pc.strptime(ts, format="%Y-%m-%dT%H:%M:%S", unit="us"), PARTITION_TIME)
    columns = dict(rows)
    columns["partition_time"] = partition_time
    table = pa.table(columns)
    buf = io.BytesIO()
    pq.write_table(table, buf)
    s3.put_object(Bucket=bucket, Key=key, Body=buf.getvalue())


def put_descriptor(
    s3,
    cfg,
    desc_key: str,
    *,
    source: str,
    partition: str | None,
    data_key: str,
    record_count: int,
    storage_target: str = "s3",
    file_path: str | None = None,
) -> None:
    desc = {
        "source": source,
        "file_path": file_path if file_path is not None else f"{cfg.s3_endpoint}/{cfg.bucket}/{data_key}",
        "file_format": "PARQUET",
        "record_count": record_count,
        "file_size_in_bytes": 100,
        "storage_target": storage_target,
        "schema_version": "testschema",
        "written_at": "2026-01-01T00:00:00Z",
        "column_stats": {},
    }
    if partition is not None:
        desc["partition"] = partition
    s3.put_object(Bucket=cfg.bucket, Key=cfg.desc_prefix + desc_key, Body=json.dumps(desc).encode())


def list_keys(s3, cfg, prefix: str) -> list[str]:
    resp = s3.list_objects_v2(Bucket=cfg.bucket, Prefix=prefix)
    return [o["Key"] for o in resp.get("Contents", [])]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_multiple_tables_get_correct_row_counts(cfg, s3, catalog, pa_fs):
    write_parquet(s3, cfg.bucket, "syslog/day=2026-01-01/a.parquet", {"message": ["m1", "m2"]}, "2026-01-01")
    put_descriptor(
        s3, cfg, "syslog/a.json", source="syslog", partition=None,
        data_key="syslog/day=2026-01-01/a.parquet", record_count=2,
    )

    write_parquet(s3, cfg.bucket, "zeek/conn/day=2026-01-01/b.parquet", {"orig_h": ["1.1.1.1", "2.2.2.2", "3.3.3.3"]}, "2026-01-01")
    put_descriptor(
        s3, cfg, "zeek/conn/b.json", source="zeek", partition="conn",
        data_key="zeek/conn/day=2026-01-01/b.parquet", record_count=3,
    )

    write_parquet(s3, cfg.bucket, "zeek/dns/day=2026-01-01/c.parquet", {"query": ["a.com"]}, "2026-01-01")
    put_descriptor(
        s3, cfg, "zeek/dns/c.json", source="zeek", partition="dns",
        data_key="zeek/dns/day=2026-01-01/c.parquet", record_count=1,
    )

    rc = commit.run(cfg, s3, catalog, pa_fs)
    assert rc == 0

    assert catalog.load_table(("logs", "syslog")).scan().to_arrow().num_rows == 2
    assert catalog.load_table(("logs", "zeek_conn")).scan().to_arrow().num_rows == 3
    assert catalog.load_table(("logs", "zeek_dns")).scan().to_arrow().num_rows == 1

    assert list_keys(s3, cfg, cfg.desc_prefix) == []
    assert len(list_keys(s3, cfg, cfg.done_prefix)) == 3
    assert list_keys(s3, cfg, cfg.quarantine_prefix) == []


def test_table_is_partitioned_by_day_of_partition_time(cfg, s3, catalog, pa_fs):
    write_parquet(s3, cfg.bucket, "syslog/day=2026-02-01/a.parquet", {"message": ["m"]}, "2026-02-01")
    put_descriptor(s3, cfg, "a.json", source="syslog", partition=None, data_key="syslog/day=2026-02-01/a.parquet", record_count=1)

    assert commit.run(cfg, s3, catalog, pa_fs) == 0

    tbl = catalog.load_table(("logs", "syslog"))
    fields = tbl.spec().fields
    assert len(fields) == 1
    assert fields[0].name == "partition_time_day"
    assert str(fields[0].transform) == "day"


def test_batching_gives_one_snapshot_per_chunk_not_per_file(cfg, s3, catalog, pa_fs):
    cfg = commit.Config(**{**cfg.__dict__, "batch_size": 2})
    for i in range(5):
        key = f"syslog/day=2026-01-01/f{i}.parquet"
        write_parquet(s3, cfg.bucket, key, {"message": ["m"]}, "2026-01-01")
        put_descriptor(s3, cfg, f"f{i}.json", source="syslog", partition=None, data_key=key, record_count=1)

    assert commit.run(cfg, s3, catalog, pa_fs) == 0

    tbl = catalog.load_table(("logs", "syslog"))
    assert tbl.scan().to_arrow().num_rows == 5
    # 5 files at batch_size=2 -> chunks of 2, 2, 1 -> 3 snapshots (add_files
    # commits once per chunk, not once per file).
    assert len(list(tbl.snapshots())) == 3


def test_idempotent_rerun_skips_already_committed_files(cfg, s3, catalog, pa_fs):
    key = "syslog/day=2026-01-01/a.parquet"
    write_parquet(s3, cfg.bucket, key, {"message": ["m1", "m2"]}, "2026-01-01")
    put_descriptor(s3, cfg, "a.json", source="syslog", partition=None, data_key=key, record_count=2)

    assert commit.run(cfg, s3, catalog, pa_fs) == 0
    tbl = catalog.load_table(("logs", "syslog"))
    assert tbl.scan().to_arrow().num_rows == 2
    snapshots_after_first_run = len(list(tbl.snapshots()))

    # Simulate a crash between committing and moving the descriptor: copy the
    # already-committed descriptor back into the queue.
    done_key = cfg.done_prefix + "a.json"
    s3.copy_object(Bucket=cfg.bucket, Key=cfg.desc_prefix + "a.json", CopySource={"Bucket": cfg.bucket, "Key": done_key})
    s3.delete_object(Bucket=cfg.bucket, Key=done_key)

    rc = commit.run(cfg, s3, catalog, pa_fs)
    assert rc == 0

    tbl = catalog.load_table(("logs", "syslog"))
    assert tbl.scan().to_arrow().num_rows == 2, "re-running must not duplicate rows"
    # Skipping an already-committed file must not create a new snapshot.
    assert len(list(tbl.snapshots())) == snapshots_after_first_run
    assert list_keys(s3, cfg, cfg.desc_prefix) == []
    assert len(list_keys(s3, cfg, cfg.done_prefix)) == 1


def test_permanent_failure_quarantines_only_the_bad_descriptor(cfg, s3, catalog, pa_fs):
    good_key = "syslog/day=2026-01-01/good.parquet"
    write_parquet(s3, cfg.bucket, good_key, {"message": ["m1"]}, "2026-01-01")
    put_descriptor(s3, cfg, "good.json", source="syslog", partition=None, data_key=good_key, record_count=1)

    # Points at a Parquet file that was never written -- pyarrow raises
    # FileNotFoundError reading its footer, which is_transient says is
    # permanent (not connectivity).
    put_descriptor(
        s3, cfg, "missing.json", source="syslog", partition=None,
        data_key="syslog/day=2026-01-01/does-not-exist.parquet", record_count=1,
    )

    rc = commit.run(cfg, s3, catalog, pa_fs)

    assert rc != 0
    tbl = catalog.load_table(("logs", "syslog"))
    assert tbl.scan().to_arrow().num_rows == 1
    assert list_keys(s3, cfg, cfg.desc_prefix) == []
    assert len(list_keys(s3, cfg, cfg.done_prefix)) == 1
    assert list_keys(s3, cfg, cfg.quarantine_prefix) == [cfg.quarantine_prefix + "missing.json"]


def test_incompatible_schema_in_same_table_quarantines_only_that_file(cfg, s3, catalog, pa_fs):
    key1 = "syslog/day=2026-01-01/a.parquet"
    write_parquet(s3, cfg.bucket, key1, {"message": ["m1"]}, "2026-01-01")
    put_descriptor(s3, cfg, "a.json", source="syslog", partition=None, data_key=key1, record_count=1)

    # First run creates the table from a.parquet's schema (message: string).
    assert commit.run(cfg, s3, catalog, pa_fs) == 0

    # Second file has an incompatible column type for the same table -- this
    # must fail add_files with a (permanent) schema-compatibility ValueError,
    # not bring down a batch containing a good file too.
    key2 = "syslog/day=2026-01-02/b.parquet"
    write_parquet(s3, cfg.bucket, key2, {"message": [123]}, "2026-01-02")
    put_descriptor(s3, cfg, "b.json", source="syslog", partition=None, data_key=key2, record_count=1)

    key3 = "syslog/day=2026-01-02/c.parquet"
    write_parquet(s3, cfg.bucket, key3, {"message": ["m3"]}, "2026-01-02")
    put_descriptor(s3, cfg, "c.json", source="syslog", partition=None, data_key=key3, record_count=1)

    rc = commit.run(cfg, s3, catalog, pa_fs)

    assert rc != 0
    tbl = catalog.load_table(("logs", "syslog"))
    assert tbl.scan().to_arrow().num_rows == 2  # a + c, not b
    assert list_keys(s3, cfg, cfg.quarantine_prefix) == [cfg.quarantine_prefix + "b.json"]
    assert sorted(list_keys(s3, cfg, cfg.done_prefix)) == [cfg.done_prefix + "a.json", cfg.done_prefix + "c.json"]


def test_transient_s3_failure_leaves_queue_untouched(cfg, s3, catalog, pa_fs):
    key = "syslog/day=2026-01-01/a.parquet"
    write_parquet(s3, cfg.bucket, key, {"message": ["m1"]}, "2026-01-01")
    put_descriptor(s3, cfg, "a.json", source="syslog", partition=None, data_key=key, record_count=1)

    unreachable_cfg = commit.Config(**{**cfg.__dict__, "s3_endpoint": "http://127.0.0.1:1"})
    unreachable_s3 = commit.make_s3_client(unreachable_cfg)

    rc = commit.run(unreachable_cfg, unreachable_s3, catalog, pa_fs)

    assert rc != 0
    # Nothing was quarantined, and the descriptor is still sitting in the
    # queue -- listing/GETting the queue itself is what failed.
    assert list_keys(s3, cfg, cfg.desc_prefix) == [cfg.desc_prefix + "a.json"]
    assert list_keys(s3, cfg, cfg.quarantine_prefix) == []
    assert list_keys(s3, cfg, cfg.done_prefix) == []


def test_transient_catalog_failure_leaves_queue_and_does_not_quarantine(cfg, s3, catalog, pa_fs):
    key = "syslog/day=2026-01-01/a.parquet"
    write_parquet(s3, cfg.bucket, key, {"message": ["m1"]}, "2026-01-01")
    put_descriptor(s3, cfg, "a.json", source="syslog", partition=None, data_key=key, record_count=1)

    # First run creates the table normally.
    assert commit.run(cfg, s3, catalog, pa_fs) == 0

    # Second descriptor would load the *existing* table -- wrap the catalog so
    # that load_table raises a CommitFailedException, simulating a commit
    # conflict/transient REST error at load time.
    key2 = "syslog/day=2026-01-02/b.parquet"
    write_parquet(s3, cfg.bucket, key2, {"message": ["m2"]}, "2026-01-02")
    put_descriptor(s3, cfg, "b.json", source="syslog", partition=None, data_key=key2, record_count=1)

    class FlakyCatalog:
        def __init__(self, real):
            self._real = real

        def load_table(self, identifier):
            raise CommitFailedException("simulated commit conflict")

        def __getattr__(self, item):
            return getattr(self._real, item)

    rc = commit.run(cfg, s3, FlakyCatalog(catalog), pa_fs)

    assert rc != 0
    assert list_keys(s3, cfg, cfg.desc_prefix) == [cfg.desc_prefix + "b.json"]
    assert list_keys(s3, cfg, cfg.quarantine_prefix) == []
    tbl = catalog.load_table(("logs", "syslog"))
    assert tbl.scan().to_arrow().num_rows == 1  # only the first file


def test_existing_unpartitioned_table_gets_day_spec_added_on_load(cfg, s3, catalog, pa_fs):
    key = "syslog/day=2026-01-01/a.parquet"
    write_parquet(s3, cfg.bucket, key, {"message": ["m1"]}, "2026-01-01")

    # Create the table directly through the catalog, unpartitioned, before
    # commit.py ever sees it -- simulating a table that predates day
    # partitioning (e.g. a partial run that created but didn't get to
    # update_spec()).
    schema = pq.read_schema(pa_fs.open_input_file(f"{cfg.bucket}/{key}"))
    catalog.create_namespace("logs")
    tbl = catalog.create_table(("logs", "syslog"), schema=schema)
    assert tbl.spec().fields == ()

    put_descriptor(s3, cfg, "a.json", source="syslog", partition=None, data_key=key, record_count=1)
    rc = commit.run(cfg, s3, catalog, pa_fs)
    assert rc == 0

    tbl = catalog.load_table(("logs", "syslog"))
    assert len(tbl.spec().fields) == 1
    assert tbl.spec().fields[0].name == "partition_time_day"
