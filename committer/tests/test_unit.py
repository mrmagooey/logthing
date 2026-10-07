"""Unit tests for commit.py: pure functions only, no network, no real S3 or
catalog.
"""

import sys
from pathlib import Path

import pyarrow as pa
import pytest
from botocore.exceptions import ClientError, ConnectionClosedError, EndpointConnectionError
from pyiceberg.exceptions import (
    AuthorizationExpiredError,
    BadRequestError,
    CommitFailedException,
    CommitStateUnknownException,
    ForbiddenError,
    OAuthError,
    ServerError,
    ServiceUnavailableError,
    UnauthorizedError,
    ValidationError,
)
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import Timeout as RequestsTimeout

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import commit  # noqa: E402


# ---------------------------------------------------------------------------
# table_name
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "source,partition,expected",
    [
        ("syslog", None, "syslog"),
        ("ipfix", None, "ipfix"),
        ("suricata", None, "suricata"),
        ("wef", None, "wef"),
        ("hec", None, "hec"),
        ("structured_syslog", None, "structured_syslog"),
        # every non-{zeek,aggregate,sflow} source ignores its partition
        ("syslog", "some-partition", "syslog"),
        ("zeek", "conn", "zeek_conn"),
        ("zeek", None, "zeek_unknown"),
        ("aggregate", "high_severity", "agg_high_severity"),
        ("aggregate", None, "agg_unknown"),
        # sflow's "flow" and "counter" partitions are genuinely different
        # Arrow schemas (SflowSink::schema in sflow_s3.rs) -- unlike every
        # other single-schema sink.
        ("sflow", "flow", "sflow_flow"),
        ("sflow", "counter", "sflow_counter"),
        ("sflow", None, "sflow_unknown"),
    ],
)
def test_table_name_for_each_source(source, partition, expected):
    assert commit.table_name(source, partition) == expected


def test_table_name_sanitizes_disallowed_characters():
    assert commit.table_name("zeek", "HTTP-Stream!") == "zeek_http_stream_"


def test_table_name_caps_partition_at_64_characters():
    long_partition = "x" * 100
    name = commit.table_name("aggregate", long_partition)
    assert name == "agg_" + "x" * 64


def test_table_name_sanitizes_arbitrary_source_names_too():
    assert commit.table_name("Weird Source!", None) == "weird_source_"


# ---------------------------------------------------------------------------
# parse_file_path
# ---------------------------------------------------------------------------


def test_parse_file_path_path_style():
    desc = {
        "storage_target": "s3",
        "file_path": "http://minio:9000/my-bucket/zeek/conn/year=2026/month=07/day=10/abc.parquet",
    }
    assert commit.parse_file_path(desc, "my-bucket") == (
        "s3://my-bucket/zeek/conn/year=2026/month=07/day=10/abc.parquet"
    )


def test_parse_file_path_path_style_https_with_port():
    desc = {
        "storage_target": "s3",
        "file_path": "https://s3.example.com:9443/my-bucket/syslog/f.parquet",
    }
    assert commit.parse_file_path(desc, "my-bucket") == "s3://my-bucket/syslog/f.parquet"


def test_parse_file_path_virtual_hosted_style():
    desc = {
        "storage_target": "s3",
        "file_path": "https://my-bucket.s3.amazonaws.com/syslog/f.parquet",
    }
    assert commit.parse_file_path(desc, "my-bucket") == "s3://my-bucket/syslog/f.parquet"


def test_parse_file_path_s3_scheme():
    desc = {"storage_target": "s3", "file_path": "s3://my-bucket/ipfix/f.parquet"}
    assert commit.parse_file_path(desc, "my-bucket") == "s3://my-bucket/ipfix/f.parquet"


def test_parse_file_path_wrong_bucket_path_style():
    desc = {
        "storage_target": "s3",
        "file_path": "http://minio:9000/other-bucket/syslog/f.parquet",
    }
    with pytest.raises(ValueError, match="does not match DATA_BUCKET"):
        commit.parse_file_path(desc, "my-bucket")


def test_parse_file_path_wrong_bucket_s3_scheme():
    desc = {"storage_target": "s3", "file_path": "s3://other-bucket/f.parquet"}
    with pytest.raises(ValueError, match="does not match DATA_BUCKET"):
        commit.parse_file_path(desc, "my-bucket")


def test_parse_file_path_wrong_bucket_virtual_hosted():
    desc = {
        "storage_target": "s3",
        "file_path": "https://other-bucket.s3.amazonaws.com/f.parquet",
    }
    with pytest.raises(ValueError, match="does not match DATA_BUCKET"):
        commit.parse_file_path(desc, "my-bucket")


def test_parse_file_path_rejects_non_s3_storage_target():
    desc = {"storage_target": "local", "file_path": "file:///data/f.parquet"}
    with pytest.raises(ValueError, match="unsupported storage_target"):
        commit.parse_file_path(desc, "my-bucket")


def test_parse_file_path_requires_file_path():
    desc = {"storage_target": "s3"}
    with pytest.raises(ValueError, match="missing required field 'file_path'"):
        commit.parse_file_path(desc, "my-bucket")


def test_parse_file_path_permanent_errors_do_not_abort():
    # Every failure mode above is a malformed/mismatched descriptor, never a
    # connectivity/systemic problem -- should_abort must say so for all of
    # them.
    bad_descs = [
        {"storage_target": "local", "file_path": "file:///x"},
        {"storage_target": "s3"},
        {"storage_target": "s3", "file_path": "http://minio:9000/other/f.parquet"},
    ]
    for desc in bad_descs:
        try:
            commit.parse_file_path(desc, "my-bucket")
        except ValueError as exc:
            assert commit.should_abort(exc) is False


# ---------------------------------------------------------------------------
# should_abort
# ---------------------------------------------------------------------------


def test_should_abort_commit_failed_exception():
    assert commit.should_abort(CommitFailedException("conflict")) is True


def test_should_abort_commit_state_unknown_exception():
    # CommitStateUnknownException is a RESTError subclass: an ambiguous commit
    # outcome, safer to not assume it failed.
    assert commit.should_abort(CommitStateUnknownException("unknown")) is True


def test_should_abort_endpoint_connection_error():
    assert commit.should_abort(EndpointConnectionError(endpoint_url="http://x")) is True


def test_should_abort_connection_closed_error():
    assert commit.should_abort(ConnectionClosedError(endpoint_url="http://x")) is True


def test_should_abort_requests_connection_error():
    assert commit.should_abort(RequestsConnectionError("refused")) is True


def test_should_abort_requests_timeout():
    assert commit.should_abort(RequestsTimeout("timed out")) is True


@pytest.mark.parametrize("status", [500, 502, 503, 504])
def test_should_abort_client_error_5xx(status):
    exc = ClientError(
        {"Error": {"Code": "InternalError"}, "ResponseMetadata": {"HTTPStatusCode": status}},
        "GetObject",
    )
    assert commit.should_abort(exc) is True


@pytest.mark.parametrize("code", ["SlowDown", "Throttling", "ThrottlingException"])
def test_should_abort_client_error_throttling(code):
    exc = ClientError(
        {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": 400}},
        "PutObject",
    )
    assert commit.should_abort(exc) is True


@pytest.mark.parametrize(
    "code",
    ["AccessDenied", "InvalidAccessKeyId", "SignatureDoesNotMatch", "NoSuchBucket", "ExpiredToken"],
)
def test_should_abort_client_error_credentials_and_config_codes(code):
    # These mean the whole run's config/credentials are wrong, not that this
    # one object is bad -- every other descriptor would fail the same way, so
    # this must abort rather than quarantine.
    exc = ClientError(
        {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": 403}},
        "GetObject",
    )
    assert commit.should_abort(exc) is True


@pytest.mark.parametrize("status", [401, 403])
def test_should_abort_client_error_any_401_or_403(status):
    # Even an unrecognised error code should abort on a 401/403 status.
    exc = ClientError(
        {"Error": {"Code": "SomeUnrecognisedCode"}, "ResponseMetadata": {"HTTPStatusCode": status}},
        "GetObject",
    )
    assert commit.should_abort(exc) is True


def test_should_abort_client_error_missing_key_does_not_abort():
    exc = ClientError(
        {"Error": {"Code": "NoSuchKey"}, "ResponseMetadata": {"HTTPStatusCode": 404}},
        "GetObject",
    )
    assert commit.should_abort(exc) is False


def test_should_abort_file_not_found_does_not_abort():
    # pyarrow raises FileNotFoundError (an OSError subclass) for a descriptor
    # pointing at a data file that just isn't in the bucket.
    assert commit.should_abort(FileNotFoundError("no such key")) is False


def test_should_abort_generic_os_error_aborts():
    # Any other OSError out of pyarrow's S3 filesystem is connectivity or a
    # permission problem (refused, reset, DNS, timeout, access denied) --
    # lean toward abort.
    assert commit.should_abort(OSError("AWS Error NETWORK_CONNECTION: curlCode 7")) is True


def test_should_abort_unrelated_exception_does_not_abort():
    assert commit.should_abort(ValueError("bad schema")) is False


@pytest.mark.parametrize(
    "exc",
    [
        ServerError("500"),
        ServiceUnavailableError("503"),
        UnauthorizedError("401"),
        ForbiddenError("403"),
        AuthorizationExpiredError("419"),
        OAuthError("bad client credentials"),
    ],
)
def test_should_abort_rest_errors_other_than_bad_request(exc):
    # Every RESTError except BadRequestError is either a 5xx or an
    # auth/config problem -- both systemic, both must abort.
    assert commit.should_abort(exc) is True


def test_should_abort_bad_request_error_does_not_abort():
    # A 400 is specific to the one request/table that produced it (e.g. one
    # table's create with a bad payload) -- not systemic, stays permanent.
    assert commit.should_abort(BadRequestError("bad create-table request")) is False


# ---------------------------------------------------------------------------
# exit_code
# ---------------------------------------------------------------------------


def test_exit_code_clean_run_is_zero():
    assert commit.exit_code(committed=5, skipped=1, quarantined=0, aborted=False) == 0


def test_exit_code_quarantined_is_nonzero():
    assert commit.exit_code(committed=5, skipped=0, quarantined=1, aborted=False) == 1


def test_exit_code_aborted_is_nonzero_even_with_no_quarantine():
    assert commit.exit_code(committed=0, skipped=0, quarantined=0, aborted=True) == 1


def test_exit_code_aborted_and_quarantined_is_nonzero():
    assert commit.exit_code(committed=1, skipped=0, quarantined=2, aborted=True) == 1


# ---------------------------------------------------------------------------
# main() -- missing required environment variable
# ---------------------------------------------------------------------------


def test_main_missing_required_env_var_exits_2_with_clear_message(monkeypatch, caplog):
    # No DATA_BUCKET/S3_ENDPOINT/etc set at all: Config.from_env() raises a bare
    # KeyError, which main() must turn into a clear, non-traceback error and
    # exit code 2 -- not let a raw KeyError abort the process with a traceback
    # as the only clue.
    for var in (
        "DATA_BUCKET",
        "S3_ENDPOINT",
        "S3_ACCESS_KEY",
        "S3_SECRET_KEY",
        "CATALOG_URI",
    ):
        monkeypatch.delenv(var, raising=False)

    with caplog.at_level("ERROR"):
        assert commit.main() == 2

    assert any("missing required environment variable" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# otlp table naming + additive schema evolution (fakes)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("partition", [None, "checkout_svc", "_overflow", "unknown", "a/b"])
def test_otlp_is_one_table_regardless_of_service_partition(partition):
    # The Parquet path segment is only a per-service grouping key; the Iceberg table is shared.
    assert commit.table_name("otlp", partition) == "otlp"


class _FakeSchema:
    def __init__(self, names):
        self.column_names = list(names)


class _FakeUpdate:
    def __init__(self, tbl):
        self.tbl = tbl
        self.staged = []

    def union_by_name(self, schema):
        if self.tbl.union_error is not None:
            raise self.tbl.union_error
        self.staged = [f.name for f in schema]

    def commit(self):
        if self.tbl.commit_error is not None:
            raise self.tbl.commit_error
        if self.tbl.commit_failures > 0:
            self.tbl.commit_failures -= 1
            raise CommitFailedException("stale table metadata")
        self.tbl.union_calls.append(self.staged)
        for n in self.staged:
            if n not in self.tbl.names:
                self.tbl.names.append(n)


class _FakeTable:
    def __init__(
        self, names, commit_failures=0, union_error=None, commit_error=None, committed=()
    ):
        self.names = list(names)
        self.commit_failures = commit_failures
        self.union_error = union_error
        self.commit_error = commit_error
        self.union_calls = []
        self.committed = set(committed)

    def schema(self):
        return _FakeSchema(self.names)

    def update_schema(self):
        return _FakeUpdate(self)


class _FakeCatalog:
    def __init__(self, reloads):
        self.reloads = list(reloads)
        self.loaded = []

    def load_table(self, ident):
        self.loaded.append(ident)
        return self.reloads.pop(0)


def _ucfg():
    return commit.Config(
        bucket="b",
        s3_endpoint="http://x",
        s3_access_key="k",
        s3_secret_key="s",
        catalog_uri="u",
        warehouse="s3://b/w",
    )


OLD = pa.schema([("sourcetype", pa.string()), ("fields", pa.string())])
NEW = pa.schema([("sourcetype", pa.string()), ("fields", pa.string()), ("event_uuid", pa.string())])


@pytest.fixture
def evolve_env(monkeypatch):
    schemas = {}
    sleeps = []
    monkeypatch.setattr(commit, "_read_file_schema", lambda fs, cfg, uri: schemas[uri])
    monkeypatch.setattr(commit, "force_pyarrow_io", lambda t, c: t)
    monkeypatch.setattr(commit, "committed_file_set", lambda t: set(t.committed))
    monkeypatch.setattr(commit.time, "sleep", lambda s: sleeps.append(s))
    return schemas, sleeps


def _evolve(tbl, batch, catalog=None, committed=None):
    return commit.evolve_schema(
        catalog or _FakeCatalog([]),
        _ucfg(),
        None,
        "hec",
        tbl,
        set() if committed is None else committed,
        batch,
    )


def test_evolve_no_new_columns_makes_no_catalog_call(evolve_env):
    schemas, _ = evolve_env
    schemas["s3://b/a"] = OLD
    tbl = _FakeTable(["sourcetype", "fields", "event_uuid"])
    out, fits, done, conflicted = _evolve(tbl, [("d1", "s3://b/a")])
    assert out is tbl and fits == [("d1", "s3://b/a")] and done == [] and conflicted == []
    assert tbl.union_calls == []


def test_evolve_adds_missing_columns_once_per_file_that_needs_it(evolve_env):
    schemas, _ = evolve_env
    schemas["s3://b/new"] = NEW
    schemas["s3://b/new2"] = NEW
    tbl = _FakeTable(["sourcetype", "fields"])
    _, fits, _, conflicted = _evolve(tbl, [("d1", "s3://b/new"), ("d2", "s3://b/new2")])
    assert len(fits) == 2 and conflicted == []
    assert len(tbl.union_calls) == 1, "second file no longer needs evolution"
    assert "event_uuid" in tbl.names


def test_evolve_type_conflict_quarantines_only_that_file(evolve_env):
    schemas, _ = evolve_env
    schemas["s3://b/bad"] = NEW
    schemas["s3://b/ok"] = OLD
    tbl = _FakeTable(["sourcetype", "fields"], union_error=ValidationError("type mismatch"))
    _, fits, _, conflicted = _evolve(tbl, [("d1", "s3://b/bad"), ("d2", "s3://b/ok")])
    assert conflicted == [("d1", "s3://b/bad")]
    assert fits == [("d2", "s3://b/ok")]
    assert tbl.union_calls == [], "a rejected file must never commit staged columns"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"union_error": ValueError("Cannot add required column: x")},
        {"commit_error": BadRequestError("catalog rejected schema update")},
    ],
)
def test_evolve_required_column_or_catalog_400_quarantines_only_that_file(evolve_env, kwargs):
    schemas, _ = evolve_env
    schemas["s3://b/bad"] = NEW
    schemas["s3://b/ok"] = OLD
    tbl = _FakeTable(["sourcetype", "fields"], **kwargs)
    _, fits, _, conflicted = _evolve(tbl, [("d1", "s3://b/bad"), ("d2", "s3://b/ok")])
    assert conflicted == [("d1", "s3://b/bad")]
    assert fits == [("d2", "s3://b/ok")]


@pytest.mark.parametrize("exc", [ServerError("boom"), UnauthorizedError("no"), ForbiddenError("no")])
def test_evolve_abort_class_errors_raise_abort(evolve_env, exc):
    schemas, _ = evolve_env
    schemas["s3://b/new"] = NEW
    tbl = _FakeTable(["sourcetype", "fields"], commit_error=exc)
    with pytest.raises(commit._Abort):
        _evolve(tbl, [("d1", "s3://b/new")])


def test_evolve_s3_credential_error_reading_footer_raises_abort(evolve_env, monkeypatch):
    def deny(fs, cfg, uri):
        raise ClientError(
            {"Error": {"Code": "AccessDenied"}, "ResponseMetadata": {"HTTPStatusCode": 403}},
            "GetObject",
        )

    monkeypatch.setattr(commit, "_read_file_schema", deny)
    with pytest.raises(commit._Abort):
        _evolve(_FakeTable(["sourcetype"]), [("d1", "s3://b/new")])


def test_evolve_missing_footer_quarantines_that_file(evolve_env, monkeypatch):
    def missing(fs, cfg, uri):
        raise FileNotFoundError(uri)

    monkeypatch.setattr(commit, "_read_file_schema", missing)
    _, fits, _, conflicted = _evolve(_FakeTable(["sourcetype"]), [("d1", "s3://b/gone")])
    assert fits == [] and conflicted == [("d1", "s3://b/gone")]


def test_evolve_retries_commit_conflicts_with_backoff_and_reloads(evolve_env):
    schemas, sleeps = evolve_env
    schemas["s3://b/new"] = NEW
    stale = _FakeTable(["sourcetype", "fields"], commit_failures=2)
    fresh1 = _FakeTable(["sourcetype", "fields"], commit_failures=1)
    fresh2 = _FakeTable(["sourcetype", "fields"])
    cat = _FakeCatalog([fresh1, fresh2])
    out, fits, _, _ = _evolve(stale, [("d1", "s3://b/new")], catalog=cat)
    assert out is fresh2 and fits == [("d1", "s3://b/new")]
    assert sleeps == [0.2, 0.4]
    assert cat.loaded == [("logs", "hec"), ("logs", "hec")]


def test_evolve_gives_up_after_five_commit_conflicts(evolve_env):
    schemas, sleeps = evolve_env
    schemas["s3://b/new"] = NEW
    tables = [_FakeTable(["sourcetype", "fields"], commit_failures=9) for _ in range(5)]
    with pytest.raises(CommitFailedException):
        _evolve(tables[0], [("d1", "s3://b/new")], catalog=_FakeCatalog(tables[1:]))
    assert sleeps == [0.2, 0.4, 0.8, 1.6]


def test_evolve_reload_rededupes_files_another_committer_registered(evolve_env):
    schemas, _ = evolve_env
    schemas["s3://b/new"] = NEW
    schemas["s3://b/other"] = NEW
    stale = _FakeTable(["sourcetype", "fields"], commit_failures=1)
    fresh = _FakeTable(["sourcetype", "fields"], committed={"s3://b/other"})
    committed = set()
    _, fits, done, _ = _evolve(
        stale,
        [("d1", "s3://b/new"), ("d2", "s3://b/other")],
        catalog=_FakeCatalog([fresh]),
        committed=committed,
    )
    assert fits == [("d1", "s3://b/new")]
    assert done == [("d2", "s3://b/other")]
    assert committed == {"s3://b/other"}, "caller's committed set is refreshed in place"


def test_is_already_referenced_matches_only_that_value_error():
    assert commit._is_already_referenced(
        ValueError("Cannot add files that are already referenced by table, files: s3://x")
    )
    assert not commit._is_already_referenced(ValueError("schema mismatch"))
    assert not commit._is_already_referenced(RuntimeError("already referenced"))
