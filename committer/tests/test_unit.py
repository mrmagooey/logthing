"""Unit tests for commit.py: pure functions only, no network, no real S3 or
catalog.
"""

import sys
from pathlib import Path

import pytest
from botocore.exceptions import ClientError, ConnectionClosedError, EndpointConnectionError
from pyiceberg.exceptions import CommitFailedException, CommitStateUnknownException
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


def test_parse_file_path_permanent_errors_are_not_transient():
    # Every failure mode above is a malformed/mismatched descriptor, never a
    # connectivity problem -- is_transient must say so for all of them.
    bad_descs = [
        {"storage_target": "local", "file_path": "file:///x"},
        {"storage_target": "s3"},
        {"storage_target": "s3", "file_path": "http://minio:9000/other/f.parquet"},
    ]
    for desc in bad_descs:
        try:
            commit.parse_file_path(desc, "my-bucket")
        except ValueError as exc:
            assert commit.is_transient(exc) is False


# ---------------------------------------------------------------------------
# is_transient
# ---------------------------------------------------------------------------


def test_is_transient_commit_failed_exception():
    assert commit.is_transient(CommitFailedException("conflict")) is True


def test_is_transient_commit_state_unknown_exception():
    assert commit.is_transient(CommitStateUnknownException("unknown")) is True


def test_is_transient_endpoint_connection_error():
    assert commit.is_transient(EndpointConnectionError(endpoint_url="http://x")) is True


def test_is_transient_connection_closed_error():
    assert commit.is_transient(ConnectionClosedError(endpoint_url="http://x")) is True


def test_is_transient_requests_connection_error():
    assert commit.is_transient(RequestsConnectionError("refused")) is True


def test_is_transient_requests_timeout():
    assert commit.is_transient(RequestsTimeout("timed out")) is True


@pytest.mark.parametrize("status", [500, 502, 503, 504])
def test_is_transient_client_error_5xx(status):
    exc = ClientError(
        {"Error": {"Code": "InternalError"}, "ResponseMetadata": {"HTTPStatusCode": status}},
        "GetObject",
    )
    assert commit.is_transient(exc) is True


@pytest.mark.parametrize("code", ["SlowDown", "Throttling", "ThrottlingException"])
def test_is_transient_client_error_throttling(code):
    exc = ClientError(
        {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": 400}},
        "PutObject",
    )
    assert commit.is_transient(exc) is True


def test_is_transient_client_error_missing_key_is_permanent():
    exc = ClientError(
        {"Error": {"Code": "NoSuchKey"}, "ResponseMetadata": {"HTTPStatusCode": 404}},
        "GetObject",
    )
    assert commit.is_transient(exc) is False


def test_is_transient_client_error_access_denied_is_permanent():
    exc = ClientError(
        {"Error": {"Code": "AccessDenied"}, "ResponseMetadata": {"HTTPStatusCode": 403}},
        "GetObject",
    )
    assert commit.is_transient(exc) is False


def test_is_transient_file_not_found_is_permanent():
    # pyarrow raises FileNotFoundError (an OSError subclass) for a descriptor
    # pointing at a data file that just isn't in the bucket.
    assert commit.is_transient(FileNotFoundError("no such key")) is False


def test_is_transient_generic_os_error_is_transient():
    # Any other OSError out of pyarrow's S3 filesystem is connectivity
    # (refused, reset, DNS, timeout) -- lean transient.
    assert commit.is_transient(OSError("AWS Error NETWORK_CONNECTION: curlCode 7")) is True


def test_is_transient_unrelated_exception_is_permanent():
    assert commit.is_transient(ValueError("bad schema")) is False


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
