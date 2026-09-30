"""Unit tests for commit.py: pure functions only, no network, no real S3 or
catalog.
"""

import sys
from pathlib import Path

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
