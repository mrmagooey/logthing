"""dbt-trino against the real Trino (HTTPS) + Lakekeeper + Garage stack (Docker required).

The tests in this module are ORDERED and share one stack: the first builds against an empty lake,
the second seeds tables, the third proves views must be rebuilt to see them.
"""
import json

import pytest

from stack import Stack, dbt_failure, require_dbt, require_docker, require_trino, run_dbt

pytestmark = pytest.mark.integration
require_docker()
require_trino()
require_dbt()

# CREATE below mirrors what the committer produces: pyiceberg maps Arrow integers of <= 32 bits to
# Iceberg int (Trino integer), so the staging casts to bigint are real widenings.
STAGING = ["stg_wef", "stg_zeek_conn", "stg_zeek_dns", "stg_ipfix", "stg_sflow_flow",
           "stg_suricata"]
TS = "TIMESTAMP '2026-10-01 12:00:00 UTC'"


def q(text):
    return "'" + text.replace("'", "''") + "'"


WEF_4624 = json.dumps({
    "id": "00000000-0000-0000-0000-000000000001", "received_at": "2026-10-01T12:00:05Z",
    "source_host": "ws01", "subscription_id": "sub1",
    "raw_xml": ("<Event><System><EventID>4624</EventID></System><EventData>"
                '<Data Name="TargetUserName">john.doe</Data>'
                "<Data Name='TargetDomainName'>CONTOSO</Data>"
                '<Data Name="LogonType">3</Data><Data Name="IpAddress">192.168.1.100</Data>'
                '<Data Name="IpPort">49234</Data></EventData></Event>'),
    "parsed": {"event_id": 4624, "computer": "WS01.contoso.com",
               "time_created": "2026-10-01T12:00:00Z", "data": None},
})

CREATE = {
    "wef": '(event_id integer, "timestamp" timestamp(6) with time zone, source_host varchar, '
           "subscription_id varchar, event_data varchar, partition_time timestamp(6) with time zone)",
    "zeek_conn": "(ts timestamp(6) with time zone, uid varchar, id_orig_h varchar, "
                 "id_orig_p integer, id_resp_h varchar, id_resp_p integer, proto varchar, "
                 "service varchar, duration double, orig_bytes bigint, resp_bytes bigint, "
                 "conn_state varchar, history varchar, orig_pkts bigint, resp_pkts bigint, "
                 "_extra varchar, partition_time timestamp(6) with time zone)",
    "zeek_dns": "(ts timestamp(6) with time zone, uid varchar, id_orig_h varchar, "
                "id_orig_p integer, id_resp_h varchar, id_resp_p integer, proto varchar, "
                "trans_id integer, query varchar, qtype_name varchar, qclass_name varchar, "
                "rcode_name varchar, answers varchar, _extra varchar, "
                "partition_time timestamp(6) with time zone)",
    "ipfix": "(observation_domain_id integer, template_id integer, protocol_version integer, "
             "exporter varchar, export_time timestamp(6) with time zone, src_addr varchar, "
             "dst_addr varchar, src_port integer, dst_port integer, ip_protocol integer, "
             "octet_delta_count bigint, packet_delta_count bigint, "
             "flow_start timestamp(6) with time zone, flow_end timestamp(6) with time zone, "
             "tcp_flags integer, input_interface integer, output_interface integer, extra varchar, "
             "partition_time timestamp(6) with time zone)",
    "sflow_flow": "(sample_type varchar, exporter varchar, received_at timestamp(6) with time zone, "
                  "src_addr varchar, dst_addr varchar, src_port integer, dst_port integer, "
                  "ip_protocol integer, sampling_rate integer, input_ifindex integer, "
                  "output_ifindex integer, extra varchar, partition_time timestamp(6) with time zone)",
    "suricata": "(event_type varchar, received_at timestamp(6) with time zone, src_ip varchar, "
                "payload varchar, partition_time timestamp(6) with time zone)",
}

INSERT = {
    "wef": f"VALUES (4624, {TS}, 'ws01', 'sub1', {q(WEF_4624)}, {TS})",
    "zeek_conn": f"VALUES ({TS}, 'C1', '10.0.0.5', 51000, '93.184.216.34', 443, 'tcp', 'ssl', "
                 f"1.5, 100, 2000, 'SF', 'ShADad', 4, 6, '{{}}', {TS})",
    "zeek_dns": f"VALUES ({TS}, 'D1', '10.0.0.5', 53211, '10.0.0.1', 53, 'udp', 4242, "
                f"'example.test', 'A', 'C_INTERNET', 'NOERROR', '[]', '{{}}', {TS})",
    "ipfix": f"VALUES (1, 256, 10, '192.0.2.1', {TS}, '10.0.0.6', '203.0.113.5', 40000, 53, 17, "
             f"500, 5, {TS}, {TS}, 0, 1, 2, '{{}}', {TS})",
    "sflow_flow": f"VALUES ('flow', '192.0.2.2', {TS}, '10.0.0.7', '203.0.113.6', 1234, 80, 6, "
                  f"1024, 1, 2, '{{}}', {TS})",
    "suricata": f"VALUES ('alert', {TS}, '10.0.0.8', "
                + q(json.dumps({"timestamp": "2026-10-01T12:00:00.123456+0000", "event_type": "alert",
                                "src_ip": "10.0.0.8", "src_port": 4444, "dest_ip": "198.51.100.7",
                                "dest_port": 22, "proto": "TCP",
                                "alert": {"signature": "ET SCAN test", "signature_id": 2001219,
                                          "severity": 1, "category": "Attempted Recon",
                                          "action": "allowed"}}))
                + f", {TS})",
}


def seed(s):
    s.trino("CREATE SCHEMA IF NOT EXISTS iceberg.logs")
    for table, columns in CREATE.items():
        s.trino(f"CREATE TABLE IF NOT EXISTS iceberg.logs.{table} {columns}")
        s.trino(f"INSERT INTO iceberg.logs.{table} {INSERT[table]}")


@pytest.fixture(scope="module")
def dbt_stack(tmp_path_factory):
    s = Stack(tmp_path_factory.mktemp("dbt"))
    try:
        s.up("trino", timeout=900)
        yield s
    finally:
        s.down()


def test_staging_builds_against_an_empty_lake(dbt_stack):
    r = run_dbt(dbt_stack, "build", "--select", "staging")
    assert dbt_failure(r) is None, dbt_failure(r)
    shown = dbt_stack.trino("SHOW TABLES FROM iceberg.logs LIKE 'stg_%'").split()
    assert sorted(shown) == sorted(STAGING)
    for name in STAGING:
        assert dbt_stack.trino(f"SELECT count(*) FROM iceberg.logs.{name}") == "0", name


def test_views_built_before_a_table_existed_stay_empty_until_rebuilt(dbt_stack):
    seed(dbt_stack)
    assert dbt_stack.trino("SELECT count(*) FROM iceberg.logs.wef") == "1"
    assert dbt_stack.trino("SELECT count(*) FROM iceberg.logs.stg_wef") == "0"
    r = run_dbt(dbt_stack, "build", "--select", "staging")
    assert dbt_failure(r) is None, dbt_failure(r)
    for name in STAGING:
        assert dbt_stack.trino(f"SELECT count(*) FROM iceberg.logs.{name}") == "1", name


def test_staging_columns_are_typed(dbt_stack):
    out = dbt_stack.trino(
        "SELECT column_name, data_type FROM iceberg.information_schema.columns "
        "WHERE table_schema = 'logs' AND table_name = 'stg_ipfix' "
        "AND column_name IN ('src_port', 'octet_delta_count', 'flow_start')")
    types = dict(line.split("\t") for line in out.splitlines())
    assert types == {"src_port": "integer", "octet_delta_count": "bigint",
                     "flow_start": "timestamp(6) with time zone"}


def test_rebuild_is_idempotent(dbt_stack):
    for _ in range(2):
        r = run_dbt(dbt_stack, "build", "--select", "staging")
        assert dbt_failure(r) is None, dbt_failure(r)


def test_full_build_runs_unit_tests_and_schema_tests(dbt_stack):
    r = run_dbt(dbt_stack, "build")
    assert dbt_failure(r) is None, dbt_failure(r)
    assert "unit_test" in r.stdout  # the dbt unit tests really ran


def tsv(stack, sql):
    return [tuple(line.split("\t")) for line in stack.trino(sql).splitlines()]


def test_seeded_rows_land_in_ocsf_authentication(dbt_stack):
    rows = tsv(dbt_stack, "SELECT user_name, user_domain, logon_type_id, src_endpoint_ip, type_uid, "
                          "dst_endpoint_hostname FROM iceberg.logs.ocsf_authentication")
    assert rows == [("john.doe", "CONTOSO", "3", "192.168.1.100", "300201", "WS01.contoso.com")]


def test_seeded_rows_land_in_ocsf_network_activity(dbt_stack):
    rows = tsv(dbt_stack, "SELECT metadata_log_name, src_endpoint_ip, dst_endpoint_port, "
                          "connection_info_protocol_name FROM iceberg.logs.ocsf_network_activity "
                          "ORDER BY 1")
    assert rows == [("ipfix", "10.0.0.6", "53", "udp"), ("sflow_flow", "10.0.0.7", "80", "tcp"),
                    ("zeek_conn", "10.0.0.5", "443", "tcp")]


def test_seeded_rows_land_in_ocsf_dns_and_detection_views(dbt_stack):
    assert tsv(dbt_stack, "SELECT query_hostname, activity_id, rcode FROM "
                          "iceberg.logs.ocsf_dns_activity") == [("example.test", "2", "NOERROR")]
    assert tsv(dbt_stack, "SELECT finding_info_title, severity_id, dst_endpoint_ip FROM "
                          "iceberg.logs.ocsf_detection_finding") == [
        ("ET SCAN test", "4", "198.51.100.7")]


def test_required_ocsf_columns_are_never_null_on_real_rows(dbt_stack):
    for view in ("ocsf_network_activity", "ocsf_dns_activity", "ocsf_authentication",
                 "ocsf_detection_finding"):
        nulls = dbt_stack.trino(
            f'SELECT count(*) FROM iceberg.logs.{view} WHERE "time" IS NULL OR class_uid IS NULL '
            "OR category_uid IS NULL OR activity_id IS NULL OR type_uid IS NULL "
            "OR severity_id IS NULL OR metadata_product_name IS NULL")
        assert nulls == "0", view
