"""dbt-trino against the real Trino (HTTPS) + Lakekeeper + Garage stack (Docker required).

The tests in this module are ORDERED and share one stack: the first builds against an empty lake,
the second seeds tables, the third proves views must be rebuilt to see them.
"""
import json
import os
import re
from datetime import datetime, timedelta, timezone

import pytest
import yaml

from stack import DBT_DIR, Stack, dbt_failure, require_dbt, require_docker, require_trino, run_dbt

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
        s.up("trino", timeout=int(os.environ.get("UP_TIMEOUT_SECS", "900")))
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
    declared = yaml.safe_load((DBT_DIR / "models" / "ocsf" / "unit_tests.yml").read_text())
    ran = re.findall(r"START unit_test ", r.stdout)
    assert len(ran) == len(declared["unit_tests"]) > 0, (len(ran), r.stdout[-3000:])


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
    assert tsv(dbt_stack, "SELECT finding_info_title, severity_id, dst_endpoint_ip, "
                          'CAST("time" AS varchar) FROM iceberg.logs.ocsf_detection_finding') == [
        ("ET SCAN test", "4", "198.51.100.7", "2026-10-01 12:00:00.123456 UTC")]  # microseconds kept


def test_required_ocsf_columns_are_never_null_on_real_rows(dbt_stack):
    for view in ("ocsf_network_activity", "ocsf_dns_activity", "ocsf_authentication",
                 "ocsf_detection_finding"):
        nulls = dbt_stack.trino(
            f'SELECT count(*) FROM iceberg.logs.{view} WHERE "time" IS NULL OR class_uid IS NULL '
            "OR category_uid IS NULL OR activity_id IS NULL OR type_uid IS NULL "
            "OR severity_id IS NULL OR metadata_product_name IS NULL")
        assert nulls == "0", view


# The detections take a pinned reference time (dbt var detection_as_of), never the wall clock.
# The seeded 2026-10-01 rows are 4 days old at AS_OF, so they form the port baseline and sit
# outside every one-day window; only the rows inserted below, one hour before AS_OF, can fire.
AS_OF = datetime(2026, 10, 5, 12, 0, 0, tzinfo=timezone.utc)
PIN = ["--vars", '{detection_as_of: "2026-10-05T12:00:00Z"}']


def lit(dt):
    return "TIMESTAMP '" + dt.strftime("%Y-%m-%d %H:%M:%S") + " UTC'"


def failed_logon(i, when):
    xml = ('<Event><EventData><Data Name="TargetUserName">user%d</Data>'
           '<Data Name="TargetDomainName">CONTOSO</Data><Data Name="LogonType">3</Data>'
           '<Data Name="IpAddress">203.0.113.9</Data></EventData></Event>' % i)
    blob = json.dumps({"raw_xml": xml, "parsed": {
        "event_id": 4625, "computer": "WS01.contoso.com",
        "time_created": when.strftime("%Y-%m-%dT%H:%M:%SZ")}})
    return f"(4625, {lit(when)}, 'ws01', 'sub', {q(blob)}, {lit(when)})"


def analysis(stack, name):
    compiled = (stack.envfile.parent / "dbttarget" / "compiled" / "logthing_analytics"
                / "analyses" / f"{name}.sql")
    return [tuple(line.split("\t")) for line in stack.trino(compiled.read_text()).splitlines()
            if line]


def test_analyses_compile_and_fire_on_fresh_seeded_activity(dbt_stack):
    fresh = AS_OF - timedelta(hours=1)
    dbt_stack.trino("INSERT INTO iceberg.logs.wef VALUES "
                    + ", ".join(failed_logon(i, fresh) for i in range(12)))
    alert = json.dumps({"timestamp": fresh.strftime("%Y-%m-%dT%H:%M:%S.000000+0000"),
                        "src_ip": "10.0.0.66", "dest_ip": "198.51.100.77", "dest_port": 445,
                        "proto": "TCP", "alert": {"signature": "ET EXPLOIT test",
                                                  "signature_id": 2024000, "severity": 1}})
    dbt_stack.trino(f"INSERT INTO iceberg.logs.suricata VALUES ('alert', {lit(fresh)}, "
                    f"'10.0.0.66', {q(alert)}, {lit(fresh)})")
    dbt_stack.trino("INSERT INTO iceberg.logs.zeek_conn VALUES "
                    f"({lit(fresh)}, 'C99', '10.0.0.5', 52000, '203.0.113.77', 31337, 'tcp', NULL, "
                    f"0.5, 10, 20, 'SF', 'ShAD', 1, 1, '{{}}', {lit(fresh)})")
    r = run_dbt(dbt_stack, "compile", *PIN)
    assert r.returncode == 0, r.stdout[-3000:] + r.stderr

    brute = analysis(dbt_stack, "detect_auth_bruteforce")
    assert [(row[0], row[2], row[3]) for row in brute] == [("203.0.113.9", "12", "12")]
    assert [(row[0], row[1]) for row in analysis(dbt_stack, "detect_suricata_high_severity")] == [
        ("198.51.100.77", "1")]
    assert [(row[0], row[1]) for row in analysis(dbt_stack, "detect_rare_outbound_port")] == [
        ("31337", "1")]


def test_detection_threshold_variable_is_honoured(dbt_stack):
    r = run_dbt(dbt_stack, "compile", "--vars",
                '{detection_as_of: "2026-10-05T12:00:00Z", bruteforce_threshold: 13}')
    assert r.returncode == 0, r.stdout[-3000:] + r.stderr
    assert analysis(dbt_stack, "detect_auth_bruteforce") == []


def test_pinned_reference_time_excludes_activity_outside_the_window(dbt_stack):
    far_future = '{detection_as_of: "2027-01-01T00:00:00Z"}'
    r = run_dbt(dbt_stack, "compile", "--vars", far_future)
    assert r.returncode == 0, r.stdout[-3000:] + r.stderr
    for name in ("detect_auth_bruteforce", "detect_suricata_high_severity"):
        assert analysis(dbt_stack, name) == [], name


def test_second_full_build_is_idempotent(dbt_stack):
    for _ in range(2):
        r = run_dbt(dbt_stack, "build")
        assert dbt_failure(r) is None, dbt_failure(r)
