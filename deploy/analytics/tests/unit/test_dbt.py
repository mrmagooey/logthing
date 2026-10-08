import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from conftest import ANALYTICS

DBT_DIR = ANALYTICS / "dbt"
DBT_BIN = Path(sys.executable).parent / "dbt"

pytestmark = pytest.mark.skipif(not DBT_BIN.exists(), reason="dbt is not installed in this venv")

SOURCE_TABLES = {"wef", "syslog", "structured_syslog", "zeek_conn", "zeek_dns", "ipfix",
                 "sflow_flow", "sflow_counter", "suricata", "hec", "otlp"}
STAGING = {"stg_wef": "wef", "stg_zeek_conn": "zeek_conn", "stg_zeek_dns": "zeek_dns",
           "stg_ipfix": "ipfix", "stg_sflow_flow": "sflow_flow", "stg_suricata": "suricata",
           "stg_otlp_typed": "otlp", "stg_hec_typed": "hec"}


@pytest.fixture(scope="module")
def manifest(tmp_path_factory):
    out = tmp_path_factory.mktemp("dbt")
    env = {"PATH": os.environ["PATH"], "HOME": str(out), "TRINO_PASSWORD": "x",
           "TRINO_CA_CERT": "/nonexistent/ca.pem", "DBT_SEND_ANONYMOUS_USAGE_STATS": "false"}
    r = subprocess.run(
        [str(DBT_BIN), "--log-path", str(out / "logs"), "parse", "--project-dir", str(DBT_DIR),
         "--profiles-dir", str(DBT_DIR), "--target-path", str(out / "target")],
        env=env, capture_output=True, text=True, timeout=300)
    assert r.returncode == 0, r.stdout + r.stderr
    return json.loads((out / "target" / "manifest.json").read_text())


def nodes(manifest, rtype):
    return {n["name"]: n for n in manifest["nodes"].values() if n["resource_type"] == rtype}


def test_sources_cover_every_table_the_stack_creates(manifest):
    names = {s["name"] for s in manifest["sources"].values() if s["source_name"] == "logthing"}
    assert names == SOURCE_TABLES
    for s in manifest["sources"].values():
        assert (s["database"], s["schema"]) == ("iceberg", "logs")


def test_staging_models_exist_and_are_views(manifest):
    models = nodes(manifest, "model")
    expected = set(STAGING) | {"stg_otlp", "stg_hec"}
    assert {n for n in models if n.startswith("stg_")} == expected
    for name in expected:
        assert models[name]["config"]["materialized"] == "view", name


def test_each_staging_model_reads_exactly_one_source(manifest):
    models = nodes(manifest, "model")
    for name, table in STAGING.items():
        assert models[name]["depends_on"]["nodes"] == [
            f"source.logthing_analytics.logthing.{table}"], name


def test_dedup_models_read_only_their_typed_model_and_are_unit_tested(manifest):
    models = nodes(manifest, "model")
    for name in ("stg_otlp", "stg_hec"):
        assert models[name]["depends_on"]["nodes"] == [
            f"model.logthing_analytics.{name}_typed"], name
        assert models[name]["config"]["materialized"] == "view"
    unit = {u["name"]: u for u in manifest["unit_tests"].values()}
    assert {"stg_otlp_keeps_one_row_per_event_uuid",
            "stg_hec_dedups_but_keeps_every_legacy_null_uuid_row"} <= set(unit)


def test_dedup_models_have_unique_event_uuid_tests(manifest):
    tests = [n for n in nodes(manifest, "test").values()
             if n.get("test_metadata", {}).get("name") == "unique"]
    assert {t["attached_node"].split(".")[-1] for t in tests} >= {"stg_otlp", "stg_hec"}


def test_source_or_empty_fills_columns_missing_from_an_existing_table():
    text = (DBT_DIR / "macros" / "source_or_empty.sql").read_text()
    assert "get_columns_in_relation" in text and "cast(null as" in text


def test_staging_models_have_not_null_tests(manifest):
    tests = [n for n in nodes(manifest, "test").values()
             if n.get("test_metadata", {}).get("name") == "not_null"]
    covered = {t["attached_node"].split(".")[-1] for t in tests}
    assert set(STAGING) <= covered


def test_macro_substitutes_a_typed_empty_select_for_missing_tables():
    text = (DBT_DIR / "macros" / "source_or_empty.sql").read_text()
    assert "adapter.get_relation" in text and "where false" in text and "cast(null as" in text


def test_profile_is_https_trino_with_credentials_from_env():
    text = (DBT_DIR / "profiles.yml").read_text()
    out = yaml.safe_load(text)["logthing_analytics"]["outputs"]["trino"]
    assert (out["type"], out["method"], out["http_scheme"]) == ("trino", "ldap", "https")
    assert (out["database"], out["schema"]) == ("iceberg", "logs")
    assert "env_var('TRINO_PASSWORD')" in text and "env_var('TRINO_CA_CERT')" in text
    assert not re.search(r"env_var\('TRINO_(PASSWORD|CA_CERT)',", text)  # no silent defaults


def test_dbt_dependencies_are_pinned_exactly():
    lines = {l.strip() for l in (DBT_DIR / "requirements.txt").read_text().splitlines()}
    assert {"dbt-core==1.11.15", "dbt-trino==1.10.6"} <= lines
    reqs = (ANALYTICS / "tests" / "requirements.txt").read_text()
    assert "-r ../dbt/requirements.txt" in reqs


OCSF = {"ocsf_network_activity": 4001, "ocsf_dns_activity": 4003,
        "ocsf_authentication": 3002, "ocsf_detection_finding": 2004}
REQUIRED = ["time", "category_uid", "class_uid", "activity_id", "type_uid", "severity_id",
            "metadata_product_name"]


def test_ocsf_models_exist_and_read_only_staging_models(manifest):
    models = nodes(manifest, "model")
    assert {n for n in models if n.startswith("ocsf_")} == set(OCSF)
    for name in OCSF:
        deps = models[name]["depends_on"]["nodes"]
        assert deps and all(d.startswith("model.logthing_analytics.stg_") for d in deps), name


def test_every_ocsf_model_has_not_null_tests_on_the_required_columns(manifest):
    tests = [n for n in nodes(manifest, "test").values()
             if n.get("test_metadata", {}).get("name") == "not_null"]
    for model in OCSF:
        cols = {t["column_name"] for t in tests if t["attached_node"].endswith(f".{model}")}
        assert set(REQUIRED) <= cols, (model, set(REQUIRED) - cols)


def test_class_uid_is_pinned_per_model(manifest):
    tests = [n for n in nodes(manifest, "test").values()
             if n.get("test_metadata", {}).get("name") == "accepted_values"
             and n["column_name"] == "class_uid"]

    def values(t):
        kw = t["test_metadata"]["kwargs"]
        return kw.get("arguments", kw)["values"]

    pinned = {t["attached_node"].split(".")[-1]: values(t) for t in tests}
    assert pinned == {m: [uid] for m, uid in OCSF.items()}
    for t in tests:  # integer values must not be rendered as quoted strings
        kw = t["test_metadata"]["kwargs"]
        assert kw.get("arguments", kw)["quote"] is False


def test_every_ocsf_model_has_a_unit_test_and_wef_covers_a_4624_blob(manifest):
    by_model = {}
    for t in manifest["unit_tests"].values():
        by_model.setdefault(t["model"], []).append(t)
    assert {m for m in by_model if m.startswith("ocsf_")} == set(OCSF)
    auth = by_model["ocsf_authentication"]
    blobs = " ".join(str(g.get("rows")) for t in auth for g in t["given"])
    assert "4624" in blobs and "TargetUserName" in blobs and "raw_xml" in blobs
    assert "not json at all" in blobs  # malformed JSON row
    assert "''TargetDomainName''" in blobs  # single-quoted attribute style


def test_ocsf_models_document_the_wef_extraction_limit(manifest):
    desc = nodes(manifest, "model")["ocsf_authentication"]["description"]
    assert "raw_xml" in desc and "NULL" in desc


def _wef_regex(name):
    text = (DBT_DIR / "macros" / "wef_field.sql").read_text()
    sql = re.search(r"regexp_extract\(\{\{ xml_col \}\}, '((?:[^']|'')*)', 1\)", text).group(1)
    return re.compile(sql.replace("''", "'").replace("{{ name }}", name))


@pytest.mark.parametrize("xml,want", [
    ('<Data Name="TargetUserName">john.doe</Data>', "john.doe"),
    ("<Data Name='TargetUserName'>john.doe</Data>", "john.doe"),
    ('<Data Name="TargetUserName" Foo="1">x y</Data>', "x y"),
    ('<Data Name="TargetUserName"></Data>', ""),
    ('<Data Name="Other">v</Data>', None),
    ('<Data Name="TargetUserName"/><Data Name="X">v</Data>', None),
    ('<Data Name="TargetUserName" />\n<Data Name="X">v</Data>', None),
    ('<Data Name="XTargetUserName">v</Data>', None),
    ("not xml at all", None),
])
def test_wef_field_regex_handles_quote_styles_and_absence(xml, want):
    m = _wef_regex("TargetUserName").search(xml)
    assert (m.group(1) if m else None) == want


def test_wef_field_turns_blank_and_dash_into_null():
    text = (DBT_DIR / "macros" / "wef_field.sql").read_text()
    assert "nullif(nullif(trim(" in text and "'-'" in text


ANALYSES = {"detect_auth_bruteforce": "ocsf_authentication",
            "detect_suricata_high_severity": "ocsf_detection_finding",
            "detect_rare_outbound_port": "ocsf_network_activity"}


def test_three_detection_analyses_read_only_ocsf_views(manifest):
    found = nodes(manifest, "analysis")
    assert set(found) == set(ANALYSES)
    for name, model in ANALYSES.items():
        assert found[name]["depends_on"]["nodes"] == [f"model.logthing_analytics.{model}"], name
        text = (DBT_DIR / "analyses" / f"{name}.sql").read_text()
        assert "iceberg.logs" not in text and "source(" not in text, name


def test_detection_thresholds_are_dbt_vars():
    text = "".join((DBT_DIR / "analyses" / f"{n}.sql").read_text() for n in ANALYSES)
    for var in ("bruteforce_threshold", "suricata_min_severity_id", "rare_port_max_connections"):
        assert f"var('{var}'" in text, var


def test_detections_take_their_reference_time_from_one_pinned_macro_never_the_wall_clock():
    for n in ANALYSES:
        text = (DBT_DIR / "analyses" / f"{n}.sql").read_text()
        assert "current_timestamp" not in text and not re.search(r"(?<!detection_)now\(\)", text), n
        assert "detection_now()" in text, n
    macro = (DBT_DIR / "macros" / "detection_now.sql").read_text()
    assert "var('detection_as_of'" in macro and "current_timestamp" in macro


def test_readme_documents_scope_decisions():
    text = (DBT_DIR / "README.md").read_text()
    for needle in ("pySigma", "syslog", "raw_xml", "dbt run", "CronJob", "stg_otlp",
                   "detection_as_of", "TextQueryBackend", "2026-10-06"):
        assert needle in text, needle


def test_zeek_protocol_number_is_mapped_from_the_name_in_the_network_view():
    text = (DBT_DIR / "models" / "ocsf" / "ocsf_network_activity.sql").read_text()
    assert "ip_protocol_num" in text
    unit = (DBT_DIR / "models" / "ocsf" / "unit_tests.yml").read_text()
    assert "connection_info_protocol_num: 6" in unit and "connection_info_protocol_num: 58" in unit


def _render_bound(variables):
    from jinja2 import Environment
    src = (DBT_DIR / "macros" / "detection_now.sql").read_text()
    env = Environment()
    tmpl = env.from_string(src + "{{ detection_upper_bound() }}",
                           globals={"var": lambda k, d=None: variables.get(k, d)})
    return tmpl.render().strip()


def test_detection_as_of_adds_an_upper_bound_only_when_set():
    assert _render_bound({}) == ""
    bound = _render_bound({"detection_as_of": "2026-10-05T12:00:00Z"})
    assert bound == 'and "time" <= from_iso8601_timestamp(\'2026-10-05T12:00:00Z\')'
    for n in ANALYSES:
        text = (DBT_DIR / "analyses" / f"{n}.sql").read_text()
        assert "detection_upper_bound()" in text, n
