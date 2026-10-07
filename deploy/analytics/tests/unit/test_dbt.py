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
                 "sflow_flow", "sflow_counter", "suricata", "hec"}
STAGING = {"stg_wef": "wef", "stg_zeek_conn": "zeek_conn", "stg_zeek_dns": "zeek_dns",
           "stg_ipfix": "ipfix", "stg_sflow_flow": "sflow_flow", "stg_suricata": "suricata"}


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
    assert {n for n in models if n.startswith("stg_")} == set(STAGING)
    for name in STAGING:
        assert models[name]["config"]["materialized"] == "view", name


def test_each_staging_model_reads_exactly_one_source(manifest):
    models = nodes(manifest, "model")
    for name, table in STAGING.items():
        assert models[name]["depends_on"]["nodes"] == [
            f"source.logthing_analytics.logthing.{table}"], name


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
