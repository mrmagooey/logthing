import json
import os
import subprocess

import pytest

from conftest import ANALYTICS


def compose_config(env=None):
    out = subprocess.run(
        ["docker", "compose", "-f", str(ANALYTICS / "docker-compose.yml"),
         "config", "--format", "json"],
        capture_output=True, text=True, check=True, env=env,
    )
    return json.loads(out.stdout)


@pytest.fixture(scope="module")
def cfg():
    return compose_config()


def test_all_services_present(cfg):
    assert set(cfg["services"]) == {
        "postgres", "garage", "garage-init", "lakekeeper-migrate", "lakekeeper",
        "lakekeeper-init", "logthing", "committer", "trino", "hue",
    }


def test_pinned_default_images(cfg):
    img = {k: v["image"] for k, v in cfg["services"].items()}
    assert img["logthing"] == "ghcr.io/mrmagooey/logthing:0.21.0"
    assert img["committer"] == "ghcr.io/mrmagooey/logthing-committer:0.21.0"
    assert img["garage"] == "dxflrs/garage:v2.4.1"
    assert img["trino"] == "trinodb/trino:483"
    assert img["hue"] == "gethue/hue:20260611-140101"
    assert img["lakekeeper"] == "quay.io/lakekeeper/catalog:v0.13.6"


def test_ordering(cfg):
    def dep(s):
        return {k: v["condition"] for k, v in cfg["services"][s].get("depends_on", {}).items()}

    assert dep("garage-init") == {"garage": "service_healthy"}
    assert dep("lakekeeper-init") == {
        "lakekeeper": "service_healthy", "garage-init": "service_completed_successfully"}
    assert dep("logthing") == {"garage-init": "service_completed_successfully"}
    assert dep("committer") == {"lakekeeper-init": "service_completed_successfully"}
    assert dep("trino") == {"lakekeeper-init": "service_completed_successfully"}
    assert dep("hue") == {"postgres": "service_healthy", "trino": "service_healthy"}


def test_postgres_healthcheck_uses_tcp(cfg):
    assert "-h 127.0.0.1" in " ".join(cfg["services"]["postgres"]["healthcheck"]["test"])


def test_compose_credentials_flow_everywhere():
    env = dict(os.environ, S3_ACCESS_KEY="GKffffffffffffffffffffffff", S3_SECRET_KEY="f" * 64)
    svc = compose_config(env)["services"]
    lt = svc["logthing"]["environment"]
    for src in ("SYSLOG", "IPFIX", "SFLOW", "ZEEK", "ICEBERG"):
        assert lt[f"LOGTHING__{src}__S3__ACCESS_KEY"] == "GKffffffffffffffffffffffff"
        assert lt[f"LOGTHING__{src}__S3__SECRET_KEY"] == "f" * 64
    for s in ("committer", "trino", "garage-init", "lakekeeper-init"):
        assert svc[s]["environment"]["S3_ACCESS_KEY"] == "GKffffffffffffffffffffffff"
        assert svc[s]["environment"]["S3_SECRET_KEY"] == "f" * 64


def test_committer_loop_traps_term(cfg):
    c = cfg["services"]["committer"]
    assert c["entrypoint"] == ["/bin/sh", "-c"]
    script = c["command"][0]
    assert "trap 'exit 0' TERM" in script and "& wait" in script
    assert "python /app/commit.py" in script


def test_region_and_bucket_consistent(cfg):
    env = cfg["services"]["committer"]["environment"]
    assert env["S3_REGION"] == "garage"
    assert env["DATA_BUCKET"] == "logthing-data"
    assert env["WAREHOUSE"] == "logthing"
