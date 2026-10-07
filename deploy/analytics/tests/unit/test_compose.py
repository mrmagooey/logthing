import json
import os
import re
import shutil
import signal
import stat
import subprocess
import time

import pytest

from conftest import ANALYTICS, generated_env

if shutil.which("docker") is None:
    pytest.skip("docker not on PATH", allow_module_level=True)


def clean_env():
    keep = ("PATH", "HOME", "DOCKER_HOST", "DOCKER_CONFIG")
    return {k: os.environ[k] for k in keep if k in os.environ}


def run_config(env_file):
    return subprocess.run(
        ["docker", "compose", "--env-file", str(env_file),
         "-f", str(ANALYTICS / "docker-compose.yml"), "config", "--format", "json"],
        capture_output=True, text=True, env=clean_env(),
    )


def compose_config(tmp_path, overrides=None):
    """Render the compose file hermetically: generated secrets + overrides, minimal process env."""
    env = generated_env(tmp_path / "gen.env")
    env.update(overrides or {})
    env_file = tmp_path / "test.env"
    env_file.write_text("".join(f"{k}={v}\n" for k, v in env.items()))
    out = run_config(env_file)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


@pytest.fixture(scope="module")
def cfg(tmp_path_factory):
    return compose_config(tmp_path_factory.mktemp("compose"))


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


def test_compose_credentials_flow_everywhere(tmp_path):
    overrides = {"S3_ACCESS_KEY": "GKffffffffffffffffffffffff", "S3_SECRET_KEY": "f" * 64}
    svc = compose_config(tmp_path, overrides)["services"]
    lt = svc["logthing"]["environment"]
    for src in ("SYSLOG", "IPFIX", "SFLOW", "ZEEK", "ICEBERG"):
        assert lt[f"LOGTHING__{src}__S3__ACCESS_KEY"] == "GKffffffffffffffffffffffff"
        assert lt[f"LOGTHING__{src}__S3__SECRET_KEY"] == "f" * 64
    for s in ("committer", "trino", "garage-init", "lakekeeper-init"):
        assert svc[s]["environment"]["S3_ACCESS_KEY"] == "GKffffffffffffffffffffffff"
        assert svc[s]["environment"]["S3_SECRET_KEY"] == "f" * 64


def _run_committer_script(tmp_path, cfg, stub_body, term_after=0.5):
    c = cfg["services"]["committer"]
    assert c["entrypoint"] == ["/bin/sh", "-c"]
    stubs = tmp_path / "bin"
    stubs.mkdir(exist_ok=True)
    py = stubs / "python"
    py.write_text(f"#!/bin/sh\n{stub_body}\n")
    py.chmod(py.stat().st_mode | stat.S_IXUSR)
    env = {"PATH": f"{stubs}:{os.environ['PATH']}", "COMMIT_INTERVAL_SECS": "30"}
    proc = subprocess.Popen(["/bin/sh", "-c", c["command"][0]], env=env)
    time.sleep(term_after)
    proc.send_signal(signal.SIGTERM)
    start = time.time()
    try:
        rc = proc.wait(timeout=2)
    finally:
        if proc.poll() is None:
            proc.kill()
    return rc, time.time() - start


def test_committer_exits_on_term_while_python_runs(tmp_path, cfg):
    rc, _ = _run_committer_script(tmp_path, cfg, "sleep 30")
    assert rc == 0


def test_committer_exits_on_term_while_sleeping(tmp_path, cfg):
    rc, _ = _run_committer_script(tmp_path, cfg, "exit 0")
    assert rc == 0


def test_committer_script_runs_commit_py(cfg):
    assert "python /app/commit.py" in cfg["services"]["committer"]["command"][0]


def test_bind_mount_sources_exist(cfg):
    for name, svc in cfg["services"].items():
        for v in svc.get("volumes", []):
            if v["type"] == "bind":
                assert os.path.exists(v["source"]), f"{name}: {v['source']}"


def test_non_ingest_ports_default_to_loopback(cfg):
    for name in ("garage", "lakekeeper", "trino", "hue"):
        for p in cfg["services"][name]["ports"]:
            assert p["host_ip"] == "127.0.0.1", name
    for p in cfg["services"]["logthing"]["ports"]:
        assert not p.get("host_ip"), p


def test_long_running_services_restart(cfg):
    for name in ("postgres", "garage", "lakekeeper", "trino", "hue", "logthing", "committer"):
        assert cfg["services"][name]["restart"] == "unless-stopped", name


def test_region_and_bucket_consistent(cfg):
    env = cfg["services"]["committer"]["environment"]
    assert env["S3_REGION"] == "garage"
    assert env["DATA_BUCKET"] == "logthing-data"
    assert env["WAREHOUSE"] == "logthing"


def required_vars():
    return set(re.findall(r"\$\{([A-Z0-9_]+):\?", (ANALYTICS / "docker-compose.yml").read_text()))


def test_env_example_lists_every_required_var_with_an_empty_value():
    env = {}
    for line in (ANALYTICS / ".env.example").read_text().splitlines():
        m = re.fullmatch(r"([A-Z0-9_]+)=(.*)", line)
        if m:
            env[m.group(1)] = m.group(2)
    required = required_vars()
    assert required, "compose declares no required variables"
    assert required <= set(env)
    assert all(env[k] == "" for k in required)


def test_no_required_secret_has_a_public_default():
    compose = (ANALYTICS / "docker-compose.yml").read_text()
    for name in required_vars():
        assert not re.search(r"\$\{%s:-" % name, compose), name
    assert "demo" not in compose.lower() and "change-me" not in compose


def test_missing_required_var_fails_with_an_actionable_message(tmp_path):
    env = generated_env(tmp_path / "gen.env")
    del env["S3_SECRET_KEY"]
    env_file = tmp_path / "partial.env"
    env_file.write_text("".join(f"{k}={v}\n" for k, v in env.items()))
    out = run_config(env_file)
    assert out.returncode != 0
    assert "S3_SECRET_KEY" in out.stderr and "gen-analytics-env.sh" in out.stderr


def test_empty_required_var_is_rejected(tmp_path):
    env = generated_env(tmp_path / "gen.env")
    env["POSTGRES_PASSWORD"] = ""
    env_file = tmp_path / "empty.env"
    env_file.write_text("".join(f"{k}={v}\n" for k, v in env.items()))
    assert run_config(env_file).returncode != 0
