import os
import re
import shutil
import stat
import subprocess

import pytest

from conftest import ANALYTICS, GEN_ENV, generated_env

pytestmark = pytest.mark.skipif(not shutil.which("openssl"), reason="openssl not available")


def required_vars():
    text = (ANALYTICS / "docker-compose.yml").read_text()
    return set(re.findall(r"\$\{([A-Z0-9_]+):\?", text))


def test_emits_exactly_the_vars_compose_requires(tmp_path):
    assert set(generated_env(tmp_path / "a.env")) == required_vars()


def test_value_formats(tmp_path):
    env = generated_env(tmp_path / "a.env")
    assert re.fullmatch(r"GK[0-9a-f]{24}", env["S3_ACCESS_KEY"])
    assert re.fullmatch(r"[0-9a-f]{64}", env["S3_SECRET_KEY"])
    assert re.fullmatch(r"[0-9a-f]{64}", env["GARAGE_RPC_SECRET"])
    for key, value in env.items():
        assert re.fullmatch(r"[A-Za-z0-9]{24,}", value), key  # URL-safe, long enough


def test_two_runs_differ(tmp_path):
    a = generated_env(tmp_path / "a.env")
    b = generated_env(tmp_path / "b.env")
    assert all(a[k] != b[k] for k in a)


def test_file_is_private(tmp_path):
    out = tmp_path / "a.env"
    generated_env(out)
    assert stat.S_IMODE(out.stat().st_mode) == 0o600


def test_refuses_to_overwrite_without_force(tmp_path):
    out = tmp_path / "a.env"
    generated_env(out)
    before = out.read_text()
    r = subprocess.run(["bash", str(GEN_ENV), str(out)], capture_output=True, text=True)
    assert r.returncode == 1 and "--force" in r.stderr
    assert out.read_text() == before
    r = subprocess.run(["bash", str(GEN_ENV), "--force", str(out)], capture_output=True, text=True)
    assert r.returncode == 0 and out.read_text() != before
    assert stat.S_IMODE(out.stat().st_mode) == 0o600


def test_unknown_option_exits_2(tmp_path):
    r = subprocess.run(["bash", str(GEN_ENV), "--bogus"], capture_output=True, text=True)
    assert r.returncode == 2
