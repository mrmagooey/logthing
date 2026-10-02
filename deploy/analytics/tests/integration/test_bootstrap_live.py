"""bootstrap.py against real Garage, Postgres and Lakekeeper (Docker required)."""
import os
import shutil
import subprocess
import sys
import time
import uuid

import pytest

from conftest import ANALYTICS, BOOTSTRAP

pytestmark = pytest.mark.integration


def _ok(*cmd):
    try:
        return subprocess.run(cmd, capture_output=True, timeout=60).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


if not shutil.which("docker"):
    pytest.skip("docker not available", allow_module_level=True)
if not _ok("docker", "info"):
    pytest.skip("docker daemon not reachable", allow_module_level=True)
if not _ok("docker", "compose", "version"):
    pytest.skip("docker compose not available", allow_module_level=True)

FILES = ["-f", str(ANALYTICS / "docker-compose.yml"),
         "-f", str(ANALYTICS / "tests" / "integration" / "docker-compose.it.yml")]
AK = "GK6b9c062a24e5a702c7c53e5b"
SK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
TOKEN = "demo-garage-admin-token-change-me"
# Compose reads interpolation vars from the shell before --env-file, so pass a scrubbed
# environment: a developer's exported vars or deploy/analytics/.env cannot change the stack.
_KEEP = ("PATH", "HOME", "DOCKER_HOST", "DOCKER_CONFIG", "XDG_RUNTIME_DIR")
COMPOSE_ENV = {k: v for k, v in os.environ.items() if k in _KEEP}


class Stack:
    def __init__(self, envfile):
        self.project = f"lt-it-{uuid.uuid4().hex[:8]}"
        self.envfile = str(envfile)
        self.garage_admin = self.lakekeeper = None

    def compose(self, *args, timeout=300, check=True, capture=False):
        return subprocess.run(
            ["docker", "compose", "--env-file", self.envfile, "-p", self.project, *FILES, *args],
            check=check, env=COMPOSE_ENV, timeout=timeout, capture_output=capture, text=True)

    def port(self, service, container_port):
        out = self.compose("port", service, str(container_port), capture=True).stdout.strip()
        return out.rsplit(":", 1)[1]


@pytest.fixture(scope="module")
def stack(tmp_path_factory):
    envfile = tmp_path_factory.mktemp("it") / "empty.env"
    envfile.write_text("# intentionally empty: compose defaults (demo credentials) apply\n")
    s = Stack(envfile)
    try:
        try:
            s.compose("up", "-d", "--wait", "postgres", "garage", "lakekeeper", timeout=600)
            s.garage_admin = f"http://127.0.0.1:{s.port('garage', 3903)}"
            s.lakekeeper = f"http://127.0.0.1:{s.port('lakekeeper', 8181)}"
        except BaseException:
            s.compose("logs", "--tail", "100", check=False)
            raise
        yield s
    finally:
        s.compose("down", "-v", "--remove-orphans", check=False)


def run(stack, *cmd, timeout=200, **env_extra):
    env = dict(COMPOSE_ENV)
    env.update(GARAGE_ADMIN_URL=stack.garage_admin, GARAGE_ADMIN_TOKEN=TOKEN,
               LAKEKEEPER_URL=stack.lakekeeper,
               S3_ACCESS_KEY=AK, S3_SECRET_KEY=SK,
               # Lakekeeper (inside the compose network) reaches Garage by service name.
               S3_ENDPOINT="http://garage:3900",
               BOOTSTRAP_TIMEOUT_SECS="120")
    env.update(env_extra)
    return subprocess.run([sys.executable, str(BOOTSTRAP), *cmd], env=env,
                          capture_output=True, text=True, timeout=timeout)


def provision(stack):
    for stage in ("garage", "lakekeeper"):
        r = run(stack, stage)
        assert r.returncode == 0, r.stderr


@pytest.fixture(scope="module")
def bootstrapped(stack):
    provision(stack)
    return stack


def s3_probe(stack):
    # Needs boto3, which the committer image ships.
    script = (
        "import boto3;c=boto3.client('s3',endpoint_url='http://garage:3900',"
        f"aws_access_key_id='{AK}',aws_secret_access_key='{SK}',region_name='garage');"
        "c.put_object(Bucket='logthing-data',Key='it/probe',Body=b'x');"
        "assert c.get_object(Bucket='logthing-data',Key='it/probe')['Body'].read()==b'x'"
    )
    stack.compose("run", "--rm", "--no-deps", "--entrypoint", "python", "committer", "-c", script,
                  timeout=300)


def test_bucket_is_usable_with_the_key(bootstrapped):
    s3_probe(bootstrapped)


def test_bootstrap_is_idempotent_and_key_survives(bootstrapped):
    provision(bootstrapped)
    assert run(bootstrapped, "wait", "garage").returncode == 0
    assert run(bootstrapped, "wait", "lakekeeper").returncode == 0
    s3_probe(bootstrapped)


def test_wrong_admin_token_fails_fast(stack):
    t0 = time.monotonic()
    r = run(stack, "garage", GARAGE_ADMIN_TOKEN="wrong", BOOTSTRAP_TIMEOUT_SECS="5", timeout=60)
    assert r.returncode == 1 and "403" in r.stderr
    assert time.monotonic() - t0 < 15
