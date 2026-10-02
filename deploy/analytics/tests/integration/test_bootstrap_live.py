"""bootstrap.py against real Garage, Postgres and Lakekeeper (Docker required)."""
import os
import shutil
import subprocess
import sys

import pytest

from conftest import ANALYTICS, BOOTSTRAP

pytestmark = pytest.mark.integration
if not shutil.which("docker"):
    pytest.skip("docker not available", allow_module_level=True)

PROJECT = "lt-analytics-it"
FILES = ["-f", str(ANALYTICS / "docker-compose.yml"),
         "-f", str(ANALYTICS / "tests" / "integration" / "docker-compose.it.yml")]
AK = "GK6b9c062a24e5a702c7c53e5b"
SK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
TOKEN = "demo-garage-admin-token-change-me"
# Compose reads interpolation vars from the shell before --env-file, so pass a scrubbed
# environment: a developer's exported vars or deploy/analytics/.env cannot change the stack.
_KEEP = ("PATH", "HOME", "DOCKER_HOST", "DOCKER_CONFIG", "XDG_RUNTIME_DIR")
COMPOSE_ENV = {k: v for k, v in os.environ.items() if k in _KEEP}


@pytest.fixture(scope="module")
def envfile(tmp_path_factory):
    p = tmp_path_factory.mktemp("it") / "empty.env"
    p.write_text("# intentionally empty: compose defaults (demo credentials) apply\n")
    return p


@pytest.fixture(scope="module")
def compose(envfile):
    def run_compose(*args):
        subprocess.run(["docker", "compose", "--env-file", str(envfile), "-p", PROJECT,
                        *FILES, *args], check=True, env=COMPOSE_ENV)
    return run_compose


@pytest.fixture(scope="module")
def stack(compose):
    try:
        compose("up", "-d", "--wait", "postgres", "garage", "lakekeeper")
        yield
    finally:
        compose("down", "-v")


def run(*cmd, **env_extra):
    env = dict(os.environ)
    env.update(GARAGE_ADMIN_URL="http://127.0.0.1:23903", GARAGE_ADMIN_TOKEN=TOKEN,
               LAKEKEEPER_URL="http://127.0.0.1:28181",
               S3_ACCESS_KEY=AK, S3_SECRET_KEY=SK,
               # Lakekeeper (inside the compose network) reaches Garage by service name.
               S3_ENDPOINT="http://garage:3900",
               BOOTSTRAP_TIMEOUT_SECS="120")
    env.update(env_extra)
    return subprocess.run([sys.executable, str(BOOTSTRAP), *cmd], env=env,
                          capture_output=True, text=True)


def test_full_bootstrap_twice_then_wait(stack):
    for _ in range(2):
        r = run("garage")
        assert r.returncode == 0, r.stderr
        r = run("lakekeeper")
        assert r.returncode == 0, r.stderr
    assert run("wait", "garage").returncode == 0
    assert run("wait", "lakekeeper").returncode == 0


def test_bucket_is_usable_with_the_key(stack, compose):
    # Needs boto3, which the committer image ships. Runs after the bootstrap test (file order).
    script = (
        "import boto3;c=boto3.client('s3',endpoint_url='http://garage:3900',"
        f"aws_access_key_id='{AK}',aws_secret_access_key='{SK}',region_name='garage');"
        "c.put_object(Bucket='logthing-data',Key='it/probe',Body=b'x');"
        "assert c.get_object(Bucket='logthing-data',Key='it/probe')['Body'].read()==b'x'"
    )
    compose("run", "--rm", "--no-deps", "--entrypoint", "python", "committer", "-c", script)


def test_wrong_admin_token_fails_fast(stack):
    r = run("garage", GARAGE_ADMIN_TOKEN="wrong", BOOTSTRAP_TIMEOUT_SECS="5")
    assert r.returncode == 1 and "403" in r.stderr
