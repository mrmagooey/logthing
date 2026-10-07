"""bootstrap.py against real Garage, Postgres and Lakekeeper (Docker required)."""
import re
import subprocess
import sys
import time

import pytest

from conftest import BOOTSTRAP
from stack import COMPOSE_ENV, Stack, require_docker

pytestmark = pytest.mark.integration
require_docker()


@pytest.fixture(scope="module")
def stack(tmp_path_factory):
    s = Stack(tmp_path_factory.mktemp("it"))
    s.garage_admin = s.lakekeeper = None
    try:
        s.up("postgres", "garage", "lakekeeper", timeout=600)
        s.garage_admin = f"http://127.0.0.1:{s.port('garage', 3903)}"
        s.lakekeeper = f"http://127.0.0.1:{s.port('lakekeeper', 8181)}"
        yield s
    finally:
        s.down()


def run(stack, *cmd, timeout=200, **env_extra):
    env = dict(COMPOSE_ENV)
    env.update(GARAGE_ADMIN_URL=stack.garage_admin,
               GARAGE_ADMIN_TOKEN=stack.env["GARAGE_ADMIN_TOKEN"],
               LAKEKEEPER_URL=stack.lakekeeper,
               S3_ACCESS_KEY=stack.env["S3_ACCESS_KEY"], S3_SECRET_KEY=stack.env["S3_SECRET_KEY"],
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
    ak, sk = stack.env["S3_ACCESS_KEY"], stack.env["S3_SECRET_KEY"]
    script = (
        "import boto3;c=boto3.client('s3',endpoint_url='http://garage:3900',"
        f"aws_access_key_id='{ak}',aws_secret_access_key='{sk}',region_name='garage');"
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


def test_generated_garage_key_format_is_accepted(bootstrapped):
    # ImportKey in provision() would have failed (HTTP 400) on a malformed id/secret.
    assert re.fullmatch(r"GK[0-9a-f]{24}", bootstrapped.env["S3_ACCESS_KEY"])
    assert re.fullmatch(r"[0-9a-f]{64}", bootstrapped.env["S3_SECRET_KEY"])


def test_wrong_admin_token_fails_fast(stack):
    t0 = time.monotonic()
    r = run(stack, "garage", GARAGE_ADMIN_TOKEN="wrong", BOOTSTRAP_TIMEOUT_SECS="5", timeout=60)
    assert r.returncode == 1 and "403" in r.stderr
    assert time.monotonic() - t0 < 15
