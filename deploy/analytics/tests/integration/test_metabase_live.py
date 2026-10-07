"""Metabase provisioning against real Postgres + Trino (HTTPS) + Metabase (Docker required)."""
import pytest

from conftest import load_metabase_query
from stack import Stack, require_docker, require_trino

pytestmark = pytest.mark.integration
require_docker()
require_trino()


@pytest.fixture(scope="module")
def mb(tmp_path_factory):
    s = Stack(tmp_path_factory.mktemp("mb"))
    try:
        s.up("metabase", "trino", timeout=1500)
        s.base = f"http://127.0.0.1:{s.port('metabase', 3000)}"
        yield s
    finally:
        s.down()


def init(s, **env):
    args = ["run", "--rm", "--no-deps"]
    for k, v in env.items():
        args += ["-e", f"{k}={v}"]
    return s.compose(*args, "metabase-init", check=False, capture=True, timeout=900)


def query(s, sql):
    return load_metabase_query().run(
        s.base, "admin@logthing.example", s.env["METABASE_ADMIN_PASSWORD"], sql, deadline_secs=180)


def test_init_creates_admin_and_trino_database(mb):
    r = init(mb)
    assert r.returncode == 0, r.stdout + r.stderr
    assert query(mb, "SELECT 1") == 1


def test_query_runs_as_the_metabase_trino_user_over_the_generated_ca(mb):
    assert query(mb, "SELECT current_user") == "metabase"


def test_metabase_container_has_only_the_ca_not_the_server_key(mb):
    out = mb.exec("metabase", "ls", "/tls").stdout.split()
    assert out == ["ca.pem"]


def test_init_is_idempotent(mb):
    assert init(mb).returncode == 0
    assert init(mb).returncode == 0
    assert query(mb, "SELECT 1") == 1


def test_wrong_admin_password_fails_fast_with_a_named_cause(mb):
    r = init(mb, METABASE_ADMIN_PASSWORD="not-the-password", BOOTSTRAP_TIMEOUT_SECS="30")
    assert r.returncode == 1 and "METABASE_ADMIN_PASSWORD" in r.stderr
