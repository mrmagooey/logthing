"""Trino over HTTPS with password auth against the real compose services (Docker required)."""
import base64
import http.client
import ssl
import urllib.error
import urllib.request

import pytest

from stack import Stack, require_docker, require_trino

pytestmark = pytest.mark.integration
require_docker()
require_trino()


@pytest.fixture(scope="module")
def trino(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("tls")
    s = Stack(tmp)
    try:
        s.up("trino", timeout=900)
        s.https_port = s.port("trino", 8443)
        s.ca = tmp / "ca.pem"
        s.ca.write_text(s.exec("trino", "cat", "/etc/trino/tls/ca.pem").stdout)
        yield s
    finally:
        s.down()


def post(trino, user, password, cafile=True):
    ctx = ssl.create_default_context(cafile=str(trino.ca) if cafile else None)
    req = urllib.request.Request(
        f"https://127.0.0.1:{trino.https_port}/v1/statement", data=b"select 1", method="POST",
        headers={"X-Trino-User": user})
    if password is not None:
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        req.add_header("Authorization", f"Basic {token}")
    try:
        return urllib.request.urlopen(req, context=ctx, timeout=60).status
    except urllib.error.HTTPError as e:
        return e.code


def test_unauthenticated_request_is_401(trino):
    assert post(trino, "admin", None) == 401


def test_wrong_password_is_401(trino):
    assert post(trino, "admin", "not-the-password") == 401


@pytest.mark.parametrize("user,var", [("admin", "TRINO_ADMIN_PASSWORD"),
                                      ("metabase", "TRINO_METABASE_PASSWORD")])
def test_both_users_authenticate(trino, user, var):
    assert post(trino, user, trino.env[var]) == 200


def test_unknown_user_is_401(trino):
    assert post(trino, "mallory", trino.env["TRINO_ADMIN_PASSWORD"]) == 401


def test_client_without_the_ca_refuses_the_server(trino):
    with pytest.raises(urllib.error.URLError) as exc:
        post(trino, "admin", trino.env["TRINO_ADMIN_PASSWORD"], cafile=False)
    assert isinstance(exc.value.reason, ssl.SSLCertVerificationError)


def test_plain_http_to_the_tls_port_returns_no_data(trino):
    try:
        status = urllib.request.urlopen(
            f"http://127.0.0.1:{trino.https_port}/v1/info", timeout=10).status
    except (urllib.error.URLError, http.client.HTTPException, OSError):
        return  # connection reset / bad status line: nothing served over plain HTTP
    assert status != 200


def test_plain_http_port_is_not_published(trino):
    r = trino.compose("port", "trino", "8080", check=False, capture=True)
    # compose prints "invalid IP:0" (exit 0) for a port that is not published
    assert r.returncode != 0 or r.stdout.strip().rsplit(":", 1)[-1] in ("", "0")


def test_cli_works_over_the_generated_ca(trino):
    out = trino.exec("trino", "trino", "--server", "https://localhost:8443",
                     "--truststore-path", "/etc/trino/tls/ca.pem", "--user", "admin",
                     "--password", "--execute", "SELECT 1").stdout
    assert out.strip() == '"1"'


def test_cli_with_a_wrong_password_fails(trino):
    r = trino.compose("exec", "-T", "-e", "TRINO_PASSWORD=wrong", "trino", "trino",
                      "--server", "https://localhost:8443", "--truststore-path",
                      "/etc/trino/tls/ca.pem", "--user", "admin", "--password",
                      "--execute", "SELECT 1", check=False, capture=True)
    assert r.returncode != 0


def test_certgen_rerun_keeps_the_ca_clients_already_trust(trino):
    trino.compose("run", "--rm", "--no-deps", "certgen", capture=True)
    again = trino.exec("trino", "cat", "/etc/trino/tls/ca.pem").stdout
    assert again == trino.ca.read_text()
