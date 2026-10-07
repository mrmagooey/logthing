import os
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from conftest import ANALYTICS

LIB = ANALYTICS / "tests" / "e2e" / "lib.sh"
CERTGEN = ANALYTICS / "scripts" / "certgen.sh"


def preflight(tmp_path, flags, **env):
    cpu = tmp_path / "cpuinfo"
    cpu.write_text(f"processor\t: 0\nflags\t\t: {flags}\n")
    e = {"PATH": os.environ["PATH"], "CPUINFO": str(cpu), **env}
    return subprocess.run(["bash", "-c", f". {LIB}; preflight_cpu"], env=e,
                          capture_output=True, text=True)


def test_preflight_passes_with_avx2(tmp_path):
    assert preflight(tmp_path, "fpu sse2 avx avx2 bmi2").returncode == 0


def test_preflight_refuses_without_avx2_and_without_override(tmp_path):
    r = preflight(tmp_path, "fpu sse2 avx")
    assert r.returncode == 1 and "TRINO_IMAGE" in r.stderr


def test_preflight_accepts_trino_override_alone(tmp_path):
    r = preflight(tmp_path, "fpu sse2", TRINO_IMAGE="trinodb/trino:470")
    assert r.returncode == 0
    assert "does NOT verify the default Trino image" in r.stderr


def test_preflight_no_longer_mentions_hue():
    assert "HUE" not in LIB.read_text() and "Hue" not in LIB.read_text()


def test_e2e_scripts_parse_and_share_one_security_helper():
    for name in ("lib.sh", "compose.sh", "helm-minikube.sh"):
        subprocess.run(["bash", "-n", str(ANALYTICS / "tests" / "e2e" / name)], check=True)
    for name in ("compose.sh", "helm-minikube.sh"):
        text = (ANALYTICS / "tests" / "e2e" / name).read_text()
        assert "trino_security_checks" in text, name
        assert "wrong-password" not in text, f"{name} must not duplicate the helper's checks"
        assert "Hue" not in text and "HUE" not in text, name
    assert not (ANALYTICS / "tests" / "e2e" / "hue_query.py").exists()


@pytest.fixture
def tls_server(tmp_path):
    """An HTTPS server that mimics Trino's PASSWORD auth: 401 without the right Basic header."""
    import base64
    import shutil
    if not shutil.which("openssl"):
        pytest.skip("openssl not available")
    subprocess.run(["sh", str(CERTGEN)], check=True, capture_output=True,
                   env={"PATH": os.environ["PATH"], "OUT_DIR": str(tmp_path)})
    good = "Basic " + base64.b64encode(b"admin:s3cret").decode()

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            code = 200 if self.headers.get("Authorization") == good else 401
            self.send_response(code)
            self.send_header("Content-Length", "0")
            self.end_headers()

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp_path / "server.pem")
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"https://localhost:{httpd.server_address[1]}", tmp_path / "ca.pem"
    httpd.shutdown()
    httpd.server_close()


def run_checks(url, ca, password):
    return subprocess.run(
        ["bash", "-c", f". {LIB}; trino_security_checks {url} {ca} {password}"],
        env={"PATH": os.environ["PATH"]}, capture_output=True, text=True)


def test_security_helper_passes_against_a_correct_server(tls_server):
    url, ca = tls_server
    r = run_checks(url, ca, "s3cret")
    assert r.returncode == 0, r.stderr
    assert "trino security: ok" in r.stdout


def test_security_helper_fails_when_the_admin_password_is_rejected(tls_server):
    url, ca = tls_server
    r = run_checks(url, ca, "not-the-password")
    assert r.returncode != 0 and "valid credentials" in r.stderr
