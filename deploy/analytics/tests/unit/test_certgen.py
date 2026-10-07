import os
import shutil
import subprocess

import pytest

from conftest import ANALYTICS

SCRIPT = ANALYTICS / "scripts" / "certgen.sh"

pytestmark = pytest.mark.skipif(not shutil.which("openssl"), reason="openssl not available")


def run(out, **env):
    e = {"PATH": os.environ["PATH"], "OUT_DIR": str(out), **env}
    return subprocess.run(["sh", str(SCRIPT)], env=e, capture_output=True, text=True, check=True)


def cert_text(path):
    return subprocess.run(
        ["openssl", "x509", "-in", str(path), "-noout", "-text"],
        capture_output=True, text=True, check=True,
    ).stdout


def test_generates_ca_and_server_cert_with_sans(tmp_path):
    run(tmp_path)
    assert (tmp_path / "ca.pem").exists() and (tmp_path / "server.pem").exists()
    text = cert_text(tmp_path / "server.pem")
    for san in ("DNS:trino", "DNS:localhost", "IP Address:127.0.0.1"):
        assert san in text
    subprocess.run(
        ["openssl", "verify", "-CAfile", str(tmp_path / "ca.pem"), str(tmp_path / "server.pem")],
        check=True, capture_output=True,
    )


def test_ca_private_key_is_not_kept(tmp_path):
    run(tmp_path)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["ca.pem", "server.pem"]


def test_server_pem_has_pkcs8_key_and_is_private(tmp_path):
    run(tmp_path)
    pem = (tmp_path / "server.pem").read_text()
    assert "BEGIN CERTIFICATE" in pem and "BEGIN PRIVATE KEY" in pem
    assert "BEGIN RSA PRIVATE KEY" not in pem
    assert (tmp_path / "server.pem").stat().st_mode & 0o777 == 0o600
    assert (tmp_path / "ca.pem").stat().st_mode & 0o777 == 0o644


def test_idempotent_keeps_valid_cert(tmp_path):
    run(tmp_path)
    before = (tmp_path / "server.pem").read_bytes(), (tmp_path / "ca.pem").read_bytes()
    out = run(tmp_path).stdout
    assert "keeping" in out
    assert before == ((tmp_path / "server.pem").read_bytes(), (tmp_path / "ca.pem").read_bytes())


def test_regenerates_when_expiring_within_30_days(tmp_path):
    run(tmp_path, TLS_DAYS="1")
    before = (tmp_path / "server.pem").read_bytes()
    run(tmp_path)
    assert (tmp_path / "server.pem").read_bytes() != before


def test_extra_sans_are_honoured(tmp_path):
    run(tmp_path, TLS_SANS="DNS:trino.example.com,IP:10.1.2.3")
    text = cert_text(tmp_path / "server.pem")
    assert "DNS:trino.example.com" in text and "IP Address:10.1.2.3" in text


def test_missing_openssl_fails_loudly(tmp_path):
    # PATH with sh but no openssl: must exit non-zero, never silently succeed.
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "sh").symlink_to(shutil.which("sh"))
    out = tmp_path / "out"
    r = subprocess.run(
        [str(bindir / "sh"), str(SCRIPT)],
        env={"PATH": str(bindir), "OUT_DIR": str(out)}, capture_output=True, text=True,
    )
    assert r.returncode != 0
    assert "openssl" in r.stderr
    assert not (out / "server.pem").exists()


def test_failure_mid_generation_leaves_previous_files_and_no_ca_key(tmp_path):
    out = tmp_path / "out"
    run(out, TLS_DAYS="1")  # expiring: the next run regenerates
    before = {n: (out / n).read_bytes() for n in ("ca.pem", "server.pem")}
    bindir = tmp_path / "bin"
    bindir.mkdir()
    real = shutil.which("openssl")
    shim = bindir / "openssl"
    shim.write_text(f'#!/bin/sh\n[ "$1" = x509 ] && [ "$2" = -req ] && exit 1\nexec {real} "$@"\n')
    shim.chmod(0o755)
    e = {"PATH": f"{bindir}:{os.environ['PATH']}", "OUT_DIR": str(out)}
    r = subprocess.run(["sh", str(SCRIPT)], env=e, capture_output=True, text=True)
    assert r.returncode != 0
    assert {n: (out / n).read_bytes() for n in ("ca.pem", "server.pem")} == before
    assert sorted(p.name for p in out.iterdir()) == ["ca.pem", "server.pem"]


def test_ca_and_chain_pass_strict_verification(tmp_path):
    # Python 3.13's default context (VERIFY_X509_STRICT) rejects a CA without keyUsage.
    run(tmp_path)
    text = cert_text(tmp_path / "ca.pem")
    assert "CA:TRUE" in text and "Certificate Sign" in text
    subprocess.run(
        ["openssl", "verify", "-x509_strict", "-CAfile", str(tmp_path / "ca.pem"),
         str(tmp_path / "server.pem")], check=True, capture_output=True)
