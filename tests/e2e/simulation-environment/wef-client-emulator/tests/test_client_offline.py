import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from stubwec import FakeContext, StubWec, make_pki
from wefemu import envelope as E
from wefemu.client import WefClient, load_events, run_checks

GOLDEN = Path(__file__).resolve().parents[4] / "fixtures" / "wef" / "golden"
CWD = Path(__file__).resolve().parents[1]
ENV = {**os.environ, "PYTHONPATH": str(CWD / "tests") + os.pathsep + str(CWD)}


@pytest.fixture
def events_dir(tmp_path):
    (tmp_path / "golden-events.xml").write_text((GOLDEN / "events.xml").read_text(encoding="utf-8"))
    return tmp_path


def kclient(stub, compress=True, **kw):
    return WefClient("kerberos-http", stub.url, "win10.example.com", compress=compress,
                     context_factory=lambda host: FakeContext(), **kw)


def test_load_events_from_golden_envelope(events_dir):
    evs = load_events(events_dir)
    assert len(evs) == 2 and all(e.startswith("<Event ") for e in evs)


def test_load_events_plain_event_file(tmp_path):
    (tmp_path / "a.xml").write_text("<Event xmlns='x'><System/></Event>")
    assert load_events(tmp_path) == ["<Event xmlns='x'><System/></Event>"]


def test_load_events_empty_dir_errors(tmp_path):
    with pytest.raises(ValueError):
        load_events(tmp_path)


def test_kerberos_full_flow(events_dir):
    with StubWec() as stub:
        s = kclient(stub).run_flow(events_dir, batches=3, batch_size=5)
        log = stub.log
    assert s["ok"] and s["events_sent"] == 15 and s["batches"] == 3
    assert s["acks"] == 4  # heartbeat + 3 event batches
    assert s["subscription_version"] == "uuid:219C5353-0000-4000-8000-000000000001"
    actions = [r["action"] for r in log]
    short = [a.rsplit("/", 1)[-1] for a in actions]
    assert short == ["AUTH", "Enumerate", "End", "AUTH", "Heartbeat", "Events", "Events", "Events",
                     "AUTH", "Enumerate", "End", "SubscriptionEnd", "End"]
    # enumeration and delivery use separate TCP connections
    conns = [r["conn"] for r in log]
    assert conns[0] == conns[1] == conns[2]
    assert conns[3] not in (conns[0],) and len(set(conns[3:8])) == 1
    assert conns[8] not in (conns[0], conns[3])
    assert conns[11] == conns[12] == conns[3]
    # auth only on the first POST of each connection; empty body
    assert [bool(r["auth"]) for r in log] == [True, False, False, True, False, False, False, False,
                                              True, False, False, False, False]
    assert all(r["auth"].startswith("Kerberos ") for r in log if r["auth"])
    assert log[0]["raw_len"] == 0 and log[0]["cenc"] == "SLDC"
    # delivery path is the NotifyTo path, with lowercase scheme normalization handled
    assert log[4]["path"].startswith("/wsman/subscriptions/")


def test_kerberos_flow_sends_expected_headers_and_bookmarks(events_dir):
    with StubWec() as stub:
        kclient(stub).run_flow(events_dir, batches=3, batch_size=2)
        ev = [r for r in stub.log if r["action"] == E.ACTION_EVENTS]
        enum2 = [r for r in stub.log if r["action"] == E.ACTION_ENUMERATE][1]
    ids = [int(E.bookmark_entries(r["msg"].bookmark)[0][1]) for r in ev]
    assert ids == sorted(set(ids)) and len(ids) == 3
    assert all(r["msg"].ack_requested and r["msg"].identifier for r in ev)
    assert all(r["ctype"] == 'multipart/encrypted;protocol="application/HTTP-Kerberos-session-encrypted";boundary="Encrypted Boundary"' for r in ev)
    assert all(r["cenc"] == "SLDC" for r in ev)
    assert enum2["msg"].machine_id == "win10.example.com"
    assert any(r["compressed"] for r in ev)


def test_flow_no_compress_omits_sldc(events_dir):
    with StubWec() as stub:
        kclient(stub, compress=False).run_flow(events_dir, batches=1, batch_size=2)
        assert all(r["cenc"] is None for r in stub.log)


def test_flow_detects_missing_bookmark_replay(events_dir):
    with StubWec() as stub:
        stub.version = "uuid:219C5353-0000-4000-8000-000000000001"
        orig = stub._post

        def forget(h, body):
            stub.bookmark = None
            return orig(h, body)

        stub._post = forget
        with pytest.raises(E.ValidationError, match="bookmark"):
            kclient(stub).run_flow(events_dir, batches=2, batch_size=1)


FAULTS = [
    "bad_action", "bad_relates", "lower_mid", "no_eos",
    "ack_bad_action", "ack_bad_relates", "ack_lower_mid", "ack_body", "ack_no_bom", "ack_decl",
    "mp_tab", "mp_charset", "mp_length", "ct_spnego",
    "end_204", "end_body", "auth_401", "auth_no_www", "auth_body",
]


@pytest.mark.parametrize("fault", FAULTS)
def test_kerberos_flow_fails_on_each_server_fault(events_dir, fault):
    with StubWec(faults=[fault]) as stub:
        with pytest.raises(E.ValidationError):
            kclient(stub).run_flow(events_dir, batches=1, batch_size=1)


def test_cli_summary_line_and_exit_code(events_dir):
    with StubWec(faults=["ack_body"]) as stub:
        r = subprocess.run(
            [sys.executable, "-m", "wefemu", "flow", "--mode", "kerberos-http", "--server", stub.url,
             "--machine-id", "win10.example.com", "--events-dir", str(events_dir), "--context-factory", "stubwec:fake_factory"],
            cwd=CWD, capture_output=True, text=True, env=ENV)
    assert r.returncode != 0
    assert json.loads(r.stdout.strip().splitlines()[-1])["ok"] is False


def test_cli_success(events_dir):
    with StubWec() as stub:
        r = subprocess.run(
            [sys.executable, "-m", "wefemu", "flow", "--mode", "kerberos-http", "--server", stub.url,
             "--machine-id", "win10.example.com", "--events-dir", str(events_dir), "--batches", "2",
             "--batch-size", "3", "--context-factory", "stubwec:fake_factory"],
            cwd=CWD, capture_output=True, text=True, env=ENV)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout.strip().splitlines()[-1])
    assert out["ok"] and out["events_sent"] == 6


@pytest.mark.parametrize("fault", [None, "ack_body", "ct_utf8", "ack_no_bom", "end_body"])
def test_https_mtls_flow(events_dir, tmp_path, fault):
    pki = make_pki(tmp_path)
    with StubWec(mode="https-mtls", tls=pki, faults=[fault] if fault else []) as stub:
        c = WefClient("https-mtls", stub.url, "win10.example.com", ca=pki["ca"],
                      cert=pki["client_cert"], key=pki["client_key"])
        if fault:
            with pytest.raises(E.ValidationError):
                c.run_flow(events_dir, batches=1, batch_size=1)
        else:
            s = c.run_flow(events_dir, batches=2, batch_size=2)
            assert s["ok"] and s["events_sent"] == 4 and s["acks"] == 3
            assert all(r["auth"] is None for r in stub.log)


def test_https_mtls_rejects_http_notify(events_dir, tmp_path):
    pki = make_pki(tmp_path)
    with StubWec(mode="https-mtls", tls=pki) as stub:
        stub.mode = "https-mtls"
        orig = stub._reply

        def swap(h, xml, bom=True):
            return orig(h, xml.replace("HTTPS://", "HTTP://"), bom)

        stub._reply = swap
        c = WefClient("https-mtls", stub.url, "win10.example.com", ca=pki["ca"],
                      cert=pki["client_cert"], key=pki["client_key"])
        with pytest.raises(E.ValidationError, match="https"):
            c.run_flow(events_dir, batches=1, batch_size=1)


def test_invalid_mode():
    with pytest.raises(ValueError):
        WefClient("bogus", "http://x", "m")


def test_checks_health_only_without_kerberos():
    with StubWec() as stub:
        res = run_checks(stub.origin, kerberos=False)
    assert res["ok"] and [c["name"] for c in res["checks"]] == ["health"]


def test_checks_kerberos_negative_checks_pass_against_conforming_stub():
    with StubWec() as stub:
        res = run_checks(stub.origin, kerberos=True, positive=False)
    assert res["ok"], res
    assert {c["name"] for c in res["checks"]} == {
        "health", "wsman-no-auth-401-both-challenges", "syslog-no-auth-401", "wsman-bogus-token-401"}


def test_checks_fail_when_server_accepts_unauthenticated():
    with StubWec(mode="https-mtls") as stub:  # stub that does not demand auth
        res = run_checks(stub.origin, kerberos=True, positive=False)
    assert not res["ok"]


def test_checks_positive_negotiate_uses_context_factory():
    seen = {}

    class Ctx:
        complete = False

        def step(self, tok=None):
            seen.setdefault("steps", []).append(tok)
            return b"NEGOTIATE-TOKEN" if tok is None else None

    with StubWec() as stub:
        res = run_checks(stub.origin, kerberos=True, positive=True,
                         context_factory=lambda host: Ctx())
    # the stub rejects the Negotiate token, so the positive check must report a failure
    pos = [c for c in res["checks"] if c["name"] == "syslog-negotiate-2xx"]
    assert pos and pos[0]["ok"] is False and seen["steps"][0] is None


def test_checks_positive_negotiate_posts_a_raw_syslog_line_not_json():
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    seen = {}

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            if self.path == "/syslog" and self.headers.get("Authorization"):
                seen["body"] = body.decode()
                seen["ctype"] = self.headers.get("Content-Type")
                self.send_response(200)
            else:
                self.send_response(401)
                self.send_header("WWW-Authenticate", "Kerberos")
                self.send_header("WWW-Authenticate", "Negotiate")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    class Ctx:
        def step(self, tok=None):
            return b"T"

    httpd = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        res = run_checks(f"http://127.0.0.1:{httpd.server_port}", kerberos=True, positive=True,
                         context_factory=lambda host: Ctx())
    finally:
        httpd.shutdown()
        httpd.server_close()
    pos = [c for c in res["checks"] if c["name"] == "syslog-negotiate-2xx"]
    assert pos and pos[0]["ok"] is True
    assert seen["body"].startswith("<134>") and seen["ctype"] == "text/plain"


def test_load_events_skips_a_fixture_that_is_not_well_formed_xml(tmp_path):
    good = "<Event><System><EventID>1</EventID></System></Event>"
    (tmp_path / "a_good.xml").write_text(good, encoding="utf-8")
    (tmp_path / "b_illegal.xml").write_text("<Event>\x04</Event>", encoding="utf-8")
    assert load_events(tmp_path) == [good]
