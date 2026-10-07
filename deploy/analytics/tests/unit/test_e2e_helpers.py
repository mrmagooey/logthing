import json
import os
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from conftest import ANALYTICS, load_metabase_query

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


def dbt_ok(code, output):
    return subprocess.run(["bash", "-c", f'. {LIB}; dbt_ok "$1" "$2"', "x", str(code), output],
                          capture_output=True).returncode == 0


def test_dbt_ok_requires_exit_zero_and_a_summary_with_error_zero():
    done = "Done. PASS=12 WARN=0 ERROR=0 SKIP=0 NO-OP=0 TOTAL=12"
    assert dbt_ok(0, f"noise\n12:00:00  {done}\n")
    assert not dbt_ok(1, done)
    assert not dbt_ok(0, "Done. PASS=11 WARN=0 ERROR=1 SKIP=0 NO-OP=0 TOTAL=12")
    assert not dbt_ok(0, "")  # exit 0 without a summary is not a pass


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
    compose = (ANALYTICS / "tests" / "e2e" / "compose.sh").read_text()
    assert "send_app_logs.py" in compose and "assert_app_log_rows" in compose
    assert "assert_staging_dedup" in compose and "build_local_images" in compose


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




def mb_routes(server, engines=("starburst",), dataset=None):
    server.routes[("GET", "/api/session/properties")] = lambda q, b: (
        200, {"engines": {e: {} for e in engines}})
    server.routes[("POST", "/api/session")] = lambda q, b: (
        (200, {"id": "s1"}) if b["password"] == "pw" else (401, {"message": "bad"}))
    server.routes[("GET", "/api/database")] = lambda q, b: (
        200, {"data": [{"id": 1, "engine": "postgres"}, {"id": 7, "engine": "starburst"}]})
    server.routes[("POST", "/api/dataset")] = dataset or (
        lambda q, b: (202, {"status": "completed", "data": {"rows": [[b["database"]]]}}))


def test_metabase_query_uses_the_starburst_database(server):
    mb_routes(server)
    assert load_metabase_query().run(server.url, "a@b.c", "pw", "select 1") == 7
    assert any(c[1] == "/api/dataset" and c[2]["native"]["query"] == "select 1"
               for c in server.calls)


def test_metabase_query_requires_the_starburst_driver(server):
    mb_routes(server, engines=("postgres",))
    with pytest.raises(RuntimeError, match="starburst"):
        load_metabase_query().run(server.url, "a@b.c", "pw", "select 1")


def test_metabase_query_login_failure_is_reported(server):
    mb_routes(server)
    with pytest.raises(RuntimeError, match="login failed"):
        load_metabase_query().run(server.url, "a@b.c", "wrong", "select 1")


def test_metabase_query_retries_failures_then_times_out_with_the_error(server, monkeypatch):
    mb_routes(server, dataset=lambda q, b: (202, {"status": "failed", "error": "trino starting"}))
    mod = load_metabase_query()
    monkeypatch.setattr(mod.time, "sleep", lambda s: None)
    with pytest.raises(TimeoutError, match="trino starting"):
        mod.run(server.url, "a@b.c", "pw", "select 1", deadline_secs=0)


PORTS = ANALYTICS / "tests" / "e2e" / "published_ports.py"


def ports_run(text):
    return subprocess.run(["python3", str(PORTS)], input=text, capture_output=True, text=True)


def _row(service, target, published=None):
    return {"Service": service, "Publishers": [{"TargetPort": target, "PublishedPort": published}]}


OK_ROWS = [_row("garage", 3900, 3900), _row("lakekeeper", 8181, 0), _row("postgres", 5432, 0),
           _row("metabase", 3000, 3000)]


def test_published_ports_accepts_ndjson_and_a_json_array():
    assert ports_run("\n".join(json.dumps(r) for r in OK_ROWS)).returncode == 0
    assert ports_run(json.dumps(OK_ROWS)).returncode == 0


def test_published_ports_rejects_an_empty_listing_in_either_format():
    for text in ("", "[]", "\n"):
        r = ports_run(text)
        assert r.returncode != 0 and "vacuous" in r.stderr, text


def test_published_ports_flags_internal_ports_in_either_format():
    bad = OK_ROWS + [_row("lakekeeper", 8181, 18181)]
    for text in (json.dumps(bad), "\n".join(json.dumps(r) for r in bad)):
        r = ports_run(text)
        assert r.returncode != 0 and "lakekeeper" in r.stderr
    assert ports_run(json.dumps(OK_ROWS + [_row("trino", 8080, 8080)])).returncode != 0


def test_e2e_scripts_run_dbt_build_and_check_the_summary():
    for name in ("compose.sh", "helm-minikube.sh"):
        text = (ANALYTICS / "tests" / "e2e" / name).read_text()
        assert "dbt_ok" in text and " build " in text + " ", name


def test_e2e_scripts_include_the_metabase_step_and_no_hue():
    for name, marker in (("compose.sh", "[6/8]"), ("helm-minikube.sh", "[9/9]")):
        text = (ANALYTICS / "tests" / "e2e" / name).read_text()
        assert marker in text and "metabase_query.py" in text, name
    assert "published_ports.py" in (ANALYTICS / "tests" / "e2e" / "compose.sh").read_text()
    helm = (ANALYTICS / "tests" / "e2e" / "helm-minikube.sh").read_text()
    assert "$FULL-trino-tls" in helm and "metabase-init" in helm


def test_e2e_scripts_send_zeek_and_execute_every_compiled_analysis():
    for name in ("compose.sh", "helm-minikube.sh"):
        text = (ANALYTICS / "tests" / "e2e" / name).read_text()
        for needle in ('"_path": "conn"', '"_path": "dns"', "ocsf_network_activity",
                       "ocsf_dns_activity", "compiled/logthing_analytics/analyses",
                       '[ "$analyses" = 3 ]', "connection_info_protocol_num = 6"):
            assert needle in text, (name, needle)


SENDER = ANALYTICS / "tests" / "e2e" / "send_app_logs.py"


def load_sender():
    import importlib.util
    spec = importlib.util.spec_from_file_location("send_app_logs", SENDER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_otlp_payload_is_gzippable_json_with_integer_severity_and_marker():
    m = load_sender()
    body = json.loads(m.otlp_payload("MK", 3, 1_700_000_000_000_000_000))
    recs = body["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
    assert [r["body"]["stringValue"] for r in recs] == ["MK otlp 0", "MK otlp 1", "MK otlp 2"]
    assert all(r["severityNumber"] == 9 and isinstance(r["severityNumber"], int) for r in recs)
    attrs = {a["key"]: a["value"]["stringValue"]
             for a in body["resourceLogs"][0]["resource"]["attributes"]}
    assert attrs["service.name"] == "e2e-app"


def test_hec_event_envelope_carries_source_index_and_indexed_fields():
    m = load_sender()
    e = json.loads(m.hec_event("MK", 7, 1_700_000_000))
    assert e["sourcetype"] == "e2e:app" and e["source"] == "e2e" and e["index"] == "main"
    assert e["fields"] == {"env": "e2e"} and e["event"]["message"] == "MK hec 7"


class _Recorder(BaseHTTPRequestHandler):
    seen = []

    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(n)
        auth = self.headers.get("Authorization", "")
        good = auth in ("Splunk hec-ok", "Bearer otlp-ok")
        _Recorder.seen.append((self.path, auth, self.headers.get("Content-Encoding")))
        self.send_response(200 if good else 401)
        self.send_header("Content-Length", "0")
        self.end_headers()


def test_sender_sends_gzip_with_tokens_and_checks_negatives(monkeypatch):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Recorder)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        monkeypatch.setenv("HEC_TOKEN", "hec-ok")
        monkeypatch.setenv("OTLP_BEARER_TOKEN", "otlp-ok")
        m = load_sender()
        _Recorder.seen.clear()
        assert m.main([f"http://127.0.0.1:{srv.server_address[1]}", "MK", "3"]) == 0
    finally:
        srv.shutdown()
    good = [s for s in _Recorder.seen if s[1] in ("Splunk hec-ok", "Bearer otlp-ok")]
    assert sum(1 for p, _, _ in good if p == "/v1/logs") == 1
    assert sum(1 for p, _, _ in good if p == "/services/collector/event") == 3
    assert all(enc == "gzip" for _, _, enc in good)
    bad = [s for s in _Recorder.seen if s not in good]
    assert {p for p, _, _ in bad} == {"/v1/logs", "/services/collector/event"}  # no/wrong token


def test_sender_fails_when_a_missing_token_is_accepted(monkeypatch):
    class Open(_Recorder):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Open)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        monkeypatch.setenv("HEC_TOKEN", "x")
        monkeypatch.setenv("OTLP_BEARER_TOKEN", "y")
        assert load_sender().main([f"http://127.0.0.1:{srv.server_address[1]}", "MK", "1"]) == 1
    finally:
        srv.shutdown()


def run_lib(snippet, **env):
    return subprocess.run(["bash", "-c", f". {LIB}; {snippet}"], capture_output=True, text=True,
                          env={"PATH": os.environ["PATH"], **env})


def _fake_sql(otlp_count):
    # `sql` fake answers by substring, most specific arm first (typeof, then count(distinct),
    # then the plain count), so the helper's exact assertions are pinned.
    return rf'''
    N=5; MARKER=MK
    fail() {{ echo "FAIL: $*" >&2; return 1; }}
    sql() {{ case "$1" in
      *'$."'*) echo "Invalid JSON path (Trino rejects \$.\"key\")" >&2; return 1;;
      *typeof*) echo "integer/timestamp(6) with time zone";;
      *"count(distinct event_uuid) FROM iceberg.logs.otlp"*) echo {otlp_count};;
      *"count(distinct event_uuid) FROM iceberg.logs.hec"*) echo 5;;
      *"FROM iceberg.logs.otlp"*) echo {otlp_count};;
      *"FROM iceberg.logs.hec"*) echo 5;;
      *) echo 0;; esac; }}
    assert_app_log_rows
    '''


def test_assert_app_log_rows_checks_otlp_hec_typed_counts_and_uuids():
    r = run_lib(_fake_sql(5))
    assert r.returncode == 0, r.stderr
    r = run_lib(_fake_sql(4))
    assert r.returncode != 0 and "otlp" in r.stderr


def test_assert_app_log_rows_rejects_wrong_column_types():
    r = run_lib(_fake_sql(5).replace("integer/timestamp(6) with time zone", "bigint/timestamp(3)"))
    assert r.returncode != 0 and "types" in r.stderr


def test_build_local_images_honours_overrides_without_docker():
    r = run_lib('build_local_images; echo "$LOGTHING_IMAGE $COMMITTER_IMAGE"',
                LOGTHING_IMAGE="l:1", COMMITTER_IMAGE="c:1")
    assert r.returncode == 0 and r.stdout.split() == ["l:1", "c:1"]


def test_build_local_images_tag_changes_with_dirty_tree_content(tmp_path):
    repo = tmp_path / "repo"
    (repo / "deploy" / "analytics").mkdir(parents=True)
    (repo / "committer").mkdir()
    (repo / "f.txt").write_text("a")
    g = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t"]
    subprocess.run([*g[:3], "init", "-q"], check=True)
    subprocess.run([*g, "add", "."], check=True)
    subprocess.run([*g, "commit", "-qm", "x"], check=True)
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "docker").write_text("#!/bin/sh\necho \"$@\" >>\"$DOCKER_LOG\"\n")
    (bindir / "docker").chmod(0o755)

    def tag():
        log = tmp_path / "docker.log"
        log.write_text("")
        r = subprocess.run(
            ["bash", "-c", f'. {LIB}; ANALYTICS={repo}/deploy/analytics; build_local_images; '
             'echo "$LOGTHING_IMAGE"'],
            capture_output=True, text=True,
            env={"PATH": f"{bindir}:{os.environ['PATH']}", "DOCKER_LOG": str(log)})
        assert r.returncode == 0, r.stderr
        assert str(repo / "committer") in log.read_text()
        return r.stdout.strip()

    clean = tag()
    assert "dirty" not in clean and tag() == clean
    (repo / "f.txt").write_text("b")
    d1 = tag()
    assert "dirty" in d1 and d1 != clean and tag() == d1
    (repo / "f.txt").write_text("c")
    assert tag() != d1
    (repo / "new.txt").write_text("untracked")
    assert tag() != d1
