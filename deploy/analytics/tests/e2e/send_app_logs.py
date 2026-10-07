#!/usr/bin/env python3
"""Send OTLP/JSON (gzip) log records and HEC events (gzip) to logthing's HTTP port.

Usage: HEC_TOKEN=.. OTLP_BEARER_TOKEN=.. send_app_logs.py <base_url> <marker> <n>

Sends ONE OTLP request carrying <n> records and <n> single-event HEC requests, then checks that
both endpoints reject a missing and a wrong token with 401. Stdlib only, so it runs unchanged on
the host (compose) and inside a python:3.12-slim pod (Helm). Exit 0 only if every check holds.
Tokens are read from the environment and never printed.
"""
import gzip
import json
import os
import sys
import time
import urllib.error
import urllib.request


def post(url, body, headers):
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def otlp_payload(marker, n, now_ns):
    records = [{
        "timeUnixNano": str(now_ns + i), "severityNumber": 9, "severityText": "INFO",
        "body": {"stringValue": f"{marker} otlp {i}"},
        "attributes": [{"key": "http.route", "value": {"stringValue": "/e2e"}}],
    } for i in range(n)]
    return json.dumps({"resourceLogs": [{
        "resource": {"attributes": [
            {"key": "service.name", "value": {"stringValue": "e2e-app"}},
            {"key": "host.name", "value": {"stringValue": "e2ehost"}}]},
        "scopeLogs": [{"scope": {"name": "e2e", "version": "1"}, "logRecords": records}],
    }]}).encode()


def hec_event(marker, i, now_s):
    return json.dumps({
        "time": now_s, "host": "e2ehost", "source": "e2e", "sourcetype": "e2e:app",
        "index": "main", "event": {"message": f"{marker} hec {i}"}, "fields": {"env": "e2e"},
    }).encode()


def main(argv):
    base, marker, n = argv[0].rstrip("/"), argv[1], int(argv[2])
    hec, otlp = os.environ["HEC_TOKEN"], os.environ["OTLP_BEARER_TOKEN"]
    otlp_url, hec_url = f"{base}/v1/logs", f"{base}/services/collector/event"
    gz = {"Content-Encoding": "gzip", "Content-Type": "application/json"}
    ok = True
    st = post(otlp_url, gzip.compress(otlp_payload(marker, n, time.time_ns())),
              {**gz, "Authorization": f"Bearer {otlp}"})
    if not 200 <= st < 300:
        print(f"FAIL: OTLP send returned {st}", file=sys.stderr)
        ok = False
    for i in range(n):
        st = post(hec_url, gzip.compress(hec_event(marker, i, int(time.time()))),
                  {**gz, "Authorization": f"Splunk {hec}"})
        if not 200 <= st < 300:
            print(f"FAIL: HEC send {i} returned {st}", file=sys.stderr)
            ok = False
    for url, scheme in ((otlp_url, "Bearer"), (hec_url, "Splunk")):
        for hdrs in ({}, {"Authorization": f"{scheme} wrong-token"}):
            st = post(url, gzip.compress(b"{}"), {**gz, **hdrs})
            if st != 401:
                print(f"FAIL: {url} with {'no' if not hdrs else 'a wrong'} token returned "
                      f"{st}, expected 401", file=sys.stderr)
                ok = False
    if ok:
        print(f"sent otlp={n} hec={n} negatives=ok")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
