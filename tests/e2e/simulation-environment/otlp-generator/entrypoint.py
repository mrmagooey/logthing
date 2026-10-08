#!/usr/bin/env python3
"""OTLP/HTTP generator for E2E testing.

Sends gzip-compressed OTLP/JSON log requests to logthing's POST /v1/logs:
- 3 records for service "svc-a" (INFO, with trace/span ids)
- 2 records for service "Svc B" (WARN)  -> partition `svc_b`, raw service_name kept
- 1 record with NO resource at all      -> partition `unknown`, service_name NULL
- 1 request with a wrong bearer token   -> must be rejected with 401
"""

import gzip
import json
import os
import time
import urllib.error
import urllib.request

URL = os.environ.get("LOGTHING_URL", "http://logthing:5985")
TOKEN = os.environ.get("OTLP_TOKEN", "")
CONNECT_TIMEOUT_SECS = int(os.environ.get("CONNECT_TIMEOUT_SECS", "30"))


def wait_for_server():
    deadline = time.time() + CONNECT_TIMEOUT_SECS
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{URL}/health", timeout=2) as r:
                if r.status == 200:
                    return
        except OSError:
            pass
        time.sleep(1)
    raise SystemExit(f"logthing not healthy at {URL} within {CONNECT_TIMEOUT_SECS}s")


def log_record(body, severity_number, severity_text, trace=False):
    rec = {
        "timeUnixNano": str(int(time.time() * 1e9)),
        "severityNumber": severity_number,
        "severityText": severity_text,
        "body": {"stringValue": body},
        "attributes": [{"key": "http.route", "value": {"stringValue": "/sim"}}],
    }
    if trace:
        rec["traceId"] = "0af7651916cd43dd8448eb211c80319c"
        rec["spanId"] = "b7ad6b7169203331"
    return rec


def request(service, records):
    resource = (
        {"attributes": [{"key": "service.name", "value": {"stringValue": service}}]}
        if service is not None
        else None
    )
    rl = {"scopeLogs": [{"scope": {"name": "sim-lib", "version": "1.0"}, "logRecords": records}]}
    if resource is not None:
        rl["resource"] = resource
    return {"resourceLogs": [rl]}


def post(payload, token, expect):
    body = gzip.compress(json.dumps(payload).encode())
    headers = {"Content-Type": "application/json", "Content-Encoding": "gzip"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(f"{URL}/v1/logs", data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            status = r.status
    except urllib.error.HTTPError as e:
        status = e.code
    if status != expect:
        raise SystemExit(f"POST /v1/logs expected {expect}, got {status}")


def main():
    wait_for_server()
    a_records = [log_record(f"a-{i}", 9, "INFO", trace=True) for i in range(3)]
    post(request("svc-a", a_records), TOKEN, 200)
    post(request("Svc B", [log_record(f"b-{i}", 13, "WARN") for i in range(2)]), TOKEN, 200)
    post(request(None, [log_record("no-resource", 9, "INFO")]), TOKEN, 200)
    post(request("svc-a", [log_record("rejected", 9, "INFO")]), "wrong-token", 401)
    print("OTLP generator sent 6 accepted records and 1 rejected request")


if __name__ == "__main__":
    main()
