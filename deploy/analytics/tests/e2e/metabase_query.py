#!/usr/bin/env python3
"""Run a native SQL query through Metabase's API (-> Trino over TLS) and print the first cell.

Usage: METABASE_PASSWORD=<admin password> metabase_query.py <base_url> <email> <sql>

Asserts the `starburst` driver is present, logs in, uses the Starburst database that
bootstrap.py metabase registered and POSTs /api/dataset. Retries while Metabase or Trino warm up.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request


def call(method, url, body=None, session=None, timeout=120):
    headers = {"Content-Type": "application/json"}
    if session:
        headers["X-Metabase-Session"] = session
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw, status = resp.read(), resp.status
    except urllib.error.HTTPError as e:
        raw, status = e.read(), e.code
    try:
        return status, json.loads(raw) if raw else None
    except ValueError:
        return status, raw.decode(errors="replace")


def run(base, email, password, sql, deadline_secs=120):
    base = base.rstrip("/")
    status, props = call("GET", f"{base}/api/session/properties")
    if status != 200 or "starburst" not in ((props or {}).get("engines") or {}):
        raise RuntimeError(f"Metabase has no starburst driver (HTTP {status})")
    status, sess = call("POST", f"{base}/api/session", {"username": email, "password": password})
    if status != 200:
        raise RuntimeError(f"Metabase login failed: HTTP {status}")
    session = sess["id"]
    status, dbs = call("GET", f"{base}/api/database", session=session)
    items = dbs["data"] if isinstance(dbs, dict) else dbs
    db = next((d for d in items if d.get("engine") == "starburst"), None)
    if db is None:
        raise RuntimeError("no starburst database is registered in Metabase")
    deadline = time.monotonic() + deadline_secs
    while True:
        _, res = call("POST", f"{base}/api/dataset",
                      {"database": db["id"], "type": "native", "native": {"query": sql}}, session)
        if isinstance(res, dict) and res.get("status") == "completed":
            return res["data"]["rows"][0][0]
        if time.monotonic() > deadline:
            raise TimeoutError(f"no result from Metabase within {deadline_secs}s; last: {res}")
        time.sleep(3)


if __name__ == "__main__":
    if len(sys.argv) != 4 or "METABASE_PASSWORD" not in os.environ:
        sys.exit(__doc__)
    try:
        print(run(sys.argv[1], sys.argv[2], os.environ["METABASE_PASSWORD"], sys.argv[3]))
    except Exception as e:  # noqa: BLE001 - CLI boundary: report and exit non-zero
        print(f"metabase_query: {e}", file=sys.stderr)
        sys.exit(1)
