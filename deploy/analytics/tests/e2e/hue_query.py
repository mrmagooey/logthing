#!/usr/bin/env python3
"""Run a SQL statement through Hue's REST API (-> Trino) and print the first cell.

Usage: HUE_PASSWORD=<password> hue_query.py <hue_base_url> <user> <sql>

The first /api/v1/token/auth login auto-creates the user as a superuser. Hue's
check_status never leaves "waiting" for Trino, so we call fetch_result_data directly
with the execute handle and retry until it returns rows.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

NOTEBOOK = {"type": "query-trino", "snippets": [{"id": "trino", "type": "trino"}], "sessions": []}


def post(url, token, *, form=None, body=None):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    else:
        data = urllib.parse.urlencode(form).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        snippet = e.read(300).decode("utf-8", "replace")
        raise RuntimeError(f"POST {url} -> HTTP {e.code}: {snippet}") from e
    try:
        return json.loads(raw)
    except ValueError as e:
        raise RuntimeError(f"POST {url} returned non-JSON body: {raw[:300]!r}") from e


def run(base, user, password, sql, deadline_secs=60):
    if '"' in sql:
        raise ValueError("statement must not contain double quotes (Hue's Trino API mangles them)")
    base = base.rstrip("/")
    login = post(f"{base}/api/v1/token/auth", None, body={"username": user, "password": password})
    token = login.get("access")
    if not token:
        raise RuntimeError(f"login failed at {base}/api/v1/token/auth: {str(login)[:300]}")
    ex = post(f"{base}/api/v1/editor/execute/trino", token,
              form={"statement": sql, "database": "iceberg.logs"})
    if "handle" not in ex:
        raise RuntimeError(f"execute returned no handle: {str(ex)[:300]}")
    snippet = {"id": "trino", "type": "trino", "result": {"handle": ex["handle"]}}
    deadline = time.monotonic() + deadline_secs
    last = None
    while time.monotonic() < deadline:
        try:
            last = post(f"{base}/api/v1/editor/fetch_result_data", token,
                        form={"notebook": json.dumps(NOTEBOOK), "snippet": json.dumps(snippet),
                              "rows": "100", "startOver": "true"})
        except (urllib.error.URLError, RuntimeError) as e:
            # Transient while Trino/Hue warm up; the deadline bounds the retry.
            last = e
            time.sleep(2)
            continue
        data = (last.get("result") or {}).get("data")
        if data:
            return data[0][0]
        time.sleep(2)
    raise TimeoutError(f"no rows from Hue within {deadline_secs}s; last response: {last}")


if __name__ == "__main__":
    if len(sys.argv) != 4 or "HUE_PASSWORD" not in os.environ:
        sys.exit(__doc__)
    try:
        print(run(sys.argv[1], sys.argv[2], os.environ["HUE_PASSWORD"], sys.argv[3]))
    except Exception as e:  # noqa: BLE001 - CLI boundary: report and exit non-zero
        print(f"hue_query: {e}", file=sys.stderr)
        sys.exit(1)
