#!/usr/bin/env python3
"""Run a SQL statement through Hue's REST API (-> Trino) and print the first cell.

Usage: hue_query.py <hue_base_url> <user> <password> <sql>

The first /api/v1/token/auth login auto-creates the user as a superuser. Hue's
check_status never leaves "waiting" for Trino, so we call fetch_result_data directly
with the execute handle and retry until it returns rows.
"""
import json
import sys
import time
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
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.load(resp)


def run(base, user, password, sql, deadline_secs=60):
    if '"' in sql:
        raise ValueError("statement must not contain double quotes (Hue's Trino API mangles them)")
    base = base.rstrip("/")
    token = post(f"{base}/api/v1/token/auth", None, body={"username": user, "password": password})["access"]
    ex = post(f"{base}/api/v1/editor/execute/trino", token,
              form={"statement": sql, "database": "iceberg.logs"})
    snippet = {"id": "trino", "type": "trino", "result": {"handle": ex["handle"]}}
    deadline = time.monotonic() + deadline_secs
    last = None
    while time.monotonic() < deadline:
        last = post(f"{base}/api/v1/editor/fetch_result_data", token,
                    form={"notebook": json.dumps(NOTEBOOK), "snippet": json.dumps(snippet),
                          "rows": "100", "startOver": "true"})
        data = (last.get("result") or {}).get("data")
        if data:
            return data[0][0]
        time.sleep(2)
    raise TimeoutError(f"no rows from Hue within {deadline_secs}s; last response: {last}")


if __name__ == "__main__":
    if len(sys.argv) != 5:
        sys.exit(__doc__)
    try:
        print(run(*sys.argv[1:5]))
    except Exception as e:  # noqa: BLE001 - CLI boundary: report and exit non-zero
        print(f"hue_query: {e}", file=sys.stderr)
        sys.exit(1)
