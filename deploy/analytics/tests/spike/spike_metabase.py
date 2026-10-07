#!/usr/bin/env python3
"""Spike helper: set up a fresh Metabase against Trino over TLS, then run SELECT 1 through it.

Usage: TRINO_PASSWORD=<metabase user password> spike_metabase.py <metabase_url> <pem|insecure>
Prints `SPIKE-RESULT key=value` lines; exits 0 only when SELECT 1 through Metabase worked.
Trino is reached from inside the Metabase container as trino:8443 with CA /tls/ca.pem.
The catalog is `system` because the spike Trino has no data catalogs.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request


def call(method, url, body=None, session=None):
    headers = {"Content-Type": "application/json"}
    if session:
        headers["X-Metabase-Session"] = session
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            raw, status = resp.read(), resp.status
    except urllib.error.HTTPError as e:
        raw, status = e.read(), e.code
    try:
        return status, json.loads(raw) if raw else None
    except ValueError:
        return status, raw.decode(errors="replace")


def result(key, value):
    print(f"SPIKE-RESULT {key}={value}", flush=True)


def main(base, mode):
    deadline = time.time() + 300
    while True:
        try:
            status, props = call("GET", base + "/api/session/properties")
            if status == 200:
                break
        except OSError:
            pass
        if time.time() > deadline:
            result("metabase_up", "fail")
            return 1
        time.sleep(3)
    result("metabase_up", "pass")
    engines = props.get("engines") or {}
    result("starburst_engine", "pass" if "starburst" in engines else "fail")
    if "starburst" not in engines:
        print("engines:", sorted(engines))
        return 1
    def names(fs):
        for f in fs:
            if f.get("name"):
                yield f["name"]
            yield from names(f.get("fields", []))

    fields = list(names(engines["starburst"].get("details-fields", [])))
    result("starburst_details_fields", ",".join(str(f) for f in fields))
    options = ("SSLVerification=NONE" if mode == "insecure"
               else "SSLTrustStorePath=/tls/ca.pem")
    details = {"host": "trino", "port": 8443, "catalog": "system", "user": "metabase",
               "password": os.environ["TRINO_PASSWORD"], "ssl": True,
               "additional-options": options}
    body = {
        "token": props["setup-token"],
        "user": {"first_name": "Spike", "last_name": "Admin", "email": "spike@logthing.example",
                 "password": "Spike-Admin-pw-0123456789"},
        "prefs": {"site_name": "spike", "allow_tracking": False},
    }
    status, r = call("POST", base + "/api/setup", body)
    result("metabase_setup_http", status)
    if status != 200:
        print("setup response:", r)
        return 1
    session = r["id"]
    # /api/setup silently drops a database that fails its connection test, so add it explicitly.
    status, r = call("POST", base + "/api/database",
                     {"engine": "starburst", "name": "spike", "details": details,
                      "is_full_sync": False}, session)
    result("metabase_add_database_http", status)
    if status != 200:
        print("add database response:", r)
        return 1
    _, dbs = call("GET", base + "/api/database", session=session)
    db_list = dbs["data"] if isinstance(dbs, dict) else dbs
    db_id = next(d["id"] for d in db_list if d["engine"] == "starburst")
    _, res = call("POST", base + "/api/dataset",
                  {"database": db_id, "type": "native", "native": {"query": "select 1"}}, session)
    ok = isinstance(res, dict) and res.get("status") == "completed" \
        and res["data"]["rows"] == [[1]]
    result(f"metabase_query_over_tls_{mode}", "pass" if ok else "fail")
    if not ok:
        print("dataset response:", res)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1].rstrip("/"), sys.argv[2]))
