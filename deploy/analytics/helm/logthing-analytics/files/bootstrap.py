#!/usr/bin/env python3
"""Idempotent provisioning for the logthing analytics stack. Python stdlib only.

    bootstrap.py garage            assign+apply Garage layout, import S3 key, create bucket, grant key
    bootstrap.py lakekeeper        bootstrap Lakekeeper, create the warehouse if absent
    bootstrap.py wait garage       block until the bucket exists and the key can read+write it
    bootstrap.py wait lakekeeper   block until the warehouse exists
    bootstrap.py metabase          finish Metabase first-run setup (admin + Trino database), idempotent

Every step is safe to re-run. Connection failures and 5xx responses are retried until
BOOTSTRAP_TIMEOUT_SECS; any other unexpected response fails immediately.
Exit codes: 0 ok, 1 failed, 2 usage / missing environment.
"""

import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from http.client import HTTPException


class Transient(Exception):
    """Worth retrying: service not up yet, 5xx, or a readiness condition not yet met."""


class Fatal(Exception):
    """Retrying will not help."""


@dataclass
class Config:
    garage_admin_url: str
    garage_admin_token: str = field(repr=False)
    access_key: str
    secret_key: str = field(repr=False)
    bucket: str
    zone: str
    capacity: int
    lakekeeper_url: str
    warehouse: str
    key_prefix: str
    s3_endpoint: str
    region: str
    timeout: float
    retry: float
    metabase_url: str
    metabase_email: str
    metabase_password: str = field(repr=False)
    metabase_db_name: str
    trino_host: str
    trino_port: int
    trino_user: str
    trino_password: str = field(repr=False)
    trino_catalog: str
    tls_mode: str
    ca_path: str

    REQUIRED = {
        "garage": ("GARAGE_ADMIN_TOKEN", "S3_ACCESS_KEY", "S3_SECRET_KEY"),
        "wait-garage": ("GARAGE_ADMIN_TOKEN", "S3_ACCESS_KEY"),
        "lakekeeper": ("S3_ACCESS_KEY", "S3_SECRET_KEY"),
        "wait-lakekeeper": (),
        "metabase": ("METABASE_ADMIN_PASSWORD", "TRINO_METABASE_PASSWORD"),
    }

    @classmethod
    def from_env(cls, env, command):
        missing = [k for k in cls.REQUIRED[command] if not env.get(k)]
        if missing:
            raise KeyError(", ".join(missing))
        try:
            capacity = int(env.get("GARAGE_CAPACITY_BYTES",
                                   str(10 * 1024**3)))
            timeout = float(env.get("BOOTSTRAP_TIMEOUT_SECS", "300"))
            retry = float(env.get("BOOTSTRAP_RETRY_SECS", "2"))
            trino_port = int(env.get("TRINO_PORT", "8443"))
        except ValueError as e:
            raise ValueError(f"invalid configuration: {e}") from e
        tls_mode = env.get("TRINO_TLS_MODE", "pem")
        if tls_mode not in ("pem", "insecure"):
            raise ValueError(
                f"invalid configuration: TRINO_TLS_MODE must be pem or insecure, got {tls_mode!r}")
        return cls(
            garage_admin_url=env.get(
                "GARAGE_ADMIN_URL",
                "http://garage:3903").rstrip("/"),
            garage_admin_token=env.get("GARAGE_ADMIN_TOKEN", ""),
            access_key=env.get("S3_ACCESS_KEY", ""),
            secret_key=env.get("S3_SECRET_KEY", ""),
            bucket=env.get("DATA_BUCKET", "logthing-data"),
            zone=env.get("GARAGE_ZONE", "dc1"),
            capacity=capacity,
            lakekeeper_url=env.get(
                "LAKEKEEPER_URL",
                "http://lakekeeper:8181").rstrip("/"),
            warehouse=env.get("WAREHOUSE", "logthing"),
            key_prefix=env.get(
                "WAREHOUSE_KEY_PREFIX",
                "iceberg-warehouse"),
            s3_endpoint=env.get("S3_ENDPOINT", "http://garage:3900"),
            region=env.get("S3_REGION", "garage"),
            timeout=timeout,
            retry=retry,
            metabase_url=env.get("METABASE_URL", "http://metabase:3000").rstrip("/"),
            metabase_email=env.get("METABASE_ADMIN_EMAIL", "admin@logthing.example"),
            metabase_password=env.get("METABASE_ADMIN_PASSWORD", ""),
            metabase_db_name=env.get("METABASE_DB_NAME", "logthing"),
            trino_host=env.get("TRINO_HOST", "trino"),
            trino_port=trino_port,
            trino_user=env.get("TRINO_METABASE_USER", "metabase"),
            trino_password=env.get("TRINO_METABASE_PASSWORD", ""),
            trino_catalog=env.get("TRINO_CATALOG", "iceberg"),
            tls_mode=tls_mode,
            ca_path=env.get("TRINO_CA_PATH", "/tls/ca.pem"),
        )


def http(method, url, token=None, body=None, headers=None):
    """Return (status, parsed JSON or None). Raises Transient on connection
    failure or 5xx."""
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    for name, value in (headers or {}).items():
        req.add_header(name, value)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    except (urllib.error.URLError, OSError, HTTPException) as e:
        raise Transient(f"{method} {url}: {e}") from e
    try:
        parsed = json.loads(raw) if raw else None
    except ValueError:
        parsed = raw.decode(errors="replace")
    parsed_str = str(parsed)
    if len(parsed_str) > 500:
        parsed_str = parsed_str[:500] + "..."
    if status >= 500:
        raise Transient(f"{method} {url}: HTTP {status} {parsed_str}")
    return status, parsed


def expect(status, parsed, ok, what):
    if status not in ok:
        parsed_str = str(parsed)
        if len(parsed_str) > 500:
            parsed_str = parsed_str[:500] + "..."
        raise Fatal(f"{what}: HTTP {status} {parsed_str}")


def garage(cfg, method, path, body=None):
    return http(method, cfg.garage_admin_url + path, cfg.garage_admin_token, body)


def garage_bootstrap(cfg):
    st, cluster = garage(cfg, "GET", "/v2/GetClusterStatus")
    expect(st, cluster, {200}, "GetClusterStatus")
    node_id = cluster["nodes"][0]["id"]

    st, layout = garage(cfg, "GET", "/v2/GetClusterLayout")
    expect(st, layout, {200}, "GetClusterLayout")
    if not layout.get("roles"):
        role = {
            "id": node_id,
            "zone": cfg.zone,
            "capacity": cfg.capacity,
            "tags": []
        }
        st, r = garage(cfg, "POST", "/v2/UpdateClusterLayout",
                       {"roles": [role]})
        expect(st, r, {200}, "UpdateClusterLayout")
        st, r = garage(cfg, "POST", "/v2/ApplyClusterLayout",
                       {"version": layout["version"] + 1})
        expect(st, r, {200}, "ApplyClusterLayout")

    key = {
        "name": "logthing",
        "accessKeyId": cfg.access_key,
        "secretAccessKey": cfg.secret_key
    }
    st, r = garage(cfg, "POST", "/v2/ImportKey", key)
    expect(st, r, {200, 409}, "ImportKey")

    st, r = garage(cfg, "POST", "/v2/CreateBucket",
                   {"globalAlias": cfg.bucket})
    expect(st, r, {200, 409}, "CreateBucket")

    bucket_info = _bucket_info(cfg)
    if not bucket_info:
        raise Fatal("bucket not found after CreateBucket")
    bucket_id = bucket_info["id"]
    grant = {
        "bucketId": bucket_id,
        "accessKeyId": cfg.access_key,
        "permissions": {"read": True, "write": True, "owner": True},
    }
    st, r = garage(cfg, "POST", "/v2/AllowBucketKey", grant)
    expect(st, r, {200}, "AllowBucketKey")


def _bucket_info(cfg):
    q = urllib.parse.urlencode({"globalAlias": cfg.bucket})
    st, info = garage(cfg, "GET", f"/v2/GetBucketInfo?{q}")
    if st in (400, 404):
        return None
    expect(st, info, {200}, "GetBucketInfo")
    return info


def garage_ready(cfg):
    info = _bucket_info(cfg)
    if not info:
        return False
    for k in info.get("keys", []):
        p = k.get("permissions", {})
        if k.get("accessKeyId") == cfg.access_key and p.get("read") and p.get("write"):
            return True
    return False


def _warehouses(cfg):
    st, r = http("GET", cfg.lakekeeper_url + "/management/v1/warehouse")
    expect(st, r, {200}, "list warehouses")
    return [w.get("name") for w in (r or {}).get("warehouses", [])]


def lakekeeper_bootstrap(cfg):
    st, r = http("POST", cfg.lakekeeper_url + "/management/v1/bootstrap",
                 body={"accept-terms-of-use": True})
    # 400 on a catalog that is already bootstrapped; check error message.
    if st == 400:
        if "bootstrap" not in str(r).lower():
            raise Fatal(f"Lakekeeper bootstrap: HTTP {st} {r}")
    elif st not in (200, 204):
        raise Fatal(f"Lakekeeper bootstrap: HTTP {st} {r}")
    if cfg.warehouse in _warehouses(cfg):
        return
    body = {
        "warehouse-name": cfg.warehouse,
        "storage-profile": {
            "type": "s3",
            "bucket": cfg.bucket,
            "key-prefix": cfg.key_prefix,
            "endpoint": cfg.s3_endpoint,
            "region": cfg.region,
            "path-style-access": True,
            "flavor": "s3-compat",
            "sts-enabled": False,
        },
        "storage-credential": {
            "type": "s3",
            "credential-type": "access-key",
            "access-key-id": cfg.access_key,
            "secret-access-key": cfg.secret_key,
        },
    }
    st, r = http(
        "POST",
        cfg.lakekeeper_url + "/management/v1/warehouse",
        body=body)
    expect(st, r, {200, 201, 409}, "create warehouse")


def lakekeeper_ready(cfg):
    return cfg.warehouse in _warehouses(cfg)


def _short(parsed):
    text = str(parsed)
    return text if len(text) <= 300 else text[:300] + "..."


def _mb(cfg, method, path, body=None, session=None):
    headers = {"X-Metabase-Session": session} if session else None
    return http(method, cfg.metabase_url + path, body=body, headers=headers)


def metabase_details(cfg):
    """Starburst driver connection details: Trino over TLS, trusting the generated CA."""
    options = ("SSLVerification=NONE" if cfg.tls_mode == "insecure"
               else f"SSLTrustStorePath={cfg.ca_path}")
    return {
        "host": cfg.trino_host,
        "port": cfg.trino_port,
        "catalog": cfg.trino_catalog,
        "user": cfg.trino_user,
        "password": cfg.trino_password,
        "ssl": True,
        "additional-options": options,
    }


def _mb_login(cfg):
    st, r = _mb(cfg, "POST", "/api/session",
                {"username": cfg.metabase_email, "password": cfg.metabase_password})
    if st in (400, 401, 403):
        raise Fatal(
            f"Metabase admin login failed (HTTP {st}): METABASE_ADMIN_PASSWORD / "
            f"METABASE_ADMIN_EMAIL do not match the admin created at first setup")
    if st == 429:
        raise Transient(f"metabase login rate-limited: HTTP 429 {_short(r)}")
    expect(st, r, {200}, "metabase login")
    return r["id"]


def metabase_bootstrap(cfg):
    st, props = _mb(cfg, "GET", "/api/session/properties")
    expect(st, props, {200}, "metabase session properties")
    engines = (props or {}).get("engines") or {}
    if "starburst" not in engines:
        raise Fatal("Metabase has no 'starburst' database driver (available: "
                    f"{', '.join(sorted(engines)) or 'none'}); the pinned OSS image is expected")
    token = props.get("setup-token")
    if token:
        # No database here: /api/setup silently drops one whose connection test fails, which
        # would leave an admin and no way to tell. The database is registered below, loudly.
        body = {
            "token": token,
            "user": {"first_name": "Logthing", "last_name": "Admin",
                     "email": cfg.metabase_email, "password": cfg.metabase_password},
            "prefs": {"site_name": "logthing", "allow_tracking": False},
        }
        st, r = _mb(cfg, "POST", "/api/setup", body)
        if st == 403:
            raise Transient(f"metabase setup: HTTP {st} {_short(r)}")  # a concurrent run won
        expect(st, r, {200}, "metabase setup")
    session = _mb_login(cfg)
    details = metabase_details(cfg)
    st, dbs = _mb(cfg, "GET", "/api/database", session=session)
    expect(st, dbs, {200}, "metabase list databases")
    items = dbs["data"] if isinstance(dbs, dict) else dbs
    existing = next((d for d in items if d.get("name") == cfg.metabase_db_name), None)
    if existing is None:
        database = {"engine": "starburst", "name": cfg.metabase_db_name, "details": details,
                    "is_full_sync": True}
        st, r = _mb(cfg, "POST", "/api/database", database, session)
    else:
        st, r = _mb(cfg, "PUT", f"/api/database/{existing['id']}", {"details": details}, session)
    if st in (401, 403):
        raise Fatal(f"metabase database update: HTTP {st} {_short(r)}")
    if st >= 400:
        # 400 is typically Trino not accepting the connection yet; retried until the deadline.
        raise Transient(f"metabase database update: HTTP {st} {_short(r)}")


def with_retry(fn, cfg, what):
    """Run fn until it returns a non-False value; retry Transient until the deadline."""
    deadline = time.monotonic() + cfg.timeout
    last = "not ready"
    while True:
        try:
            if fn(cfg) is not False:
                return
        except Transient as e:
            last = str(e)
        if time.monotonic() >= deadline:
            raise Fatal(f"timed out after {cfg.timeout:g}s waiting for {what}: {last}")
        time.sleep(cfg.retry)


def main(argv, env):
    command = "-".join(argv)
    actions = {
        "garage": (
            garage_bootstrap,
            lambda c: f"garage at {c.garage_admin_url}"),
        "lakekeeper": (
            lakekeeper_bootstrap,
            lambda c: f"lakekeeper at {c.lakekeeper_url}"),
        "metabase": (
            metabase_bootstrap,
            lambda c: f"metabase at {c.metabase_url} (Trino {c.trino_host}:{c.trino_port})"),
        "wait-garage": (
            garage_ready,
            lambda c: (
                f"garage at {c.garage_admin_url}: bucket '{c.bucket}' "
                f"writable by {c.access_key}")),
        "wait-lakekeeper": (
            lakekeeper_ready,
            lambda c: (
                f"lakekeeper at {c.lakekeeper_url}: "
                f"warehouse '{c.warehouse}'")),
    }
    if command not in actions:
        msg = ("usage: bootstrap.py garage|lakekeeper|metabase|wait garage|"
               "wait lakekeeper")
        print(msg, file=sys.stderr)
        return 2
    try:
        cfg = Config.from_env(env, command)
    except KeyError as e:
        print(
            f"bootstrap: missing required environment variable(s): "
            f"{e.args[0]}",
            file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"bootstrap: {e}", file=sys.stderr)
        return 2
    fn, describe = actions[command]
    try:
        with_retry(fn, cfg, describe(cfg))
    except Fatal as e:
        print(f"bootstrap: {command}: {e}", file=sys.stderr)
        return 1
    except (KeyError, IndexError, TypeError) as e:
        print(
            f"bootstrap: {command}: unexpected response: {e}",
            file=sys.stderr)
        return 1
    print(f"bootstrap: {command}: ok")
    return 0


if __name__ == "__main__":
    import os
    sys.exit(main(sys.argv[1:], dict(os.environ)))
