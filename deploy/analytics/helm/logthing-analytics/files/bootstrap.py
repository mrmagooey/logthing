#!/usr/bin/env python3
"""Idempotent provisioning for the logthing analytics stack. Python stdlib only.

    bootstrap.py garage            assign+apply Garage layout, import S3 key, create bucket, grant key
    bootstrap.py lakekeeper        bootstrap Lakekeeper, create the warehouse if absent
    bootstrap.py wait garage       block until the bucket exists and the key can read+write it
    bootstrap.py wait lakekeeper   block until the warehouse exists

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
from dataclasses import dataclass


class Transient(Exception):
    """Worth retrying: service not up yet, 5xx, or a readiness condition not yet met."""


class Fatal(Exception):
    """Retrying will not help."""


@dataclass
class Config:
    garage_admin_url: str
    garage_admin_token: str
    access_key: str
    secret_key: str
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

    REQUIRED = {
        "garage": ("GARAGE_ADMIN_TOKEN", "S3_ACCESS_KEY", "S3_SECRET_KEY"),
        "wait-garage": ("GARAGE_ADMIN_TOKEN", "S3_ACCESS_KEY"),
        "lakekeeper": ("S3_ACCESS_KEY", "S3_SECRET_KEY"),
        "wait-lakekeeper": (),
    }

    @classmethod
    def from_env(cls, env, command):
        missing = [k for k in cls.REQUIRED[command] if not env.get(k)]
        if missing:
            raise KeyError(", ".join(missing))
        return cls(
            garage_admin_url=env.get("GARAGE_ADMIN_URL", "http://garage:3903").rstrip("/"),
            garage_admin_token=env.get("GARAGE_ADMIN_TOKEN", ""),
            access_key=env.get("S3_ACCESS_KEY", ""),
            secret_key=env.get("S3_SECRET_KEY", ""),
            bucket=env.get("DATA_BUCKET", "logthing-data"),
            zone=env.get("GARAGE_ZONE", "dc1"),
            capacity=int(env.get("GARAGE_CAPACITY_BYTES", str(10 * 1024**3))),
            lakekeeper_url=env.get("LAKEKEEPER_URL", "http://lakekeeper:8181").rstrip("/"),
            warehouse=env.get("WAREHOUSE", "logthing"),
            key_prefix=env.get("WAREHOUSE_KEY_PREFIX", "iceberg-warehouse"),
            s3_endpoint=env.get("S3_ENDPOINT", "http://garage:3900"),
            region=env.get("S3_REGION", "garage"),
            timeout=float(env.get("BOOTSTRAP_TIMEOUT_SECS", "300")),
            retry=float(env.get("BOOTSTRAP_RETRY_SECS", "2")),
        )


def http(method, url, token=None, body=None):
    """Return (status, parsed JSON or None). Raises Transient on connection failure or 5xx."""
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    except (urllib.error.URLError, OSError) as e:
        raise Transient(f"{method} {url}: {e}") from e
    try:
        parsed = json.loads(raw) if raw else None
    except ValueError:
        parsed = raw.decode(errors="replace")
    if status >= 500:
        raise Transient(f"{method} {url}: HTTP {status} {parsed}")
    return status, parsed


def expect(status, parsed, ok, what):
    if status not in ok:
        raise Fatal(f"{what}: HTTP {status} {parsed}")


def garage(cfg, method, path, body=None):
    return http(method, cfg.garage_admin_url + path, cfg.garage_admin_token, body)


def garage_bootstrap(cfg):
    st, cluster = garage(cfg, "GET", "/v2/GetClusterStatus")
    expect(st, cluster, {200}, "GetClusterStatus")
    node_id = cluster["nodes"][0]["id"]

    st, layout = garage(cfg, "GET", "/v2/GetClusterLayout")
    expect(st, layout, {200}, "GetClusterLayout")
    if not layout.get("roles"):
        role = {"id": node_id, "zone": cfg.zone, "capacity": cfg.capacity, "tags": []}
        st, r = garage(cfg, "POST", "/v2/UpdateClusterLayout", {"roles": [role]})
        expect(st, r, {200}, "UpdateClusterLayout")
        st, r = garage(cfg, "POST", "/v2/ApplyClusterLayout", {"version": layout["version"] + 1})
        expect(st, r, {200}, "ApplyClusterLayout")

    key = {"name": "logthing", "accessKeyId": cfg.access_key, "secretAccessKey": cfg.secret_key}
    st, r = garage(cfg, "POST", "/v2/ImportKey", key)
    expect(st, r, {200, 409}, "ImportKey")

    st, r = garage(cfg, "POST", "/v2/CreateBucket", {"globalAlias": cfg.bucket})
    expect(st, r, {200, 409}, "CreateBucket")

    bucket_id = _bucket_info(cfg)["id"]
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
    # 400 on a catalog that is already bootstrapped.
    expect(st, r, {200, 204, 400}, "Lakekeeper bootstrap")
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
    st, r = http("POST", cfg.lakekeeper_url + "/management/v1/warehouse", body=body)
    expect(st, r, {200, 201, 409}, "create warehouse")


def lakekeeper_ready(cfg):
    return cfg.warehouse in _warehouses(cfg)


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
        "garage": (garage_bootstrap, lambda c: f"garage at {c.garage_admin_url}"),
        "lakekeeper": (lakekeeper_bootstrap, lambda c: f"lakekeeper at {c.lakekeeper_url}"),
        "wait-garage": (garage_ready, lambda c: (
            f"garage at {c.garage_admin_url}: bucket '{c.bucket}' writable by {c.access_key}")),
        "wait-lakekeeper": (lakekeeper_ready, lambda c: (
            f"lakekeeper at {c.lakekeeper_url}: warehouse '{c.warehouse}'")),
    }
    if command not in actions:
        print("usage: bootstrap.py garage|lakekeeper|wait garage|wait lakekeeper", file=sys.stderr)
        return 2
    try:
        cfg = Config.from_env(env, command)
    except KeyError as e:
        print(f"bootstrap: missing required environment variable(s): {e.args[0]}", file=sys.stderr)
        return 2
    fn, describe = actions[command]
    try:
        with_retry(fn, cfg, describe(cfg))
    except Fatal as e:
        print(f"bootstrap: {command}: {e}", file=sys.stderr)
        return 1
    print(f"bootstrap: {command}: ok")
    return 0


if __name__ == "__main__":
    import os
    sys.exit(main(sys.argv[1:], dict(os.environ)))
