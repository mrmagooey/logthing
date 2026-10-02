import time

import pytest

AK = "GK6b9c062a24e5a702c7c53e5b"
SK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


def env_for(url, **extra):
    env = {
        "GARAGE_ADMIN_URL": url,
        "GARAGE_ADMIN_TOKEN": "tok",
        "S3_ACCESS_KEY": AK,
        "S3_SECRET_KEY": SK,
        "LAKEKEEPER_URL": url,
        "BOOTSTRAP_TIMEOUT_SECS": "3",
        "BOOTSTRAP_RETRY_SECS": "0.05",
    }
    env.update(extra)
    return env


class FakeGarage:
    """Stateful model of the Garage admin API v2 subset bootstrap.py
    uses."""

    def __init__(self, server):
        self.roles = []
        self.version = 0
        self.keys = set()
        self.buckets = {}  # alias -> {"id":..., "keys": {ak: perms}}
        r = server.routes
        r[("GET", "/v2/GetClusterStatus")] = (
            lambda q, b: (200, {"nodes": [{"id": "n" * 64}]}))
        r[("GET", "/v2/GetClusterLayout")] = (
            lambda q, b: (
                200,
                {"version": self.version, "roles": self.roles}))
        r[("POST", "/v2/UpdateClusterLayout")] = self.update_layout
        r[("POST", "/v2/ApplyClusterLayout")] = self.apply_layout
        r[("POST", "/v2/ImportKey")] = self.import_key
        r[("POST", "/v2/CreateBucket")] = self.create_bucket
        r[("GET", "/v2/GetBucketInfo")] = self.bucket_info
        r[("POST", "/v2/AllowBucketKey")] = self.allow
        self.staged = None

    def update_layout(self, q, b):
        self.staged = b["roles"]
        return 200, {}

    def apply_layout(self, q, b):
        if b["version"] != self.version + 1:
            return 500, {"message": "Invalid new layout version"}
        self.version, self.roles = b["version"], self.staged
        return 200, {}

    def import_key(self, q, b):
        if b["accessKeyId"] in self.keys:
            return 409, {"code": "KeyAlreadyExists"}
        self.keys.add(b["accessKeyId"])
        return 200, {}

    def create_bucket(self, q, b):
        if b["globalAlias"] in self.buckets:
            return 409, {"code": "BucketAlreadyExists"}
        self.buckets[b["globalAlias"]] = {"id": "b" * 64, "keys": {}}
        return 200, {"id": "b" * 64}

    def bucket_info(self, q, b):
        bucket = self.buckets.get(q["globalAlias"][0])
        if not bucket:
            return 404, {"code": "NoSuchBucket"}
        keys = [
            {"accessKeyId": k, "permissions": p}
            for k, p in bucket["keys"].items()
        ]
        return 200, {"id": bucket["id"], "keys": keys}

    def allow(self, q, b):
        for bucket in self.buckets.values():
            if bucket["id"] == b["bucketId"]:
                bucket["keys"][b["accessKeyId"]] = b["permissions"]
        return 200, {}


class FakeLakekeeper:
    def __init__(self, server):
        self.bootstrapped = False
        self.warehouses = []
        r = server.routes
        r[("POST", "/management/v1/bootstrap")] = self.do_bootstrap
        r[("GET", "/management/v1/warehouse")] = (
            lambda q, b: (
                200,
                {"warehouses": [{"name": n} for n in self.warehouses]}))
        r[("POST", "/management/v1/warehouse")] = self.create
        self.created_bodies = []

    def do_bootstrap(self, q, b):
        if self.bootstrapped:
            return 400, {"error": {"message": "Catalog already bootstrapped"}}
        self.bootstrapped = True
        return 204, None

    def create(self, q, b):
        self.created_bodies.append(b)
        self.warehouses.append(b["warehouse-name"])
        return 201, {"warehouse-id": "w1"}


def test_garage_bootstrap_provisions_everything(bootstrap, server):
    g = FakeGarage(server)
    assert bootstrap.main(["garage"], env_for(server.url)) == 0
    assert g.version == 1 and g.roles[0]["zone"] == "dc1"
    assert AK in g.keys
    assert g.buckets["logthing-data"]["keys"][AK] == (
        {"read": True, "write": True, "owner": True})
    assert all(c[3] == "Bearer tok" for c in server.calls)


def test_garage_rerun_is_noop(bootstrap, server):
    g = FakeGarage(server)
    assert bootstrap.main(["garage"], env_for(server.url)) == 0
    assert bootstrap.main(["garage"], env_for(server.url)) == 0
    assert g.version == 1  # layout not re-applied


def test_wait_garage_true_only_after_grant(bootstrap, server):
    g = FakeGarage(server)
    cfg = bootstrap.Config.from_env(env_for(server.url), "wait-garage")
    assert bootstrap.garage_ready(cfg) is False
    bootstrap.garage_bootstrap(
        bootstrap.Config.from_env(env_for(server.url), "garage"))
    assert bootstrap.garage_ready(cfg) is True


def test_lakekeeper_bootstrap_creates_warehouse_once(bootstrap, server):
    lk = FakeLakekeeper(server)
    assert bootstrap.main(["lakekeeper"], env_for(server.url)) == 0
    assert bootstrap.main(["lakekeeper"], env_for(server.url)) == 0
    assert lk.warehouses == ["logthing"]
    body = lk.created_bodies[0]
    prof = body["storage-profile"]
    assert prof == {
        "type": "s3",
        "bucket": "logthing-data",
        "key-prefix": "iceberg-warehouse",
        "endpoint": "http://garage:3900",
        "region": "garage",
        "path-style-access": True,
        "flavor": "s3-compat",
        "sts-enabled": False,
    }
    assert body["storage-credential"] == {
        "type": "s3",
        "credential-type": "access-key",
        "access-key-id": AK,
        "secret-access-key": SK,
    }


def test_wait_lakekeeper(bootstrap, server):
    lk = FakeLakekeeper(server)
    assert bootstrap.main(
        ["wait", "lakekeeper"],
        env_for(server.url, BOOTSTRAP_TIMEOUT_SECS="0.3")) == 1
    lk.warehouses.append("logthing")
    assert bootstrap.main(["wait", "lakekeeper"], env_for(server.url)) == 0


def test_retries_until_service_answers(bootstrap, server):
    FakeGarage(server)
    status = server.routes[("GET", "/v2/GetClusterStatus")]
    attempts = {"n": 0}

    def flaky(q, b):
        attempts["n"] += 1
        return (503, {"message": "starting"}) if attempts["n"] < 3 else status(q, b)

    server.routes[("GET", "/v2/GetClusterStatus")] = flaky
    assert bootstrap.main(["garage"], env_for(server.url)) == 0
    assert attempts["n"] >= 3


def test_connection_refused_is_retried_then_deadline_error_names_target(
        bootstrap, capsys):
    env = env_for("http://127.0.0.1:9", BOOTSTRAP_TIMEOUT_SECS="0.3")
    assert bootstrap.main(["wait", "garage"], env) == 1
    err = capsys.readouterr().err
    assert (err.startswith("bootstrap:") and "garage" in err and
            "127.0.0.1:9" in err)


def test_deadline_error_names_target(bootstrap, server, capsys):
    FakeLakekeeper(server)
    assert bootstrap.main(
        ["wait", "lakekeeper"],
        env_for(server.url, BOOTSTRAP_TIMEOUT_SECS="0.2")) == 1
    assert "warehouse 'logthing'" in capsys.readouterr().err


def test_client_error_is_fatal_without_waiting(bootstrap, server, capsys):
    FakeGarage(server)
    server.routes[("POST", "/v2/ImportKey")] = (
        lambda q, b: (
            400,
            {"message": "Secret keys should be at least 16 characters long"}))
    env = env_for(server.url, BOOTSTRAP_TIMEOUT_SECS="30")
    t = time.monotonic()
    assert bootstrap.main(["garage"], env) == 1
    assert time.monotonic() - t < 5
    assert "16 characters" in capsys.readouterr().err


def test_lakekeeper_bootstrap_400_invalid_request_fails(bootstrap, server,
                                                        capsys):
    """400 response without 'bootstrap' in body is fatal."""
    lk = FakeLakekeeper(server)
    server.routes[("POST", "/management/v1/bootstrap")] = (
        lambda q, b: (400, {"error": {"message": "invalid request"}}))
    assert bootstrap.main(["lakekeeper"], env_for(server.url)) == 1
    assert "invalid request" in capsys.readouterr().err


def test_missing_env_is_usage_error(bootstrap, capsys):
    assert bootstrap.main(["garage"], {}) == 2
    assert "GARAGE_ADMIN_TOKEN" in capsys.readouterr().err


def test_non_numeric_config_is_usage_error(bootstrap, capsys):
    """Non-numeric BOOTSTRAP_TIMEOUT_SECS/RETRY_SECS raise ValueError."""
    env = env_for("http://example.com", BOOTSTRAP_TIMEOUT_SECS="not_a_number")
    assert bootstrap.main(["garage"], env) == 2
    assert "invalid configuration" in capsys.readouterr().err


def test_unknown_command_is_usage_error(bootstrap):
    assert bootstrap.main(["frobnicate"], {}) == 2
