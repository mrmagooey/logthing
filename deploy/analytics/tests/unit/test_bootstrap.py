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


class FakeMetabase:
    """Stateful model of the Metabase API subset bootstrap.py metabase uses."""

    def __init__(self, server, engines=("starburst", "postgres"), db_400s=0):
        self.setup_token = "setup-tok"
        self.admin = None
        self.dbs = {}
        self.db_400s = db_400s
        self.setup_bodies = []
        self.db_bodies = []
        self.puts = []
        self.engines = {e: {} for e in engines}
        r = server.routes
        r[("GET", "/api/session/properties")] = lambda q, b: (
            200, {"setup-token": self.setup_token, "engines": self.engines})
        r[("POST", "/api/setup")] = self.setup
        r[("POST", "/api/session")] = self.login
        r[("GET", "/api/database")] = lambda q, b: (
            200, {"data": [{"id": i, **d} for i, d in self.dbs.items()]})
        r[("POST", "/api/database")] = self.add_db
        r[("PUT", "/api/database/1")] = self.put_db

    def setup(self, q, b):
        self.setup_bodies.append(b)
        if b["token"] != self.setup_token:
            return 403, {"message": "invalid token"}
        self.admin = (b["user"]["email"], b["user"]["password"])
        self.setup_token = None
        return 200, {"id": "session-1"}

    def login(self, q, b):
        if self.admin == (b["username"], b["password"]):
            return 200, {"id": "session-2"}
        return 401, {"message": "Password did not match stored password."}

    def add_db(self, q, b):
        self.db_bodies.append(b)
        if self.db_400s:
            self.db_400s -= 1
            return 400, {"message": "Unable to connect to Trino"}
        self.dbs[len(self.dbs) + 1] = {
            "name": b["name"], "engine": b["engine"], "details": b["details"]}
        return 200, {"id": len(self.dbs)}

    def put_db(self, q, b):
        self.puts.append(b)
        self.dbs[1]["details"] = b["details"]
        return 200, {}


ADMIN_PW = "AdminPw-123456"
TRINO_PW = "TrinoMbPw123456"
PEM_OPTIONS = "SSLTrustStorePath=/tls/ca.pem"


def mb_env(url, **extra):
    env = env_for(url, METABASE_URL=url, METABASE_ADMIN_PASSWORD=ADMIN_PW,
                  TRINO_METABASE_PASSWORD=TRINO_PW, TRINO_HOST="trino", TRINO_PORT="8443")
    env.update(extra)
    return env


def test_metabase_first_run_sets_up_admin_then_registers_starburst_database(bootstrap, server):
    mb = FakeMetabase(server)
    assert bootstrap.main(["metabase"], mb_env(server.url)) == 0
    body = mb.setup_bodies[0]
    assert body["token"] == "setup-tok"
    assert body["user"]["email"] == "admin@logthing.example"
    assert body["user"]["password"] == ADMIN_PW
    assert body["prefs"]["allow_tracking"] is False
    assert "database" not in body  # /api/setup silently drops a DB whose test fails
    db = mb.db_bodies[0]
    assert db["engine"] == "starburst" and db["name"] == "logthing"
    assert db["details"] == {
        "host": "trino", "port": 8443, "catalog": "iceberg", "user": "metabase",
        "password": TRINO_PW, "ssl": True, "additional-options": PEM_OPTIONS}
    assert "SSLTrustStoreType" not in db["details"]["additional-options"]


def test_metabase_second_run_logs_in_and_does_not_set_up_again(bootstrap, server):
    mb = FakeMetabase(server)
    assert bootstrap.main(["metabase"], mb_env(server.url)) == 0
    assert bootstrap.main(["metabase"], mb_env(server.url)) == 0
    assert len(mb.setup_bodies) == 1 and len(mb.dbs) == 1 and len(mb.puts) == 1
    assert any(h.get("X-Metabase-Session") == "session-2" for h in server.header_log)


def test_metabase_rerun_syncs_a_rotated_trino_password(bootstrap, server):
    mb = FakeMetabase(server)
    assert bootstrap.main(["metabase"], mb_env(server.url)) == 0
    assert bootstrap.main(
        ["metabase"], mb_env(server.url, TRINO_METABASE_PASSWORD="Rotated-pw-99999")) == 0
    assert mb.dbs[1]["details"]["password"] == "Rotated-pw-99999"


def test_metabase_registers_database_when_setup_exists_without_it(bootstrap, server):
    mb = FakeMetabase(server)
    mb.setup_token = None
    mb.admin = ("admin@logthing.example", ADMIN_PW)
    assert bootstrap.main(["metabase"], mb_env(server.url)) == 0
    assert len(mb.dbs) == 1 and mb.dbs[1]["engine"] == "starburst"
    assert mb.setup_bodies == []


def test_metabase_missing_starburst_engine_fails_clearly(bootstrap, server, capsys):
    FakeMetabase(server, engines=("postgres", "h2"))
    assert bootstrap.main(["metabase"], mb_env(server.url)) == 1
    err = capsys.readouterr().err
    assert "starburst" in err and "postgres" in err


def test_metabase_insecure_mode_disables_verification(bootstrap, server):
    mb = FakeMetabase(server)
    assert bootstrap.main(["metabase"], mb_env(server.url, TRINO_TLS_MODE="insecure")) == 0
    assert mb.dbs[1]["details"]["additional-options"] == "SSLVerification=NONE"


def test_metabase_invalid_tls_mode_is_a_usage_error(bootstrap, capsys):
    assert bootstrap.main(["metabase"], mb_env("http://x", TRINO_TLS_MODE="maybe")) == 2
    assert "TRINO_TLS_MODE" in capsys.readouterr().err


def test_metabase_wrong_admin_password_fails_fast(bootstrap, server, capsys):
    mb = FakeMetabase(server)
    mb.setup_token = None
    mb.admin = ("admin@logthing.example", "a-different-password")
    t = time.monotonic()
    assert bootstrap.main(["metabase"], mb_env(server.url, BOOTSTRAP_TIMEOUT_SECS="30")) == 1
    assert time.monotonic() - t < 5
    assert "METABASE_ADMIN_PASSWORD" in capsys.readouterr().err


def test_metabase_database_add_is_retried_until_trino_accepts_the_connection(bootstrap, server):
    mb = FakeMetabase(server, db_400s=2)
    assert bootstrap.main(["metabase"], mb_env(server.url)) == 0
    assert len(mb.db_bodies) == 3 and len(mb.setup_bodies) == 1 and len(mb.dbs) == 1


def test_metabase_persistent_database_error_times_out_naming_the_cause(bootstrap, server, capsys):
    mb = FakeMetabase(server, db_400s=10_000)
    assert bootstrap.main(["metabase"], mb_env(server.url, BOOTSTRAP_TIMEOUT_SECS="0.4")) == 1
    assert "Unable to connect to Trino" in capsys.readouterr().err
    assert mb.dbs == {}


def test_metabase_unexpected_database_status_fails_loudly(bootstrap, server, capsys):
    mb = FakeMetabase(server)
    server.routes[("POST", "/api/database")] = lambda q, b: (403, {"message": "nope"})
    assert bootstrap.main(["metabase"], mb_env(server.url)) == 1
    assert "403" in capsys.readouterr().err and mb.dbs == {}


def test_metabase_missing_env_is_a_usage_error(bootstrap, capsys):
    assert bootstrap.main(["metabase"], {}) == 2
    err = capsys.readouterr().err
    assert "METABASE_ADMIN_PASSWORD" in err and "TRINO_METABASE_PASSWORD" in err
