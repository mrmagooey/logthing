import re
import shutil
import subprocess

import pytest
import yaml

from conftest import ANALYTICS, CHART

if not shutil.which("helm"):
    pytest.skip("helm not available", allow_module_level=True)

FULL = "lt-logthing-analytics"
TIMEOUT = 60


def render(*sets):
    args = ["helm", "template", "lt", str(CHART)]
    for s in sets:
        args += ["--set", s]
    out = subprocess.run(
        args, capture_output=True, text=True, check=True, timeout=TIMEOUT
    ).stdout
    return [d for d in yaml.safe_load_all(out) if d]


def by(docs, kind, name):
    return next(d for d in docs if d["kind"] == kind and d["metadata"]["name"] == name)


def pod_spec(doc):
    if doc["kind"] == "CronJob":
        return doc["spec"]["jobTemplate"]["spec"]["template"]["spec"]
    return doc["spec"]["template"]["spec"]


def env_names(docs, kind, name):
    spec = pod_spec(by(docs, kind, name))
    return {e["name"] for c in spec["containers"] for e in c.get("env", [])}


def test_lint():
    subprocess.run(["helm", "lint", str(CHART)], check=True, capture_output=True, timeout=TIMEOUT)


def test_expected_resources():
    docs = render()
    names = {(d["kind"], d["metadata"]["name"]) for d in docs}
    for kind, name in [
        ("Secret", f"{FULL}-credentials"),
        ("ConfigMap", f"{FULL}-files"),
        ("ConfigMap", f"{FULL}-hue"),
        ("StatefulSet", f"{FULL}-postgres"),
        ("StatefulSet", f"{FULL}-garage"),
        ("Service", f"{FULL}-postgres"),
        ("Service", f"{FULL}-garage"),
        ("Service", f"{FULL}-lakekeeper"),
        ("Service", f"{FULL}-trino"),
        ("Service", f"{FULL}-hue"),
        ("Job", f"{FULL}-garage-init"),
        ("Job", f"{FULL}-lakekeeper-init"),
        ("Deployment", f"{FULL}-lakekeeper"),
        ("Deployment", f"{FULL}-logthing"),
        ("CronJob", f"{FULL}-committer"),
        ("Deployment", f"{FULL}-trino"),
        ("Deployment", f"{FULL}-hue"),
        ("Service", f"{FULL}-logthing-udp"),
        ("Service", f"{FULL}-logthing-tcp"),
    ]:
        assert (kind, name) in names, (kind, name)


def test_logthing_services_split_by_protocol():
    docs = render()
    udp = by(docs, "Service", f"{FULL}-logthing-udp")["spec"]["ports"]
    tcp = by(docs, "Service", f"{FULL}-logthing-tcp")["spec"]["ports"]
    assert {p["protocol"] for p in udp} == {"UDP"}
    assert {p["port"] for p in udp} == {514, 4739, 6343}
    assert {p.get("protocol", "TCP") for p in tcp} == {"TCP"}
    assert {p["port"] for p in tcp} == {601, 47760, 5985}


def test_service_selectors_match_workload_labels():
    docs = render()
    for svc in (d for d in docs if d["kind"] == "Service"):
        sel = svc["spec"]["selector"]
        matches = [
            d
            for d in docs
            if d["kind"] in ("Deployment", "StatefulSet")
            and all(d["spec"]["template"]["metadata"]["labels"].get(k) == v for k, v in sel.items())
        ]
        assert len(matches) == 1, (svc["metadata"]["name"], sel)


def test_wait_init_containers():
    docs = render()

    def waits(kind, name):
        return [
            c["command"][-1]
            for c in pod_spec(by(docs, kind, name)).get("initContainers", [])
            if c["name"].startswith("wait-")
        ]

    assert waits("Deployment", f"{FULL}-logthing") == ["garage"]
    assert waits("Job", f"{FULL}-lakekeeper-init") == ["garage"]
    assert waits("Deployment", f"{FULL}-trino") == ["lakekeeper"]
    assert waits("CronJob", f"{FULL}-committer") == ["lakekeeper"]


def test_every_files_volume_is_defined_where_mounted():
    for d in render():
        if d["kind"] not in ("Deployment", "StatefulSet", "Job", "CronJob"):
            continue
        spec = pod_spec(d)
        vols = {v["name"] for v in spec.get("volumes", [])}
        vols |= {t["metadata"]["name"] for t in d["spec"].get("volumeClaimTemplates", [])}
        for c in spec.get("initContainers", []) + spec["containers"]:
            for m in c.get("volumeMounts", []):
                assert m["name"] in vols, (d["metadata"]["name"], m["name"])


def test_committer_cronjob_policy():
    cj = by(render(), "CronJob", f"{FULL}-committer")
    assert cj["spec"]["concurrencyPolicy"] == "Forbid"
    assert cj["spec"]["jobTemplate"]["spec"]["backoffLimit"] == 0
    assert pod_spec(cj)["restartPolicy"] == "Never"


def test_garage_uses_image_default_command_like_compose():
    c = pod_spec(by(render(), "StatefulSet", f"{FULL}-garage"))["containers"][0]
    assert "command" not in c and "args" not in c
    mounts = {m["mountPath"] for m in c["volumeMounts"]}
    assert {"/etc/garage.toml", "/var/lib/garage/meta", "/var/lib/garage/data"} <= mounts


def test_lakekeeper_env_order_allows_expansion():
    env = pod_spec(by(render(), "Deployment", f"{FULL}-lakekeeper"))["containers"][0]["env"]
    names = [e["name"] for e in env]
    assert names.index("LAKEKEEPER_DB_PASSWORD") < names.index("LAKEKEEPER__PG_DATABASE_URL_READ")
    assert names.index("LAKEKEEPER_DB_PASSWORD") < names.index("LAKEKEEPER__PG_DATABASE_URL_WRITE")


def test_existing_secret_used():
    docs = render("credentials.existingSecret=mine")
    assert not any(d["kind"] == "Secret" for d in docs)
    refs = re.findall(
        r"secretKeyRef:\s*\n\s*name: (\S+)", yaml.safe_dump_all(docs, sort_keys=False)
    )
    assert refs and set(refs) == {"mine"}


def test_secret_keys_complete():
    data = by(render(), "Secret", f"{FULL}-credentials")["stringData"]
    assert set(data) == {
        "garage-rpc-secret", "garage-admin-token", "s3-access-key", "s3-secret-key",
        "postgres-password", "lakekeeper-db-password", "lakekeeper-encryption-key",
        "hue-db-password", "hue-secret-key",
    }


def test_helm_secret_refs_everywhere():
    docs = render()
    assert {"LOGTHING__SYSLOG__S3__ACCESS_KEY", "LOGTHING__ICEBERG__S3__SECRET_KEY"} <= env_names(
        docs, "Deployment", f"{FULL}-logthing"
    )
    assert {"S3_ACCESS_KEY", "S3_SECRET_KEY"} <= env_names(docs, "Deployment", f"{FULL}-trino")
    assert {"S3_ACCESS_KEY", "S3_SECRET_KEY"} <= env_names(docs, "CronJob", f"{FULL}-committer")
    assert {"HUE_DB_PASSWORD", "HUE_SECRET_KEY"} <= env_names(docs, "Deployment", f"{FULL}-hue")
    assert {"GARAGE_RPC_SECRET", "GARAGE_ADMIN_TOKEN"} <= env_names(
        docs, "StatefulSet", f"{FULL}-garage"
    )
    assert {"POSTGRES_PASSWORD", "LAKEKEEPER_DB_PASSWORD", "HUE_DB_PASSWORD"} <= env_names(
        docs, "StatefulSet", f"{FULL}-postgres"
    )


def test_logthing_flush_interval_and_endpoints():
    docs = render("logthing.flushIntervalSecs=15")
    env = {
        e["name"]: e.get("value")
        for e in pod_spec(by(docs, "Deployment", f"{FULL}-logthing"))["containers"][0]["env"]
    }
    for sec in ("SYSLOG", "IPFIX", "SFLOW", "ZEEK"):
        assert env[f"LOGTHING__{sec}__S3__FLUSH_INTERVAL_SECS"] == "15"
    for sec in ("SYSLOG", "IPFIX", "SFLOW", "ZEEK", "ICEBERG"):
        assert env[f"LOGTHING__{sec}__S3__ENDPOINT"] == f"http://{FULL}-garage:3900"


def test_committer_env_matches_compose():
    env = {
        e["name"]: e.get("value")
        for e in pod_spec(by(render(), "CronJob", f"{FULL}-committer"))["containers"][0]["env"]
    }
    assert env["DATA_BUCKET"] == "logthing-data"
    assert env["S3_REGION"] == "garage"
    assert env["WAREHOUSE"] == "logthing"
    assert env["ICEBERG_NAMESPACE"] == "logs"
    assert env["CATALOG_URI"] == f"http://{FULL}-lakekeeper:8181/catalog"


def test_image_overrides():
    docs = render("trino.image=trinodb/trino:470", "hue.image=example/hue:x")
    trino = pod_spec(by(docs, "Deployment", f"{FULL}-trino"))["containers"][0]["image"]
    hue = pod_spec(by(docs, "Deployment", f"{FULL}-hue"))["containers"][0]["image"]
    assert trino == "trinodb/trino:470"
    assert hue == "example/hue:x"


def test_default_images_pinned():
    images = {
        c["image"]
        for d in render()
        if d["kind"] in ("Deployment", "StatefulSet", "Job", "CronJob")
        for c in pod_spec(d)["containers"] + pod_spec(d).get("initContainers", [])
    }
    assert images == {
        "postgres:17", "dxflrs/garage:v2.4.1", "python:3.12-slim",
        "quay.io/lakekeeper/catalog:v0.13.6", "ghcr.io/mrmagooey/logthing:0.21.0",
        "ghcr.io/mrmagooey/logthing-committer:0.21.0", "trinodb/trino:483",
        "gethue/hue:20260611-140101",
    }


def test_storage_class_only_when_set():
    def claims(docs):
        return [
            t["spec"]
            for d in docs
            if d["kind"] == "StatefulSet"
            for t in d["spec"]["volumeClaimTemplates"]
        ]

    assert all("storageClassName" not in c for c in claims(render()))
    assert all(c["storageClassName"] == "fast" for c in claims(render("storageClassName=fast")))


def test_shared_files_are_verbatim():
    files = by(render(), "ConfigMap", f"{FULL}-files")["data"]
    names = ("bootstrap.py", "garage.toml", "logthing.toml", "trino-iceberg.properties",
             "postgres-init.sh")
    assert set(files) == set(names)
    for name in names:
        assert files[name].strip() == (CHART / "files" / name).read_text().strip(), name


def _significant(text):
    return [
        ln for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")
    ]


def test_hue_ini_parity_with_compose():
    rendered = by(render(), "ConfigMap", f"{FULL}-hue")["data"]["z-hue-overrides.ini"]
    normalised = rendered.replace(f"{FULL}-postgres", "postgres").replace(f"{FULL}-trino", "trino")
    assert _significant(normalised) == _significant((ANALYTICS / "hue.ini").read_text())


def test_rendered_yaml_has_no_duplicate_keys():
    class Strict(yaml.SafeLoader):
        pass

    def construct(loader, node, deep=False):
        keys = [loader.construct_object(k, deep=deep) for k, _ in node.value]
        dupes = {k for k in keys if keys.count(k) > 1}
        assert not dupes, dupes
        return yaml.SafeLoader.construct_mapping(loader, node, deep)

    Strict.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct)
    out = subprocess.run(
        ["helm", "template", "lt", str(CHART)],
        capture_output=True, text=True, check=True, timeout=TIMEOUT,
    ).stdout
    assert list(yaml.load_all(out, Loader=Strict))
