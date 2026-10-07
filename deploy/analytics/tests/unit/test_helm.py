import os
import re
import shutil
import subprocess
import tempfile

import pytest
import yaml

from conftest import ANALYTICS, CHART

if not shutil.which("helm"):
    pytest.skip("helm not available", allow_module_level=True)

FULL = "lt-logthing-analytics"
TIMEOUT = 60


def render(*sets, release="lt"):
    args = ["helm", "template", release, str(CHART)]
    for s in sets:
        args += ["--set", s]
    out = subprocess.run(
        args, capture_output=True, text=True, check=True, timeout=TIMEOUT
    ).stdout
    return [d for d in yaml.safe_load_all(out) if d]


def render_fails(*sets):
    with pytest.raises(subprocess.CalledProcessError) as exc:
        render(*sets)
    return exc.value.stderr


def notes(*sets):
    """Render NOTES.txt hermetically: `helm install --dry-run` can need a live cluster and
    `helm template` drops notes, so render a copy of the chart that exposes the notes text as a
    ConfigMap value."""
    with tempfile.TemporaryDirectory() as d:
        chart = shutil.copytree(CHART, f"{d}/chart")
        with open(f"{chart}/templates/NOTES.txt") as f:
            text = f.read()
        os.remove(f"{chart}/templates/NOTES.txt")
        with open(f"{chart}/templates/_notes.tpl", "w") as f:
            f.write('{{- define "notes" -}}' + text + "{{- end -}}")
        with open(f"{chart}/templates/notes.yaml", "w") as f:
            f.write('apiVersion: v1\nkind: ConfigMap\nmetadata: {name: notes}\ndata:\n'
                    '  notes: |\n    {{- include "notes" . | nindent 4 }}\n')
        args = ["helm", "template", "lt", chart, "--show-only", "templates/notes.yaml"]
        for s in sets:
            args += ["--set", s]
        out = subprocess.run(args, capture_output=True, text=True, check=True,
                             timeout=TIMEOUT).stdout
        return yaml.safe_load(out)["data"]["notes"]


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
        ("Secret", f"{FULL}-trino-tls"),
        ("StatefulSet", f"{FULL}-postgres"),
        ("StatefulSet", f"{FULL}-garage"),
        ("Service", f"{FULL}-postgres"),
        ("Service", f"{FULL}-garage"),
        ("Service", f"{FULL}-lakekeeper"),
        ("Service", f"{FULL}-trino"),
        ("Service", f"{FULL}-metabase"),
        ("Deployment", f"{FULL}-metabase"),
        ("Job", f"{FULL}-metabase-init-1"),
        ("Job", f"{FULL}-garage-init-1"),
        ("Job", f"{FULL}-lakekeeper-init-1"),
        ("Deployment", f"{FULL}-lakekeeper"),
        ("Deployment", f"{FULL}-logthing"),
        ("CronJob", f"{FULL}-committer"),
        ("Deployment", f"{FULL}-trino"),
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
    assert waits("Job", f"{FULL}-lakekeeper-init-1") == ["garage"]
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
    spec = pod_spec(by(render(), "Deployment", f"{FULL}-lakekeeper"))
    for c in spec["initContainers"] + spec["containers"]:
        names = [e["name"] for e in c["env"]]
        pw = names.index("LAKEKEEPER_DB_PASSWORD")
        assert pw < names.index("LAKEKEEPER__PG_DATABASE_URL_READ"), c["name"]
        assert pw < names.index("LAKEKEEPER__PG_DATABASE_URL_WRITE"), c["name"]


def _secret_refs(docs):
    refs = set()
    for d in docs:
        if d["kind"] not in ("Deployment", "StatefulSet", "Job", "CronJob"):
            continue
        spec = pod_spec(d)
        for c in spec.get("initContainers", []) + spec["containers"]:
            for e in c.get("env", []):
                ref = e.get("valueFrom", {}).get("secretKeyRef")
                if ref:
                    refs.add(ref["name"])
    return refs


def test_existing_secret_used():
    docs = render("credentials.existingSecret=mine")
    # the generated TLS Secret is independent of credentials.existingSecret
    assert [d["metadata"]["name"] for d in docs if d["kind"] == "Secret"] == [f"{FULL}-trino-tls"]
    assert _secret_refs(docs) == {"mine"}
    assert _secret_refs(render()) == {f"{FULL}-credentials"}


def test_secret_keys_complete():
    data = by(render(), "Secret", f"{FULL}-credentials")["stringData"]
    assert set(data) == {
        "garage-rpc-secret", "garage-admin-token", "s3-access-key", "s3-secret-key",
        "postgres-password", "lakekeeper-db-password", "lakekeeper-encryption-key",
        "trino-admin-password", "trino-metabase-password", "trino-shared-secret",
        "metabase-db-password", "metabase-encryption-key", "metabase-admin-password",
        "hec-token", "otlp-bearer-token",
    }


def test_helm_secret_refs_everywhere():
    docs = render()
    assert {"LOGTHING__SYSLOG__S3__ACCESS_KEY", "LOGTHING__ICEBERG__S3__SECRET_KEY"} <= env_names(
        docs, "Deployment", f"{FULL}-logthing"
    )
    assert {"S3_ACCESS_KEY", "S3_SECRET_KEY"} <= env_names(docs, "Deployment", f"{FULL}-trino")
    assert {"S3_ACCESS_KEY", "S3_SECRET_KEY"} <= env_names(docs, "CronJob", f"{FULL}-committer")
    assert {"TRINO_SHARED_SECRET", "TRINO_PASSWORD"} <= env_names(
        docs, "Deployment", f"{FULL}-trino")
    assert {"GARAGE_RPC_SECRET", "GARAGE_ADMIN_TOKEN"} <= env_names(
        docs, "StatefulSet", f"{FULL}-garage"
    )
    assert {"POSTGRES_PASSWORD", "LAKEKEEPER_DB_PASSWORD", "METABASE_DB_PASSWORD"} <= env_names(
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
    docs = render("trino.image=trinodb/trino:470", "trino.authgen.image=example/htpasswd:x")
    spec = pod_spec(by(docs, "Deployment", f"{FULL}-trino"))
    assert spec["containers"][0]["image"] == "trinodb/trino:470"
    assert next(c for c in spec["initContainers"] if c["name"] == "authgen")["image"] == \
        "example/htpasswd:x"


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
        "httpd:2.4.69-alpine", "metabase/metabase:v0.64.1",
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
             "postgres-init.sh", "authgen.sh", "trino-config.properties",
             "trino-password-authenticator.properties")
    assert set(files) == set(names)
    for name in names:
        assert files[name].strip() == (CHART / "files" / name).read_text().strip(), name


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


def test_jobs_are_revisioned_with_ttl_and_stable_component_label():
    docs = render()
    for comp in ("garage-init", "lakekeeper-init", "metabase-init"):
        job = by(docs, "Job", f"{FULL}-{comp}-1")
        assert job["spec"]["ttlSecondsAfterFinished"] == 3600
        assert job["metadata"]["labels"]["app.kubernetes.io/component"] == comp
        assert "helm.sh/hook" not in job["metadata"].get("annotations", {})


def test_long_release_name_keeps_names_within_limits():
    docs = render(release="r" * 30)
    for d in docs:
        assert len(d["metadata"]["name"]) <= 63, d["metadata"]["name"]
    cj = next(d for d in docs if d["kind"] == "CronJob")
    assert len(cj["metadata"]["name"]) <= 52


def _annotations(docs, kind, name):
    return pod_spec_meta(by(docs, kind, name)).get("annotations", {})


def pod_spec_meta(doc):
    if doc["kind"] == "CronJob":
        return doc["spec"]["jobTemplate"]["spec"]["template"]["metadata"]
    return doc["spec"]["template"]["metadata"]


def test_checksum_annotations():
    docs = render()
    for kind, name in [("Deployment", "logthing"), ("Deployment", "trino"),
                       ("StatefulSet", "garage"), ("StatefulSet", "postgres")]:
        a = _annotations(docs, kind, f"{FULL}-{name}")
        assert "checksum/secret" in a and "checksum/files" in a, name
    assert "checksum/tls" in _annotations(docs, "Deployment", f"{FULL}-trino")
    docs = render("credentials.existingSecret=mine", "trino.tls.existingSecret=mytls")
    a = _annotations(docs, "Deployment", f"{FULL}-trino")
    assert "checksum/secret" not in a and "checksum/tls" not in a


def test_checksum_changes_with_values():
    a = _annotations(render(), "Deployment", f"{FULL}-trino")["checksum/secret"]
    b = _annotations(render("credentials.trinoAdminPassword=other"), "Deployment",
                     f"{FULL}-trino")["checksum/secret"]
    assert a != b


def _decode(secret, key):
    import base64
    return base64.b64decode(secret["data"][key]).decode()


def test_trino_tls_secret_is_a_valid_ca_signed_cert():
    import os
    secret = by(render(), "Secret", f"{FULL}-trino-tls")
    assert set(secret["data"]) == {"ca.pem", "server.pem"}
    server, ca = _decode(secret, "server.pem"), _decode(secret, "ca.pem")
    assert "BEGIN CERTIFICATE" in server and "PRIVATE KEY" in server
    assert "PRIVATE KEY" not in ca
    if not shutil.which("openssl"):
        pytest.skip("openssl not available")
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, "server.pem"), "w").write(server)
        open(os.path.join(d, "ca.pem"), "w").write(ca)
        subprocess.run(["openssl", "verify", "-CAfile", f"{d}/ca.pem", f"{d}/server.pem"],
                       check=True, capture_output=True)
        text = subprocess.run(["openssl", "x509", "-in", f"{d}/server.pem", "-noout", "-text"],
                              capture_output=True, text=True, check=True).stdout
    for san in (f"DNS:{FULL}-trino", f"DNS:{FULL}-trino.default.svc", "DNS:localhost",
                "IP Address:127.0.0.1"):
        assert san in text, san


def test_trino_tls_existing_secret_is_used_and_not_rendered():
    docs = render("trino.tls.existingSecret=mytls")
    assert not any(d["kind"] == "Secret" and d["metadata"]["name"].endswith("-trino-tls")
                   for d in docs)
    vols = pod_spec(by(docs, "Deployment", f"{FULL}-trino"))["volumes"]
    assert next(v for v in vols if v["name"] == "tls")["secret"]["secretName"] == "mytls"


def test_trino_service_exposes_only_https_never_plain_http():
    svc = by(render(), "Service", f"{FULL}-trino")
    assert [(p["name"], p["port"]) for p in svc["spec"]["ports"]] == [("https", 8443)]
    assert all(p["port"] != 8080 and p["targetPort"] != 8080 for p in svc["spec"]["ports"])


def test_trino_pod_wiring():
    spec = pod_spec(by(render(), "Deployment", f"{FULL}-trino"))
    assert spec["securityContext"]["fsGroup"] == 1000
    assert spec["initContainers"][0]["name"] == "wait-lakekeeper"
    authgen = next(c for c in spec["initContainers"] if c["name"] == "authgen")
    assert authgen["command"] == ["sh", "/bootstrap/authgen.sh"]
    refs = {e["name"]: e["valueFrom"]["secretKeyRef"]["key"] for e in authgen["env"]
            if "valueFrom" in e}
    assert refs == {"TRINO_ADMIN_PASSWORD": "trino-admin-password",
                    "TRINO_METABASE_PASSWORD": "trino-metabase-password"}
    trino = spec["containers"][0]
    # 8080 (internal/discovery) is deliberately not declared; only HTTPS is a container port.
    assert [p["containerPort"] for p in trino["ports"]] == [8443]
    env = {e["name"]: e["valueFrom"]["secretKeyRef"]["key"] for e in trino["env"]
           if "valueFrom" in e}
    assert env["TRINO_SHARED_SECRET"] == "trino-shared-secret"
    assert env["TRINO_PASSWORD"] == "trino-admin-password"
    mounts = {m["mountPath"]: m for m in trino["volumeMounts"]}
    for path in ("/etc/trino/config.properties", "/etc/trino/password-authenticator.properties",
                 "/etc/trino/catalog/iceberg.properties", "/etc/trino/tls", "/etc/trino/auth"):
        assert path in mounts, path
    assert "https://localhost:8443" in " ".join(trino["readinessProbe"]["exec"]["command"])
    tls = next(v for v in spec["volumes"] if v["name"] == "tls")["secret"]
    assert tls["defaultMode"] == 0o440 and tls["secretName"] == f"{FULL}-trino-tls"


def test_exec_probes_have_timeouts():
    seen = 0
    for d in render():
        if d["kind"] not in ("Deployment", "StatefulSet"):
            continue
        for c in pod_spec(d)["containers"]:
            probe = c.get("readinessProbe", {})
            if "exec" in probe:
                seen += 1
                assert probe["timeoutSeconds"] >= 5, d["metadata"]["name"]
    assert seen == 4
    trino = pod_spec(by(render(), "Deployment", f"{FULL}-trino"))["containers"][0]
    assert trino["readinessProbe"]["initialDelaySeconds"] == 20


def test_default_requests_set():
    docs = render()
    for kind, name in [("StatefulSet", "postgres"), ("StatefulSet", "garage"),
                       ("Deployment", "lakekeeper"), ("Deployment", "logthing")]:
        c = pod_spec(by(docs, kind, f"{FULL}-{name}"))["containers"][0]
        assert c["resources"]["requests"]["memory"], name
    c = pod_spec(by(docs, "CronJob", f"{FULL}-committer"))["containers"][0]
    assert c["resources"]["requests"]["cpu"]


def test_wait_init_containers_get_minimal_env():
    docs = render()
    lk = pod_spec(by(docs, "Deployment", f"{FULL}-trino"))["initContainers"][0]
    assert {e["name"] for e in lk["env"]} == {"LAKEKEEPER_URL", "BOOTSTRAP_TIMEOUT_SECS"}
    g = pod_spec(by(docs, "Deployment", f"{FULL}-logthing"))["initContainers"][0]
    assert {e["name"] for e in g["env"]} == {
        "GARAGE_ADMIN_URL", "GARAGE_ADMIN_TOKEN", "S3_ACCESS_KEY", "BOOTSTRAP_TIMEOUT_SECS"}


def test_committer_active_deadline():
    cj = by(render(), "CronJob", f"{FULL}-committer")
    assert cj["spec"]["jobTemplate"]["spec"]["activeDeadlineSeconds"] == 900


def test_garage_capacity_rendered_as_plain_integer():
    # Helm parses YAML numbers as float64; a bare `quote` renders 1.073741824e+10, which
    # bootstrap.py's int() rejects (found on a real cluster).
    for sets, want in [((), "10737418240"), (("garage.capacityBytes=21474836480",), "21474836480")]:
        job = by(render(*sets), "Job", f"{FULL}-garage-init-1")
        env = {e["name"]: e.get("value") for e in pod_spec(job)["containers"][0]["env"]}
        assert env["GARAGE_CAPACITY_BYTES"] == want


def test_volume_claim_templates_carry_instance_label():
    # `kubectl delete pvc -l app.kubernetes.io/instance=<release>` (docs, NOTES.txt) relies on it.
    docs = render()
    sets = [d for d in docs if d["kind"] == "StatefulSet"]
    assert sets
    for sts in sets:
        for vct in sts["spec"]["volumeClaimTemplates"]:
            # immutable field: only stable keys, so appVersion/chart bumps never break upgrades
            assert set(vct["metadata"]["labels"]) == {
                "app.kubernetes.io/name",
                "app.kubernetes.io/instance",
            }
            assert vct["metadata"]["labels"]["app.kubernetes.io/instance"] == "lt"


HEX64 = re.compile(r"[0-9a-f]{64}")


def test_generated_credentials_have_required_shapes():
    d = by(render(), "Secret", f"{FULL}-credentials")["stringData"]
    assert re.fullmatch(r"GK[0-9a-f]{24}", d["s3-access-key"])
    assert HEX64.fullmatch(d["s3-secret-key"]) and HEX64.fullmatch(d["garage-rpc-secret"])
    for k in ("garage-admin-token", "postgres-password", "lakekeeper-db-password",
              "lakekeeper-encryption-key", "trino-admin-password", "trino-metabase-password",
              "trino-shared-secret", "metabase-db-password", "metabase-encryption-key",
              "metabase-admin-password"):
        assert re.fullmatch(r"[A-Za-z0-9]{32,}", d[k]), k


def test_no_demo_credentials_remain():
    text = str(by(render(), "Secret", f"{FULL}-credentials")["stringData"])
    assert "demo" not in text and "change-me" not in text
    values = (CHART / "values.yaml").read_text()
    assert "demo" not in values and "change-me" not in values and "GK6b9c" not in values


def test_two_renders_generate_different_secrets():
    a = by(render(), "Secret", f"{FULL}-credentials")["stringData"]
    b = by(render(), "Secret", f"{FULL}-credentials")["stringData"]
    assert all(a[k] != b[k] for k in a)


def test_explicit_credential_wins_over_generation():
    d = by(render("credentials.postgresPassword=abc123"), "Secret",
           f"{FULL}-credentials")["stringData"]
    assert d["postgres-password"] == "abc123"


def test_non_url_safe_password_fails_render():
    err = render_fails("credentials.lakekeeperDbPassword=a/b@c")
    assert "lakekeeperDbPassword" in err and "URL-safe" in err


def test_notes_point_at_metabase_and_https_trino():
    text = notes()
    assert "metabase-admin-password" in text and "svc/lt-logthing-analytics-metabase" in text
    assert "svc/lt-logthing-analytics-trino 8443" in text and "https://localhost:8443" in text
    assert "Hue" not in text


def test_notes_describe_generated_credentials():
    text = notes()
    assert "Demo credentials" not in text
    assert f"{FULL}-credentials" in text and "kubectl get secret" in text
    assert f"{FULL}-credentials" not in notes("credentials.existingSecret=mine")


def test_notes_warn_on_pre_b1_demo_credentials():
    text = notes("credentials.postgresPassword=demo-postgres-change-me",
                 "credentials.s3AccessKey=GK6b9c062a24e5a702c7c53e5b")
    assert "WARNING" in text and "PUBLIC demo values" in text
    assert "postgres-password" in text and "s3-access-key" in text
    assert "lakekeeper-encryption-key" not in text
    assert "Upgrading an existing stack" in text


def test_notes_do_not_warn_for_generated_or_custom_credentials():
    assert "WARNING" not in notes()
    assert "WARNING" not in notes("credentials.postgresPassword=something-else-entirely")
    assert "WARNING" not in notes("credentials.existingSecret=mine",
                                  "credentials.postgresPassword=demo-postgres-change-me")


def test_checksum_secret_is_stable_across_renders_with_generated_secrets():
    # The generated Secret differs per render (see test_two_renders_generate_different_secrets),
    # but the pod-roll checksum must not, or every `helm upgrade` would roll every pod.
    # LIMITATION: `helm template` has no cluster so `lookup` returns empty and the lookup
    # persistence path itself cannot be exercised here; it is covered by helm-minikube.sh step 3b
    # (secret unchanged across `helm upgrade`). This test pins the checksum independence from
    # whatever the Secret resolved to, which is what makes the lookup path roll-free.
    a, b = render(), render()
    for kind, name in (("Deployment", "logthing"),
                       ("Deployment", "trino"), ("StatefulSet", "postgres"),
                       ("StatefulSet", "garage"), ("Deployment", "lakekeeper"),
                       ("CronJob", "committer"), ("Job", "garage-init-1"),
                       ("Job", "lakekeeper-init-1"), ("Deployment", "metabase"),
                       ("Job", "metabase-init-1")):
        full = f"{FULL}-{name}"
        assert (_annotations(a, kind, full)["checksum/secret"]
                == _annotations(b, kind, full)["checksum/secret"]), name


LABEL = "app.kubernetes.io/component"


def policies(*sets, release="lt"):
    return {d["metadata"]["name"]: d for d in render(*sets, release=release)
            if d["kind"] == "NetworkPolicy"}


def peers(rule):
    return {p["podSelector"]["matchLabels"][LABEL] for p in rule["from"]}


def ports(rule):
    return [(p["protocol"], p["port"]) for p in rule["ports"]]


def test_network_policies_rendered_by_default_and_ingress_only():
    pol = policies()
    assert set(pol) == {f"{FULL}-lakekeeper", f"{FULL}-postgres", f"{FULL}-garage",
                        f"{FULL}-trino"}
    for p in pol.values():
        assert p["spec"]["policyTypes"] == ["Ingress"]


def test_lakekeeper_reachable_only_from_committer_trino_and_bootstrap():
    spec = policies()[f"{FULL}-lakekeeper"]["spec"]
    assert spec["podSelector"]["matchLabels"][LABEL] == "lakekeeper"
    (rule,) = spec["ingress"]
    assert peers(rule) == {"committer", "trino", "lakekeeper-init"}
    assert ports(rule) == [("TCP", 8181)]


def test_postgres_reachable_only_from_lakekeeper_and_metabase():
    spec = policies()[f"{FULL}-postgres"]["spec"]
    assert spec["podSelector"]["matchLabels"][LABEL] == "postgres"
    (rule,) = spec["ingress"]
    assert peers(rule) == {"lakekeeper", "metabase"}
    assert ports(rule) == [("TCP", 5432)]


def test_garage_s3_open_rpc_self_only_admin_bootstrap_only():
    spec = policies()[f"{FULL}-garage"]["spec"]
    by_port = {ports(r)[0][1]: r for r in spec["ingress"]}
    assert set(by_port) == {3900, 3901, 3903}
    assert "from" not in by_port[3900]                      # S3 stays default-allow
    assert peers(by_port[3901]) == {"garage"}
    # logthing's wait-garage initContainer polls the admin API, so it must be allowed too
    assert peers(by_port[3903]) == {"garage-init", "lakekeeper-init", "logthing"}


def test_trino_only_https_reachable_from_other_workloads():
    # Rule chosen: the policy allows ingress on 8443/TCP only (from any source: clients and
    # Metabase); 8080 is not listed, so no other pod can reach it. Trino's own discovery and
    # internal traffic use localhost:8080 inside the pod, which NetworkPolicy never filters.
    spec = policies()[f"{FULL}-trino"]["spec"]
    assert spec["podSelector"]["matchLabels"][LABEL] == "trino"
    (rule,) = spec["ingress"]
    assert "from" not in rule
    assert ports(rule) == [("TCP", 8443)]


def test_policies_are_scoped_to_the_release():
    for p in policies(release="other").values():
        selectors = [p["spec"]["podSelector"]["matchLabels"]]
        selectors += [x["podSelector"]["matchLabels"] for r in p["spec"]["ingress"]
                      for x in r.get("from", [])]
        assert all(s["app.kubernetes.io/instance"] == "other" for s in selectors)


def test_policy_selectors_match_real_pod_labels():
    docs = render()
    pod_components = set()
    for d in docs:
        if d["kind"] in ("Deployment", "StatefulSet", "Job", "CronJob"):
            pod_components.add(pod_spec_meta(d)["labels"][LABEL])
    for p in policies().values():
        used = {p["spec"]["podSelector"]["matchLabels"][LABEL]}
        used |= {x["podSelector"]["matchLabels"][LABEL] for r in p["spec"]["ingress"]
                 for x in r.get("from", [])}
        assert used <= pod_components, used - pod_components


def test_network_policy_can_be_disabled():
    assert policies("networkPolicy.enabled=false") == {}


def _env_map(container):
    return {e["name"]: e.get("value") or e["valueFrom"]["secretKeyRef"]["key"]
            for e in container["env"]}


def test_metabase_deployment_wiring():
    spec = pod_spec(by(render(), "Deployment", f"{FULL}-metabase"))
    wait = spec["initContainers"][0]
    assert wait["name"] == "wait-postgres" and f"{FULL}-postgres" in wait["command"]
    c = spec["containers"][0]
    env = _env_map(c)
    assert env["MB_DB_TYPE"] == "postgres" and env["MB_DB_HOST"] == f"{FULL}-postgres"
    assert env["MB_DB_DBNAME"] == "metabase" and env["MB_DB_USER"] == "metabase"
    assert env["MB_DB_PASS"] == "metabase-db-password"
    assert env["MB_ENCRYPTION_SECRET_KEY"] == "metabase-encryption-key"
    assert c["readinessProbe"]["httpGet"] == {"path": "/api/health", "port": 3000}
    # only the CA is mounted: never Trino's private key
    tls = next(v for v in spec["volumes"] if v["name"] == "tls")["secret"]
    assert tls["items"] == [{"key": "ca.pem", "path": "ca.pem"}]
    assert tls["secretName"] == f"{FULL}-trino-tls"
    assert [(m["mountPath"], m["readOnly"]) for m in c["volumeMounts"]] == [("/tls", True)]


def test_metabase_tls_secret_follows_trino_existing_secret():
    spec = pod_spec(by(render("trino.tls.existingSecret=mytls"), "Deployment",
                       f"{FULL}-metabase"))
    assert next(v for v in spec["volumes"] if v["name"] == "tls")["secret"]["secretName"] == "mytls"


def test_metabase_init_job_env_and_modes():
    job = by(render(), "Job", f"{FULL}-metabase-init-1")
    c = pod_spec(job)["containers"][0]
    assert c["command"] == ["python", "/bootstrap/bootstrap.py", "metabase"]
    env = _env_map(c)
    assert env["METABASE_URL"] == f"http://{FULL}-metabase:3000"
    assert env["TRINO_HOST"] == f"{FULL}-trino" and env["TRINO_PORT"] == "8443"
    assert env["METABASE_ADMIN_PASSWORD"] == "metabase-admin-password"
    assert env["TRINO_METABASE_PASSWORD"] == "trino-metabase-password"
    assert env["TRINO_TLS_MODE"] == "pem" and env["TRINO_CA_PATH"] == "/tls/ca.pem"
    job2 = by(render("metabase.trinoTlsMode=insecure"), "Job", f"{FULL}-metabase-init-1")
    assert _env_map(pod_spec(job2)["containers"][0])["TRINO_TLS_MODE"] == "insecure"


def test_postgres_policy_selects_the_real_metabase_pods():
    docs = render()
    assert pod_spec_meta(by(docs, "Deployment", f"{FULL}-metabase"))["labels"][LABEL] == "metabase"
    (rule,) = policies()[f"{FULL}-postgres"]["spec"]["ingress"]
    assert "metabase" in peers(rule)


def test_secret_has_ingest_tokens_with_url_safe_generated_values():
    data = by(render(), "Secret", f"{FULL}-credentials")["stringData"]
    for key in ("hec-token", "otlp-bearer-token"):
        assert re.fullmatch(r"[A-Za-z0-9]{40}", data[key]), key
    assert data["hec-token"] != data["otlp-bearer-token"]


def test_explicit_ingest_tokens_win():
    data = by(render("credentials.hecToken=HecTokenPinned1234",
                     "credentials.otlpBearerToken=OtlpTokenPinned12"),
              "Secret", f"{FULL}-credentials")["stringData"]
    assert data["hec-token"] == "HecTokenPinned1234"
    assert data["otlp-bearer-token"] == "OtlpTokenPinned12"


def test_logthing_gets_hec_and_otlp_sinks_and_token_secret_refs():
    docs = render("logthing.flushIntervalSecs=15")
    env = {e["name"]: e for e in
           pod_spec(by(docs, "Deployment", f"{FULL}-logthing"))["containers"][0]["env"]}
    for sec in ("HEC", "OTLP"):
        assert env[f"LOGTHING__{sec}__S3__ENDPOINT"]["value"] == f"http://{FULL}-garage:3900"
        assert env[f"LOGTHING__{sec}__S3__FLUSH_INTERVAL_SECS"]["value"] == "15"
        assert "valueFrom" in env[f"LOGTHING__{sec}__S3__ACCESS_KEY"]
    ref = lambda n: env[n]["valueFrom"]["secretKeyRef"]
    assert ref("LOGTHING__HEC__TOKEN")["key"] == "hec-token"
    assert ref("LOGTHING__OTLP__BEARER_TOKEN")["key"] == "otlp-bearer-token"
    assert "value" not in env["LOGTHING__HEC__TOKEN"]  # never inline


def test_notes_say_how_to_read_the_ingest_tokens():
    text = notes()
    assert "hec-token" in text and "otlp-bearer-token" in text


def test_require_tokens_init_container_guards_empty_tokens():
    for sets in ((), ("credentials.existingSecret=mine",)):
        docs = render(*sets)
        secret = "mine" if sets else f"{FULL}-credentials"
        init = {c["name"]: c for c in pod_spec(by(docs, "Deployment", f"{FULL}-logthing"))
                ["initContainers"]}["require-tokens"]
        refs = {e["name"]: e for e in init["env"]}
        assert set(refs) == {"HEC_TOKEN", "OTLP_BEARER_TOKEN"}
        for name, key in (("HEC_TOKEN", "hec-token"), ("OTLP_BEARER_TOKEN", "otlp-bearer-token")):
            assert "value" not in refs[name]
            assert refs[name]["valueFrom"]["secretKeyRef"] == {"name": secret, "key": key}
        assert "exit 1" in " ".join(init["command"])
