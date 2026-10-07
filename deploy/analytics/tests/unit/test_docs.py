import re

from conftest import ANALYTICS, CHART

README = (ANALYTICS / "README.md").read_text()


def tracked_text_files():
    roots = [ANALYTICS / "docker-compose.yml", ANALYTICS / ".env.example", CHART / "values.yaml",
             CHART / "Chart.yaml"]
    for d in (CHART / "templates", CHART / "files", ANALYTICS / "tests" / "e2e",
              ANALYTICS / "scripts"):
        roots += [p for p in d.rglob("*") if "__pycache__" not in p.parts]
    return [p for p in roots if p.is_file()]


def test_hue_is_gone_from_every_deployable_and_e2e_file():
    for path in tracked_text_files():
        assert not re.search(r"\bhue\b", path.read_text(), re.IGNORECASE), path


def test_readme_mentions_hue_only_in_the_migration_section():
    sections = re.split(r"(?m)^## ", README)
    for section in sections:
        if re.search(r"\bhue\b", section, re.IGNORECASE):
            assert section.startswith("Migrating from Hue"), section[:60]


def test_no_demo_secrets_documented_or_shipped():
    for text in (README, (ANALYTICS / ".env.example").read_text()):
        assert "demo-" not in text and "change-me" not in text and "GK6b9c" not in text


def test_readme_covers_every_b1_behaviour():
    for needle in ("gen-analytics-env.sh", "Network isolation", "Querying Trino", "trino-tls",
                   "Migrating from Hue", "TRINO_IMAGE", "networkPolicy.enabled", "Metabase",
                   "OPENID_PROVIDER_URI", "trino.tls.existingSecret", "dbt/README.md"):
        assert needle in README, needle


def test_readme_documents_credentials_and_isolation_caveats():
    assert "no default secrets" in README.lower()
    assert re.search(r"NetworkPolicies are enforced only by CNIs.*?Enforcement is \*\*not\*\* tested",
                     README, re.DOTALL)


def test_dbt_readme_documents_detection_caveats_and_runtime_setup():
    text = (ANALYTICS / "dbt" / "README.md").read_text()
    for needle in ("tumbling", "~8 days", "not keyed by protocol", ".venv/bin/dbt",
                   "TRINO_HOST", "TRINO_CA_CERT", "upper bound"):
        assert needle in text, needle
    cron = text[text.index("cron every"):]
    assert "TRINO_PASSWORD" in cron and "TRINO_USER" in cron and "TRINO_PORT" in cron


def test_readme_documents_sending_app_logs():
    for needle in ("Sending application logs", "HEC_TOKEN", "OTLP_BEARER_TOKEN", "/v1/logs",
                   "/services/collector/event", "Authorization: Splunk", "Authorization: Bearer",
                   "docs/otlp.md", "hec-token", "otlp-bearer-token", "0.22.0"):
        assert needle in README, needle
    assert "unauthenticated plaintext HTTP" not in README
    assert "cleartext" in README.lower()  # tokens cross the wire unencrypted: front with TLS
