import re

from conftest import ANALYTICS, CHART

README = (ANALYTICS / "README.md").read_text()


def tracked_text_files():
    roots = [ANALYTICS / "docker-compose.yml", ANALYTICS / ".env.example"]
    roots += [p for p in (CHART / "templates").iterdir()]
    roots += [p for p in (CHART / "files").iterdir()]
    roots += [CHART / "values.yaml", CHART / "Chart.yaml"]
    roots += [p for p in (ANALYTICS / "tests" / "e2e").iterdir() if p.is_file()]
    roots += [p for p in (ANALYTICS / "scripts").iterdir()]
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
    assert "not** tested" in README or "not tested" in README


def test_dbt_readme_documents_detection_caveats_and_runtime_setup():
    text = (ANALYTICS / "dbt" / "README.md").read_text()
    for needle in ("tumbling", "~8 days", "not keyed by protocol", ".venv/bin/dbt",
                   "TRINO_HOST", "TRINO_CA_CERT", "upper bound"):
        assert needle in text, needle
    cron = text[text.index("cron every"):]
    assert "TRINO_PASSWORD" in cron and "TRINO_USER" in cron and "TRINO_PORT" in cron
