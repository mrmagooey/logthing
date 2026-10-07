"""Release-consistency guard: stack image pins and 'since X' strings track Cargo.toml."""
import re
from pathlib import Path

ANALYTICS = Path(__file__).resolve().parents[2]
ROOT = ANALYTICS.parents[1]

# "since/from/before 0.22.0" (any case) but not an IP-like run such as "from 10.0.0.5".
SINCE_RE = re.compile(
    r"(?<![\w.])(?:[Ss]ince|[Ff]rom|[Bb]efore) (\d+\.\d+\.\d+)(?![\d.]*\d)(?!\.\d)"
)
FIRST_SHIPPED = (0, 22, 0)  # the release that introduced the strings; never decreases


def cargo_version() -> str:
    text = (ROOT / "Cargo.toml").read_text()
    return re.search(r'^version\s*=\s*"([^"]+)"', text, re.M).group(1)


def read(rel: str) -> str:
    return (ANALYTICS / rel).read_text()


def test_compose_defaults_pin_the_cargo_version():
    v = cargo_version()
    t = read("docker-compose.yml")
    assert f"ghcr.io/mrmagooey/logthing:{v}}}" in t
    assert f"ghcr.io/mrmagooey/logthing-committer:{v}}}" in t


def test_env_example_pins_the_cargo_version():
    v = cargo_version()
    t = read(".env.example")
    assert f"logthing:{v}" in t and f"logthing-committer:{v}" in t


def test_helm_values_and_chart_app_version_pin_the_cargo_version():
    v = cargo_version()
    values = read("helm/logthing-analytics/values.yaml")
    assert f"ghcr.io/mrmagooey/logthing:{v}" in values
    assert f"ghcr.io/mrmagooey/logthing-committer:{v}" in values
    assert f'appVersion: "{v}"' in read("helm/logthing-analytics/Chart.yaml")


def test_readme_image_table_pins_the_cargo_version():
    v = cargo_version()
    t = read("README.md")
    assert f"ghcr.io/mrmagooey/logthing:{v}" in t
    assert f"ghcr.io/mrmagooey/logthing-committer:{v}" in t


def test_no_stale_older_pin_anywhere_in_the_stack():
    v = cargo_version()
    stale = []
    for p in ANALYTICS.rglob("*"):
        if not p.is_file() or ".venv" in p.parts or p.suffix in {".pyc"}:
            continue
        try:
            text = p.read_text()
        except UnicodeDecodeError:
            continue
        for m in re.finditer(r"ghcr\.io/mrmagooey/logthing(?:-committer)?:(\d+\.\d+\.\d+)", text):
            if m.group(1) != v:
                stale.append((str(p.relative_to(ANALYTICS)), m.group(0)))
    assert not stale, stale


def test_since_regex_ignores_ip_like_and_prose_matches():
    assert SINCE_RE.findall("Failed password from 10.0.0.5 port 22") == []
    assert SINCE_RE.findall("seen since 10.0.0.5 or so") == []
    assert SINCE_RE.findall("a since-boot window, since a deployment") == []
    assert SINCE_RE.findall("sinks since 0.22.0; see") == ["0.22.0"]
    assert SINCE_RE.findall("Since 0.22.0 OTLP has") == ["0.22.0"]
    assert SINCE_RE.findall("Before 0.22.0, OTLP; from 0.22.0 on") == ["0.22.0", "0.22.0"]


def test_version_strings_never_exceed_the_crate_version():
    """'since/from/before X.Y.Z' strings in code and docs must not name a version newer than the
    crate, and the 0.22.0 strings written for this feature must still be present."""
    v = cargo_version()
    found = set()
    for base in ("src", "docs", "logthing.toml", "tests", "deploy/analytics"):
        root = ROOT / base
        files = [root] if root.is_file() else [
            f for f in root.rglob("*")
            if f.is_file() and ".venv" not in f.parts
            and f.suffix in {".rs", ".md", ".toml", ".yml", ".yaml", ".sql", ".py"}
            and f.name != "test_release_pins.py"
        ]
        for f in files:
            for ver in SINCE_RE.findall(f.read_text()):
                found.add(tuple(int(x) for x in ver.split(".")))
    cur = tuple(int(x) for x in v.split("."))
    assert found, "expected at least one 'since X.Y.Z' string"
    assert max(found) <= cur, f"strings reference a version newer than {v}: {sorted(found)}"
    assert max(found) >= FIRST_SHIPPED, f"the {FIRST_SHIPPED} strings vanished: {sorted(found)}"
