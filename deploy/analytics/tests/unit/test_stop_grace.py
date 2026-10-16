"""logthing's graceful shutdown can take ~22 s; Docker's 10 s default stop timeout would
SIGKILL it mid-flush, so every compose manifest running it must set stop_grace_period >= 30 s."""
from pathlib import Path

import pytest
import yaml

from conftest import ANALYTICS

ROOT = ANALYTICS.parent.parent


@pytest.mark.parametrize("path", [ROOT / "docker-compose.yml", ANALYTICS / "docker-compose.yml"])
def test_logthing_service_has_stop_grace_period(path: Path):
    svc = yaml.safe_load(path.read_text())["services"]["logthing"]
    grace = str(svc.get("stop_grace_period", ""))
    assert grace.endswith("s") and int(grace[:-1]) >= 30, f"{path}: stop_grace_period={grace!r}"
