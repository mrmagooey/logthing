"""Shared helper for integration tests that drive the real compose stack (needs Docker)."""
import os
import shutil
import subprocess
import uuid

import pytest

from conftest import ANALYTICS, generated_env

OVERRIDE = ANALYTICS / "tests" / "integration" / "docker-compose.it.yml"
FILES = ["-f", str(ANALYTICS / "docker-compose.yml"), "-f", str(OVERRIDE)]
# Compose reads interpolation vars from the shell before --env-file, so pass a scrubbed
# environment: a developer's exported vars or deploy/analytics/.env cannot change the stack.
_KEEP = ("PATH", "HOME", "DOCKER_HOST", "DOCKER_CONFIG", "XDG_RUNTIME_DIR")
COMPOSE_ENV = {k: v for k, v in os.environ.items() if k in _KEEP}


def _ok(*cmd):
    try:
        return subprocess.run(cmd, capture_output=True, timeout=60).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def require_docker():
    """Call at module import time: skip the module unless docker and compose work."""
    if not shutil.which("docker"):
        pytest.skip("docker not available", allow_module_level=True)
    if not _ok("docker", "info"):
        pytest.skip("docker daemon not reachable", allow_module_level=True)
    if not _ok("docker", "compose", "version"):
        pytest.skip("docker compose not available", allow_module_level=True)


def has_avx2():
    try:
        return "avx2" in open("/proc/cpuinfo").read().split()
    except OSError:
        return False


def require_trino():
    """Skip when the default Trino 483 image cannot run and no override is given."""
    if not (has_avx2() or os.environ.get("TRINO_IMAGE")):
        pytest.skip("Trino 483 needs AVX2; set TRINO_IMAGE (e.g. trinodb/trino:470)",
                    allow_module_level=True)


class Stack:
    def __init__(self, tmp_dir):
        self.project = f"lt-it-{uuid.uuid4().hex[:8]}"
        self.env = generated_env(tmp_dir / "gen.env")
        if os.environ.get("TRINO_IMAGE"):
            self.env["TRINO_IMAGE"] = os.environ["TRINO_IMAGE"]
        self.envfile = tmp_dir / "stack.env"
        self.envfile.write_text("".join(f"{k}={v}\n" for k, v in self.env.items()))

    def compose(self, *args, timeout=300, check=True, capture=False, input=None):
        return subprocess.run(
            ["docker", "compose", "--env-file", str(self.envfile), "-p", self.project,
             *FILES, *args],
            check=check, env=COMPOSE_ENV, timeout=timeout, capture_output=capture, text=True,
            input=input)

    def port(self, service, container_port):
        out = self.compose("port", service, str(container_port), capture=True).stdout.strip()
        return out.rsplit(":", 1)[1]

    def up(self, *services, timeout=900):
        try:
            self.compose("up", "-d", "--wait", *services, timeout=timeout)
        except BaseException:
            self.compose("logs", "--tail", "100", check=False)
            raise

    def exec(self, service, *cmd, timeout=120, check=True):
        return self.compose("exec", "-T", service, *cmd, timeout=timeout, check=check,
                            capture=True)

    def down(self):
        self.compose("down", "-v", "--remove-orphans", check=False)
