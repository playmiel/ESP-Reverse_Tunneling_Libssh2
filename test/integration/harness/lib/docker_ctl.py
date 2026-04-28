"""Thin wrapper around `docker compose` for use in pytest fixtures."""
from __future__ import annotations

import subprocess
from pathlib import Path

COMPOSE_FILE = (
    Path(__file__).resolve().parents[2]
    / "docker"
    / "docker-compose.yml"
)


def _compose(*args: str) -> subprocess.CompletedProcess:
    cmd = ["docker", "compose", "-f", str(COMPOSE_FILE), *args]
    return subprocess.run(cmd, check=True, capture_output=True, text=True)


def up() -> None:
    # --no-recreate keeps existing containers running so we don't drop the
    # ESP32's SSH session between pytest runs. --build is intentionally
    # NOT used here: rebuild manually with `make test-integration-down &&
    # docker compose ... build` if you change a Dockerfile or sshd_config.
    _compose("up", "-d", "--no-recreate")


def down() -> None:
    _compose("down")


def kill(service: str) -> None:
    _compose("kill", service)


def start(service: str) -> None:
    _compose("start", service)


def is_running(service: str) -> bool:
    cp = subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE),
         "ps", "--services", "--filter", "status=running"],
        capture_output=True, text=True)
    return service in cp.stdout.splitlines()
