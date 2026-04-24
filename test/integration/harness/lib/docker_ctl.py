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
    _compose("up", "-d", "--build")


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
