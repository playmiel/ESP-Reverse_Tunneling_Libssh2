"""Pytest fixtures for the ESP32 tunnel integration harness."""
from __future__ import annotations

import socket
import time

import pytest

from lib import docker_ctl, thresholds as TH
from lib.serial_stats import StatsMonitor


@pytest.fixture(scope="session", autouse=True)
def _docker_stack():
    docker_ctl.up()
    time.sleep(3)
    yield
    docker_ctl.down()


@pytest.fixture(scope="session")
def serial_monitor():
    sm = StatsMonitor(port=TH.SERIAL_PORT, baud=TH.SERIAL_BAUD)
    sm.start()
    sm.wait_for(lambda s: True, timeout_s=15.0)
    yield sm
    sm.stop()


@pytest.fixture
def wait_tunnel_ready(serial_monitor):
    def _wait():
        return serial_monitor.wait_for(
            lambda s: s.get("state") == TH.TUNNEL_STATE_CONNECTED,
            timeout_s=TH.TUNNEL_READY_TIMEOUT_S)
    return _wait


@pytest.fixture
def tunnel_socket():
    """Factory: open a TCP socket to the forwarded sshd port for `mapping_port`.
    The harness reaches the listener via 127.0.0.1:<port> on the docker host
    (the WSL host with mirrored networking)."""
    sockets = []

    def _open(mapping_port: int, timeout_s: float = 30.0) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout_s)
        s.connect((TH.DOCKER_HOST_FOR_CLIENT, mapping_port))
        sockets.append(s)
        return s

    yield _open

    for s in sockets:
        try:
            s.close()
        except OSError:
            pass


@pytest.fixture
def reset_stats_baseline(serial_monitor):
    """Returns a snapshot dict captured at the moment of the call."""
    def _snapshot():
        return serial_monitor.latest()
    return _snapshot
