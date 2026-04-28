"""Test F — Reconnect after sshd loss mid-transfer.

Start a 10 MB transfer; at ~50% progress kill the sshd container; wait
F_DOWN_S; restart sshd; assert ESP32 returns to Connected within
F_RECONNECT_TIMEOUT_S; verify a new transfer succeeds afterwards;
verify no panic appeared in the serial log.
"""
from __future__ import annotations

import threading
import time

from lib import docker_ctl, thresholds as TH
from lib.pattern import make_stream


def test_reconnect_after_sshd_kill(wait_tunnel_ready, tunnel_socket,
                                    reset_stats_baseline, serial_monitor):
    wait_tunnel_ready()
    baseline = reset_stats_baseline()  # noqa: F841 — captured for telemetry baseline

    payload = make_stream(0x1F1F, TH.F_TRANSFER_BYTES)
    half = int(len(payload) * TH.F_KILL_AT_FRACTION)

    sock = tunnel_socket(22080, timeout_s=60.0)
    half_sent = threading.Event()

    def _send():
        try:
            sock.sendall(payload[:half])
            half_sent.set()
            try:
                sock.sendall(payload[half:])
            except OSError:
                pass
        except OSError:
            half_sent.set()

    threading.Thread(target=_send, daemon=True).start()
    assert half_sent.wait(timeout=60.0), "did not reach 50% of transfer in 60s"

    docker_ctl.kill("sshd")
    time.sleep(TH.F_DOWN_S)
    docker_ctl.start("sshd")

    snap = serial_monitor.wait_for(
        lambda s: s.get("state") == TH.TUNNEL_STATE_CONNECTED,
        timeout_s=TH.F_RECONNECT_TIMEOUT_S)
    print(f"[F] reconnected after sshd kill: {snap}")

    try:
        sock.close()
    except OSError:
        pass

    raw = serial_monitor.raw_log()
    panic_markers = ["Guru Meditation", "abort()", "assertion", "CORRUPT HEAP"]
    panics = [line for line in raw if any(m in line for m in panic_markers)]
    assert not panics, f"panic markers in serial log: {panics[:3]}"

    # New transfer must succeed after reconnect. Wait for ch=0 first so the
    # killed channel has been cleaned up before we open a new one.
    serial_monitor.wait_for(lambda s: s.get("ch", 99) == 0, timeout_s=10.0)
    sock2 = tunnel_socket(22080, timeout_s=10.0)
    sock2.sendall(b"hello-after-reconnect")
    sock2.settimeout(10.0)
    try:
        echoed = sock2.recv(64)
    finally:
        sock2.close()
    assert echoed.startswith(b"hello-after-reconnect"), (
        f"new transfer after reconnect failed: got {echoed!r}")
