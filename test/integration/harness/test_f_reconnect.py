"""Test F — Reconnect after sshd loss mid-transfer.

Start a 10 MB transfer; at ~50% progress kill the sshd container; wait
F_DOWN_S; restart sshd; assert ESP32 returns to Connected within
F_RECONNECT_TIMEOUT_S; verify a new transfer succeeds afterwards;
verify no panic appeared in the serial log.
"""
from __future__ import annotations

import socket
import threading
import time

from lib import docker_ctl, thresholds as TH
from lib.pattern import make_stream


def _probe_post_reconnect(open_socket_fn, mapping_port, payload,
                          attempts=3, gap_s=5.0, sock_timeout_s=10.0):
    """After a reconnect, sshd may take a few seconds to re-establish the
    tcpip-forward listeners even though the ESP32 reports state=Connected
    and listeners_ready==N. Retry the probe up to `attempts` times.

    Bug #2 in 2026-04-28 baseline report.
    """
    last_err = None
    for i in range(attempts):
        try:
            s = open_socket_fn(mapping_port, timeout_s=sock_timeout_s)
            try:
                s.sendall(payload)
                s.shutdown(socket.SHUT_WR)
                got = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    got += chunk
                if got == payload:
                    return got
                last_err = AssertionError(
                    f"echo mismatch on attempt {i+1}: "
                    f"got {len(got)} of {len(payload)} bytes")
            finally:
                try:
                    s.close()
                except OSError:
                    pass
        except (ConnectionResetError, BrokenPipeError, socket.timeout,
                OSError) as e:
            last_err = e
        if i < attempts - 1:
            time.sleep(gap_s)
    raise AssertionError(
        f"post-reconnect probe failed after {attempts} attempts: {last_err!r}")


def _count_reconnects(monitor) -> int:
    """How many fresh SSH reconnect cycles have completed since boot."""
    return sum(1 for line in monitor.raw_log()
               if "Reconnection successful" in line)


def test_reconnect_after_sshd_kill(wait_tunnel_ready, tunnel_socket,
                                    reset_stats_baseline, serial_monitor):
    wait_tunnel_ready()
    baseline = reset_stats_baseline()  # noqa: F841 — captured for telemetry baseline
    base_reconnects = _count_reconnects(serial_monitor)

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
    # Use recreate (not start) so the new sshd doesn't inherit the killed
    # sshd's listening socket from the same network namespace — Docker
    # `start` on the same container preserves the namespace, causing the
    # next tcpip-forward to fail with "bind: Address in use".
    docker_ctl.recreate("sshd")

    # Wait for a NEW "Reconnection successful" log line. Plain
    # state==Connected isn't enough: it can still reflect the dying
    # session that ESP32 has not yet detected as broken (keepalive
    # cascade is 30 s × 3 strikes ≈ 90 s before reconnect fires).
    deadline = time.monotonic() + TH.F_RECONNECT_TIMEOUT_S
    while time.monotonic() < deadline:
        if _count_reconnects(serial_monitor) > base_reconnects:
            break
        time.sleep(1.0)
    else:
        raise AssertionError(
            f"no fresh 'Reconnection successful' within "
            f"{TH.F_RECONNECT_TIMEOUT_S} s after sshd recreate")
    snap = serial_monitor.latest()
    print(f"[F] reconnected after sshd kill: {snap}")

    try:
        sock.close()
    except OSError:
        pass

    raw = serial_monitor.raw_log()
    panic_markers = ["Guru Meditation", "abort()", "assertion", "CORRUPT HEAP"]
    panics = [line for line in raw if any(m in line for m in panic_markers)]
    assert not panics, f"panic markers in serial log: {panics[:3]}"

    # New transfer must succeed after reconnect. Use the same readiness
    # check as session startup: state=Connected, ch=0, listeners_ready==N.
    # Plain "ch=0 + state=Connected" is not enough — sshd may still be
    # rejecting the new tcpip-forward with "Address in use" (Bug #2),
    # leaving the firmware's `listeners_ready` count below N.
    wait_tunnel_ready()
    probe_payload = b"hello-after-reconnect-%d" % int(time.time())
    _probe_post_reconnect(tunnel_socket, 22080, probe_payload)
