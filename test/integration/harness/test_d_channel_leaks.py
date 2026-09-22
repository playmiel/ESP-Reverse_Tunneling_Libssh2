"""Test D — Channel slot leaks across open/close cycles.

Open a TCP connection through the tunnel, transfer D_CHUNK_BYTES via echo,
close it. Repeat D_CYCLES times. Each payload must be returned byte-for-byte
and the ESP32 must return to ch=0. After the full run, verify heap stability
and that the transport reported no dropped bytes.
"""
from __future__ import annotations

import threading
import time

from lib import thresholds as TH
from lib.pattern import make_stream


def _round_trip(sock, payload: bytes) -> bytes:
    """Threaded send + receive of a fixed-size payload through an open socket.
    Returns received bytes. Mirrors the pattern used by Test A.
    """
    target = len(payload)
    received = bytearray()
    send_errors: list[Exception] = []
    recv_errors: list[Exception] = []

    def _send():
        try:
            sock.sendall(payload)
            try:
                sock.shutdown(1)
            except OSError:
                pass
        except Exception as exc:
            send_errors.append(exc)

    def _recv():
        sock.settimeout(30.0)
        try:
            while len(received) < target:
                buf = sock.recv(min(64 * 1024, target - len(received)))
                if not buf:
                    break
                received.extend(buf)
        except Exception as exc:
            recv_errors.append(exc)

    ts = threading.Thread(target=_send, daemon=True)
    tr = threading.Thread(target=_recv, daemon=True)
    ts.start()
    tr.start()
    ts.join(60.0)
    tr.join(60.0)

    if ts.is_alive() or tr.is_alive():
        raise TimeoutError(
            f"round trip threads did not finish: send_alive={ts.is_alive()} "
            f"recv_alive={tr.is_alive()}")
    if send_errors:
        raise send_errors[0]
    if recv_errors:
        raise recv_errors[0]
    return bytes(received)


def test_channel_no_leak_over_cycles(wait_tunnel_ready, tunnel_socket,
                                      reset_stats_baseline, serial_monitor):
    wait_tunnel_ready()
    baseline = reset_stats_baseline()
    initial_heap = baseline.get("heap", 0)
    payload = make_stream(0xABCD, TH.D_CHUNK_BYTES)

    settled = 0
    leaked_cycle = -1
    for i in range(TH.D_CYCLES):
        sock = tunnel_socket(22080, timeout_s=30.0)
        received = _round_trip(sock, payload)
        sock.close()

        assert len(received) == len(payload), (
            f"cycle {i}: expected {len(payload)} bytes, got {len(received)}")
        assert received == payload, f"cycle {i}: echoed payload differs"

        time.sleep(TH.D_INTER_CYCLE_DELAY_S)

        try:
            serial_monitor.wait_for(lambda s: s.get("ch", 99) == 0,
                                    timeout_s=TH.D_CHANNEL_SETTLE_TIMEOUT_S)
            settled += 1
        except TimeoutError:
            if leaked_cycle < 0:
                leaked_cycle = i
            snap = serial_monitor.latest()
            raise AssertionError(
                f"cycle {i}: ch did not return to 0 within "
                f"{TH.D_CHANNEL_SETTLE_TIMEOUT_S}s "
                f"(last snap: {snap})")

    final = serial_monitor.latest()
    final_heap = final.get("heap", 0)
    heap_drift = initial_heap - final_heap if initial_heap and final_heap else 0
    dropped_delta = final.get("dropped", 0) - baseline.get("dropped", 0)
    print(
        f"[D] settled={settled}/{TH.D_CYCLES} "
        f"heap_drift={heap_drift} bytes dropped={dropped_delta}")

    assert settled == TH.D_CYCLES
    assert dropped_delta == 0, (
        f"ESP32 reports {dropped_delta} bytes dropped during endurance run")
    assert heap_drift <= TH.D_MAX_HEAP_DRIFT_BYTES, (
        f"heap drifted down {heap_drift} > {TH.D_MAX_HEAP_DRIFT_BYTES}")
