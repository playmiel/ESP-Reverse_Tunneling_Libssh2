"""Test D — Channel slot leaks across open/close cycles.

Open a TCP connection through the tunnel, transfer D_CHUNK_BYTES via echo,
close it. Repeat D_CYCLES times. After each cycle, verify the ESP32
returns to ch=0. After the full run, verify heap has not drifted.
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

    def _send():
        try:
            sock.sendall(payload)
            try:
                sock.shutdown(1)
            except OSError:
                pass
        except OSError:
            pass

    def _recv():
        sock.settimeout(30.0)
        try:
            while len(received) < target:
                buf = sock.recv(min(64 * 1024, target - len(received)))
                if not buf:
                    break
                received.extend(buf)
        except (TimeoutError, OSError):
            pass

    ts = threading.Thread(target=_send, daemon=True)
    tr = threading.Thread(target=_recv, daemon=True)
    ts.start()
    tr.start()
    ts.join(60.0)
    tr.join(60.0)
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

        # Quick sanity check on transfer size; allow some tolerance for the
        # known intermittent byte-loss bug surfaced by Test A. We're testing
        # leaks here, not integrity.
        if abs(len(received) - len(payload)) > len(payload) * 0.01:
            print(f"[D] cycle {i}: only {len(received)}/{len(payload)} bytes — "
                  f"continuing leak check anyway")

        time.sleep(TH.D_INTER_CYCLE_DELAY_S)

        try:
            serial_monitor.wait_for(lambda s: s.get("ch", 99) == 0,
                                    timeout_s=3.0)
            settled += 1
        except TimeoutError:
            if leaked_cycle < 0:
                leaked_cycle = i
            snap = serial_monitor.latest()
            raise AssertionError(
                f"cycle {i}: ch did not return to 0 within 3s "
                f"(last snap: {snap})")

    final_heap = serial_monitor.latest().get("heap", 0)
    heap_drift = initial_heap - final_heap if initial_heap and final_heap else 0
    print(f"[D] settled={settled}/{TH.D_CYCLES} heap_drift={heap_drift} bytes")

    assert settled == TH.D_CYCLES
    assert heap_drift <= TH.D_MAX_HEAP_DRIFT_BYTES, (
        f"heap drifted down {heap_drift} > {TH.D_MAX_HEAP_DRIFT_BYTES}")
