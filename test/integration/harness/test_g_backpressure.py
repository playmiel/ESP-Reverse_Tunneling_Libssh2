"""Test G — Circuit breaker (G1) + slow consumer / backpressure (G2).

G1: repeatedly open channels through 22082 (mapped to dead port 65500
on the docker host), assert the ESP32's breaker_trips counter increments
and that a parallel channel on 22080 (live echo) keeps working.

G2: open a sustained burst on 22081 (slow_echo, 1 KB/s) while
simultaneously transferring on 22080; assert 22080's throughput stays
within G2_LIVE_THROUGHPUT_TOLERANCE of its baseline measurement.
"""
from __future__ import annotations

import socket
import threading
import time

from lib import thresholds as TH
from lib.pattern import make_stream


def test_g1_circuit_breaker_engages(wait_tunnel_ready, tunnel_socket,
                                     reset_stats_baseline, serial_monitor):
    wait_tunnel_ready()
    baseline = reset_stats_baseline()
    base_trips = baseline.get("breaker_trips", 0)

    for i in range(TH.G1_ATTEMPTS):
        try:
            s = tunnel_socket(TH.G1_DEAD_PORT_MAPPING, timeout_s=5.0)
            time.sleep(0.5)
            s.close()
        except OSError:
            pass
        time.sleep(0.5)

    time.sleep(3.0)
    final = serial_monitor.latest()
    delta_trips = final.get("breaker_trips", 0) - base_trips
    print(f"[G1] breaker_trips delta after {TH.G1_ATTEMPTS} dead-port "
          f"attempts: {delta_trips}")
    assert delta_trips >= 1, (
        f"breaker did not engage after {TH.G1_ATTEMPTS} attempts; "
        f"trips delta={delta_trips}")

    # Live mapping must still work despite the broken one being in back-off
    serial_monitor.wait_for(lambda s: s.get("ch", 99) == 0, timeout_s=10.0)
    live = tunnel_socket(TH.G1_PARALLEL_LIVE_MAPPING, timeout_s=10.0)
    live.sendall(b"ping-during-breaker")
    live.settimeout(5.0)
    try:
        got = live.recv(64)
    finally:
        live.close()
    assert got.startswith(b"ping-during-breaker"), (
        f"live channel broken while another is in back-off: got {got!r}")


def _measure_throughput(sock, duration_s: float) -> int:
    """Send + receive on `sock` for `duration_s`, return bytes received."""
    sock.settimeout(0.5)
    end = time.monotonic() + duration_s
    recv_total = 0
    chunk = b"X" * 4096
    while time.monotonic() < end:
        try:
            sock.sendall(chunk)
        except OSError:
            break
        try:
            buf = sock.recv(8192)
            if buf:
                recv_total += len(buf)
        except (TimeoutError, OSError):
            continue
    return recv_total


def test_g2_slow_consumer_does_not_starve_others(wait_tunnel_ready,
                                                  tunnel_socket,
                                                  reset_stats_baseline,
                                                  serial_monitor):
    wait_tunnel_ready()

    # Phase 1: baseline throughput on 22080 alone (5s)
    live1 = tunnel_socket(TH.G2_LIVE_MAPPING, timeout_s=30.0)
    baseline_recv = _measure_throughput(live1, 5.0)
    live1.close()
    assert baseline_recv > 0, "no throughput observed on baseline measurement"
    print(f"[G2] baseline 5s recv on 22080: {baseline_recv} bytes")

    serial_monitor.wait_for(lambda s: s.get("ch", 99) == 0, timeout_s=10.0)

    # Phase 2: kick off a slow_echo burst on 22081 in background, re-measure
    # 22080 throughput simultaneously.
    slow = tunnel_socket(TH.G2_SLOW_MAPPING, timeout_s=120.0)

    def _slow_burst():
        try:
            slow.sendall(make_stream(0xBADC, TH.G2_BURST_BYTES))
        except OSError:
            pass

    burst = threading.Thread(target=_slow_burst, daemon=True)
    burst.start()

    live2 = tunnel_socket(TH.G2_LIVE_MAPPING, timeout_s=30.0)
    under_load_recv = _measure_throughput(live2, 5.0)
    live2.close()
    try:
        slow.close()
    except OSError:
        pass

    ratio = under_load_recv / baseline_recv if baseline_recv > 0 else 0
    print(f"[G2] under_load 5s recv on 22080: {under_load_recv} bytes "
          f"(ratio={ratio:.3f})")

    assert ratio >= (1.0 - TH.G2_LIVE_THROUGHPUT_TOLERANCE), (
        f"live channel throughput dropped from {baseline_recv} to "
        f"{under_load_recv} ({ratio:.2%}) while slow_echo was busy; "
        f"tolerance is {TH.G2_LIVE_THROUGHPUT_TOLERANCE:.0%}")
