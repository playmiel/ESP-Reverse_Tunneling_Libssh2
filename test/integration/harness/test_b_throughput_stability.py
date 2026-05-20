"""Test B — Sustained throughput stability + heap drift detection.

Stream data through 22080 for B_DURATION_S seconds. Sample throughput at
1 Hz from both the client side and the ESP32's STATS_TEST telemetry.
Detect stalls (windows below B_MIN_STALL_BYTES_PER_S), verify stddev/mean
ratio, and confirm heap does not drift downward by more than
B_MAX_HEAP_DRIFT_BYTES.
"""
from __future__ import annotations

import statistics
import threading
import time

from lib import thresholds as TH


def _continuous_send(sock, stop_event, sent_counter):
    chunk = b"\x55" * 4096
    while not stop_event.is_set():
        try:
            sock.sendall(chunk)
            sent_counter[0] += len(chunk)
        except OSError:
            break


def _continuous_recv(sock, stop_event, recv_counter):
    sock.settimeout(0.5)
    while not stop_event.is_set():
        try:
            buf = sock.recv(8192)
            if not buf:
                break
            recv_counter[0] += len(buf)
        except (TimeoutError, OSError):
            continue


def test_throughput_stability(wait_tunnel_ready, tunnel_socket,
                               reset_stats_baseline, serial_monitor):
    wait_tunnel_ready()
    baseline = reset_stats_baseline()
    initial_heap = baseline.get("heap", 0)

    sock = tunnel_socket(22080, timeout_s=120.0)
    stop = threading.Event()
    sent = [0]
    recv = [0]
    t_send = threading.Thread(target=_continuous_send,
                              args=(sock, stop, sent), daemon=True)
    t_recv = threading.Thread(target=_continuous_recv,
                              args=(sock, stop, recv), daemon=True)
    t_send.start()
    t_recv.start()

    samples = []  # (t_offset_s, recv_bps, heap)
    last_recv = 0
    start = time.monotonic()
    deadline = start + TH.B_DURATION_S
    last_t = start

    while time.monotonic() < deadline:
        time.sleep(1.0 / TH.B_SAMPLE_HZ)
        now = time.monotonic()
        dt = now - last_t
        last_t = now
        delta = recv[0] - last_recv
        last_recv = recv[0]
        bps = delta / dt
        snap = serial_monitor.latest()
        samples.append((now - start, bps, snap.get("heap", 0)))

    stop.set()
    sock.close()
    t_send.join(2.0)
    t_recv.join(2.0)

    # Skip first 5s ramp-up window
    samples = [s for s in samples if s[0] >= 5.0]
    bps_values = [s[1] for s in samples]
    assert bps_values, "no throughput samples collected"

    # Stall detection: any 2-sample average below threshold
    stalls = []
    for i in range(len(samples) - 1):
        win_bps = (samples[i][1] + samples[i + 1][1]) / 2
        if win_bps < TH.B_MIN_STALL_BYTES_PER_S:
            stalls.append(samples[i][0])

    mean_bps = statistics.mean(bps_values)
    stddev = statistics.pstdev(bps_values)
    ratio = stddev / mean_bps if mean_bps > 0 else float("inf")

    final_heap = serial_monitor.latest().get("heap", 0)
    heap_drift = initial_heap - final_heap if initial_heap and final_heap else 0

    print(f"[B] mean={mean_bps:.0f} B/s stddev={stddev:.0f} ratio={ratio:.3f} "
          f"stalls={len(stalls)} heap_drift={heap_drift} bytes")

    assert mean_bps > 0, "no throughput observed"
    assert ratio < TH.B_MAX_STDDEV_RATIO, (
        f"throughput stddev/mean = {ratio:.2f} > {TH.B_MAX_STDDEV_RATIO}")
    assert len(stalls) == 0, (
        f"{len(stalls)} stall windows below "
        f"{TH.B_MIN_STALL_BYTES_PER_S} B/s; first at t={stalls[0]:.1f}s")
    assert heap_drift <= TH.B_MAX_HEAP_DRIFT_BYTES, (
        f"heap drifted down by {heap_drift} bytes > "
        f"{TH.B_MAX_HEAP_DRIFT_BYTES}")
