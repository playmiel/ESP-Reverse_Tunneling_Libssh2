"""Test A — Data integrity through the reverse tunnel.

For each (size, chunk_size) combination, send a deterministic byte stream
through 22080 -> echo container -> back, then verify byte-for-byte equality
and that the ESP32 reports zero drops.
"""
from __future__ import annotations

import time

import pytest

from lib import thresholds as TH
from lib.pattern import make_stream, verify_stream


def _send_recv_echo(sock, payload: bytes, chunk: int) -> bytes:
    """Send `payload` in `chunk`-sized writes; receive exactly len(payload) bytes.

    Sender and receiver run on independent threads so a slow consumer side
    cannot starve the sender (and vice versa). This matches real-world
    echo workloads better than interleaved single-threaded read/write,
    which can deadlock when chunk is small and the round-trip latency is
    dominated by SSH framing overhead.
    """
    import threading

    target = len(payload)
    received = bytearray()
    recv_done = threading.Event()
    send_err: list[Exception] = []
    recv_err: list[Exception] = []

    def _send():
        try:
            i = 0
            while i < target:
                end = min(i + chunk, target)
                sock.sendall(payload[i:end])
                i = end
            try:
                sock.shutdown(1)  # half-close: we're done sending
            except OSError:
                pass
        except Exception as e:
            send_err.append(e)

    def _recv():
        try:
            sock.settimeout(60.0)
            while len(received) < target:
                want = min(64 * 1024, target - len(received))
                buf = sock.recv(want)
                if not buf:
                    break
                received.extend(buf)
        except Exception as e:
            recv_err.append(e)
        finally:
            recv_done.set()

    ts = threading.Thread(target=_send, daemon=True)
    tr = threading.Thread(target=_recv, daemon=True)
    ts.start()
    tr.start()
    ts.join(timeout=120.0)
    tr.join(timeout=120.0)

    if send_err:
        raise send_err[0]
    if recv_err:
        raise recv_err[0]
    return bytes(received)


@pytest.mark.parametrize("size", TH.A_TRANSFER_SIZES)
@pytest.mark.parametrize("chunk", TH.A_CHUNK_SIZES)
def test_echo_data_integrity(size, chunk, wait_tunnel_ready, tunnel_socket,
                              reset_stats_baseline, serial_monitor):
    wait_tunnel_ready()
    baseline = reset_stats_baseline()

    payload = make_stream(TH.A_PRNG_SEED, size)
    sock = tunnel_socket(22080, timeout_s=120.0)
    received = _send_recv_echo(sock, payload, chunk)
    sock.close()

    assert len(received) == size, (
        f"expected {size} bytes, got {len(received)}")

    mismatches, first_off = verify_stream(TH.A_PRNG_SEED, received)
    assert mismatches == 0, (
        f"{mismatches} byte mismatches; first at offset {first_off}")

    # Allow ESP32 a moment to update its counters AND fully tear down the
    # channel before the next test opens a new one. Without this delay,
    # subsequent tests intermittently fail with BrokenPipe or empty recv.
    time.sleep(5.0)
    final = serial_monitor.latest()
    dropped_delta = final.get("dropped", 0) - baseline.get("dropped", 0)
    assert dropped_delta == 0, (
        f"ESP32 reports {dropped_delta} bytes dropped during transfer")
