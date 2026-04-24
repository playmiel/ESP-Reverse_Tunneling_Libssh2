"""Background reader for STATS_TEST telemetry lines from the ESP32."""
from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

import serial

_STATS_RE = re.compile(rb"STATS_TEST\s+(.*)$")
_KV_RE = re.compile(rb"(\w+)=(\S+)")


def _parse_line(payload: bytes) -> dict:
    out: dict = {}
    for k, v in _KV_RE.findall(payload):
        key = k.decode("ascii")
        sval = v.decode("ascii", errors="replace")
        try:
            out[key] = int(sval)
        except ValueError:
            out[key] = sval
    return out


@dataclass
class StatsMonitor:
    port: str
    baud: int = 115200
    _ser: serial.Serial | None = None
    _thread: threading.Thread | None = None
    _stop: threading.Event = field(default_factory=threading.Event)
    _latest: dict = field(default_factory=dict)
    _history: list[dict] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _raw_log: list[str] = field(default_factory=list)

    def start(self) -> None:
        self._ser = serial.Serial(self.port, self.baud, timeout=0.5)
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2.0)
        if self._ser:
            self._ser.close()

    def latest(self) -> dict:
        with self._lock:
            return dict(self._latest)

    def history(self, since_ms: int | None = None) -> list[dict]:
        with self._lock:
            if since_ms is None:
                return list(self._history)
            return [s for s in self._history if s.get("t", 0) >= since_ms]

    def raw_log(self) -> list[str]:
        with self._lock:
            return list(self._raw_log)

    def wait_for(self, predicate: Callable[[dict], bool], timeout_s: float) -> dict:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            snap = self.latest()
            if snap and predicate(snap):
                return snap
            time.sleep(0.1)
        raise TimeoutError(
            f"predicate not satisfied within {timeout_s}s; last={self.latest()}")

    def _run(self) -> None:
        assert self._ser is not None
        buf = bytearray()
        while not self._stop.is_set():
            try:
                chunk = self._ser.read(256)
            except serial.SerialException:
                break
            if not chunk:
                continue
            buf.extend(chunk)
            while b"\n" in buf:
                line, _, rest = buf.partition(b"\n")
                buf = bytearray(rest)
                with self._lock:
                    self._raw_log.append(line.decode("ascii", errors="replace"))
                m = _STATS_RE.search(line)
                if not m:
                    continue
                parsed = _parse_line(m.group(1))
                with self._lock:
                    self._latest = parsed
                    self._history.append(parsed)
