# Throughput / Integrity / Resilience Test Suite — Design

**Date:** 2026-04-23
**Status:** Approved (pending user re-review of this written spec)
**Scope:** Add a two-layer test suite to detect data drops, throughput regressions, channel leaks, reconnection failures, and circuit-breaker misbehavior in `ESP-Reverse_Tunneling_Libssh2`.

---

## 1. Goal

Give the maintainer (and Claude) a way to **detect "holes"** — silent byte drops, throughput stalls, channel slot leaks, reconnection bugs, and circuit-breaker regressions — that are currently only observable by running the firmware against production traffic and watching logs by eye.

The recent commit history (b92ccee circuit breaker, 2f89e61 channel closure timing, 247f5e8 backpressure, 1edc20a PSRAM corruption, 511148f client queue) shows that the regression-prone areas are **circuit breaker logic, channel lifecycle, EAGAIN/backpressure handling, and the SSH transport pump**. The suite is sized to catch regressions in those areas specifically.

## 2. Non-goals

- ESP32 emulation (QEMU/Wokwi). Rejected because (a) the host-only layer doesn't need an MCU at all and (b) the integration layer needs *real* PSRAM/WiFi/libssh2 timing — emulation would give false confidence.
- Multi-channel saturation stress tests (category E). Out of scope for v1; can be added later if needed.
- Dedicated memory-leak harness (category C). Subsumed by the throughput-stability test, which samples heap/largest-free-block at 1 Hz and asserts on drift.
- Self-hosted GitHub runner with hardware-in-the-loop. Operational cost not justified for a solo-maintained project.
- Refactoring beyond what the tests require (no general "tidy-up" of `ssh_channel.cpp`, no API renames, no rework of the logging layer).

## 3. Test categories in scope

| Code | Category | Why it matters |
|---|---|---|
| **A** | Data integrity (byte-exact echo) | Detects silent drops, channel desync, transport corruption |
| **B** | Throughput stability over time | Detects stalls, slow degradation, heap drift (also covers C as a freebie) |
| **D** | Channel slot leaks | Detects `getActiveChannels()` not returning to 0 after close cycles |
| **F** | Reconnect resilience | Detects double-free, leaks, or stuck states after sshd loss |
| **G** | Backpressure / circuit breaker | Detects regression in the circuit-breaker FSM and slow-consumer handling |

## 4. Architecture overview

Two independent layers:

```
┌────────────────────────────────────────────────────────────────┐
│ Layer 1 — Host-only unit tests (PlatformIO [env:native])        │
│   Pure C++ logic, runs on x86, ~5s, runs in GitHub Actions CI   │
│   Targets: extracted FSMs and helpers                           │
└────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────┐
│ Layer 2 — Integration harness (Python + Docker + real ESP32)    │
│   Real network, real libssh2, real PSRAM. ~10-15 min.           │
│   Manual trigger; not in CI.                                    │
└────────────────────────────────────────────────────────────────┘
```

The two layers are deliberately decoupled: changing one cannot break the other.

## 5. Layer 1 — Host-only unit tests

### 5.1 Refactors required (Phase 1, no behavior change)

Three pure-C++ headers extracted from existing code, each replaceable as a drop-in for the consumers that currently inline the logic:

- **`src/circuit_breaker.h`** — extract `MappingHealth` struct + the four methods (`isMappingBackedOff`, `recordMappingFailure`, `recordMappingSuccess`, `findOrAllocHealth`) currently in `ChannelManager` (`ssh_channel.cpp:466-549`) into a standalone class `CircuitBreaker`. Constants (`MAX_MAPPING_HEALTH`, `FAIL_THRESHOLD`, `BACKOFF_BASE_MS`, `BACKOFF_CAP_MS`) moved to the new header. The existing `LOGF_W` call in `recordMappingFailure` is removed from the FSM and re-added at the call site in `ssh_channel.cpp`: `recordFailure()` returns a `bool` indicating whether this call newly engaged the backoff (i.e., transitioned CLOSED → OPEN), and the caller emits the log line when true. This keeps `circuit_breaker.h` free of any logging dependency. `ChannelManager` gains a `CircuitBreaker breaker_` member; old methods become one-liner forwarders.

- **`src/ssh_config_validators.h`** — extract validation rules currently embedded in `SSHConfiguration::validateSSHConfig`/`validateTunnelConfig`/`validateConnectionConfig` (in `ssh_config.cpp`) into free functions in namespace `ssh_validators`, taking `std::string_view`/`int`. The class methods `validateXxx` keep their signature but delegate. Rules to extract: `isValidPort`, `isValidHostname`, `isValidKeepAlive`, `isValidBufferSize`, `isValidReconnectDelay`, `isValidMaxChannels`, `isPlausibleSshPrivateKey`.

- **`src/prepend_buffer.h`** — extract the prepend buffer logic from `DataRingBuffer` (`ring_buffer.h:30-42, 131-164`) into a templated `PrependBuffer<Cap>` class with `writeToFront`, `read`, `empty`, `pending`. The FreeRTOS-backed ring portion stays inside `DataRingBuffer`. Backing storage uses a plain `uint8_t[Cap]` (no PSRAM allocator dependency — testable host-side).

**Hard rule:** Phase 1 ships as a single isolated commit, "Extract circuit_breaker / validators / prepend_buffer (no behavior change)". Firmware build must be green before Phase 2 starts. The commit must be revert-safe.

### 5.2 PlatformIO config addition

```ini
[env:native]
platform = native
test_framework = unity
build_flags = -std=gnu++17 -Wall -Wextra
```

### 5.3 Test files (Unity framework)

```
test/native/
├── test_circuit_breaker/test_circuit_breaker.cpp
├── test_ssh_config_validators/test_validators.cpp
└── test_prepend_buffer/test_prepend_buffer.cpp
```

### 5.4 Circuit breaker test cases (12, explicit)

1. Initial state: `isBackedOff(port=22080, now=0) == false`
2. Below threshold: 2 failures (THRESHOLD=3) → still not backed off
3. At threshold: 3 failures → `isBackedOff() == true` until `now + BACKOFF_BASE_MS`
4. Backoff expired: `now >= backoffUntilMs` → false
5. Exponential growth: 4 failures → 2× delay; 5 → 4×; capped at `BACKOFF_CAP_MS`
6. Shift exponent cap: 100 failures → no UB, delay stays at `BACKOFF_CAP_MS`
7. Recovery: `recordSuccess(port)` resets `consecutiveFails` and `backoffUntilMs`
8. Multi-port isolation: port 22080 backed off does not affect port 22081
9. Table saturation: 9th distinct port when table full → silently ignored (no crash, no overwrite)
10. `millis()` wrap: `now` overflows uint32 between `recordFailure` and `isBackedOff` → signed-difference comparison still correct
11. Sentinel port: `recordFailure(0, ...)` is a no-op
12. Re-arming: success → 3 fresh failures → backoff re-engages correctly

`test_validators.cpp` covers ~15 cases on the seven validators: boundary values (port 0, 1, 65535, 65536), empty/whitespace-only strings, negative integers, oversized buffer sizes, malformed PEM headers. ASCII hostnames only — the library does not support IDN/Punycode and the tests do not assert on it. `test_prepend_buffer.cpp` covers ~10 cases (empty read, full write, oversized write rejected, partial read across writes, write-when-non-empty rejected, read-after-clear, etc.).

### 5.5 CI integration

`.github/workflows/ci.yml` gains a parallel job:

```yaml
test-native:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-python@v5
    - run: pip install platformio
    - run: pio test -e native
```

Runs in ~30s, blocks PRs on failure.

## 6. Layer 2 — Integration harness

### 6.1 Network topology

WSL2 with mirrored networking, so the WSL host appears as a regular LAN host reachable from the ESP32's WiFi. All Docker containers run on the WSL host. Both the SSH server and the "local target" echo server live on the same Docker host; the ESP32 reaches them at the same IP on different ports.

Fallback if mirrored networking unavailable (Win10 or older Win11): `netsh interface portproxy` script documented in `test/integration/README.md`. Harness code unchanged.

### 6.2 Docker stack (`test/integration/docker/`)

`docker-compose.yml` defines three services:

- **`sshd`** — alpine + openssh-server. Custom `sshd_config` with `AllowTcpForwarding yes`, `GatewayPorts yes`, `MaxSessions 10`. User `testuser` / password `testpass` (test environment only, never production). Exposes ports 22, 22080, 22081, 22082.
- **`echo`** — `socat -d TCP-LISTEN:9000,reuseaddr,fork EXEC:cat`. Port 9000 exposed.
- **`slow_echo`** — Python TCP server, throttled to 1 KB/s, for backpressure test G2. Port 9001 exposed.

### 6.3 Test firmware (`test/integration/firmware/main_test.cpp`)

A variant of `examples/src/main.cpp` with:

- WiFi credentials and Docker host IP injected via build flags (`-DWIFI_SSID="..."`, `-DWIFI_PASS="..."`, `-DDOCKER_HOST_IP="..."`) sourced from environment variables (`TEST_WIFI_SSID`, `TEST_WIFI_PASS`, `TEST_DOCKER_HOST_IP`).
- Three hardcoded mappings:
  - `22080 → DOCKER_HOST_IP:9000` (echo, used by tests A, B, D, F)
  - `22081 → DOCKER_HOST_IP:9001` (slow_echo, used by test G2)
  - `22082 → DOCKER_HOST_IP:65500` (dead port, used by test G1 to trigger circuit breaker)
- `STATS_INTERVAL = 1000` (1 Hz instead of 10 Hz period).
- `reportStats()` rewritten to emit one machine-parsable line per cycle, prefixed `STATS_TEST `, with key=value pairs:
  ```
  STATS_TEST t=12345 state=CONNECTED ch=2 sent=1048576 recv=1048576 dropped=0 heap=180432 minheap=174000 largest=120000 breaker_trips=0
  ```
- No additional firmware logic. The harness drives all behavior over the network.

PlatformIO env addition:
```ini
[env:test_integration]
extends = env:arduino-3
build_src_filter = +<../test/integration/firmware/main_test.cpp> -<main.cpp>
build_flags =
  ${env.build_flags}
  -DWIFI_SSID=\"${sysenv.TEST_WIFI_SSID}\"
  -DWIFI_PASS=\"${sysenv.TEST_WIFI_PASS}\"
  -DDOCKER_HOST_IP=\"${sysenv.TEST_DOCKER_HOST_IP}\"
```

### 6.4 Library mini-addition: `getBreakerTrips()`

To make test G robust against log-format changes, expose an integer counter incremented each time the circuit breaker transitions from CLOSED to OPEN. Surfaced in `STATS_TEST` line as `breaker_trips=N`. Single counter on `ChannelManager` (or `SSHTunnel`), incremented inside `CircuitBreaker::recordFailure` when threshold is first reached. Read-only public getter.

### 6.5 Python harness (`test/integration/harness/`)

```
harness/
├── pyproject.toml            (deps: pytest, paramiko, pyserial)
├── conftest.py               (fixtures)
├── lib/
│   ├── __init__.py
│   ├── serial_stats.py       (StatsMonitor: thread, parses STATS_TEST lines)
│   ├── pattern.py            (deterministic byte-stream generator + verifier)
│   ├── thresholds.py         (named constants for all pass/fail thresholds)
│   └── docker_ctl.py         (compose up/down/kill/start helpers)
├── test_a_data_integrity.py
├── test_b_throughput_stability.py
├── test_d_channel_leaks.py
├── test_f_reconnect.py
└── test_g_backpressure.py
```

**Fixtures (in `conftest.py`):**

| Fixture | Scope | Role |
|---|---|---|
| `docker_stack` | session | `compose up -d` at start, `down` at end |
| `serial_monitor` | session | Background thread reading `/dev/ttyUSB0` 115200, parsing `STATS_TEST` lines, exposing thread-safe latest-snapshot + history |
| `wait_tunnel_ready` | function | Block until ESP32 reports `state=CONNECTED` (timeout 30s) |
| `tunnel_socket(port)` | function | Factory opening TCP to `127.0.0.1:port` (the forwarded port on Docker host) |
| `reset_stats_baseline` | function | Snapshot ESP32 counters at test start for delta measurement |

**`StatsMonitor` API:**
```python
class StatsMonitor:
    def start(self) -> None
    def latest(self) -> dict
    def history(self, since_ms: int | None = None) -> list[dict]
    def wait_for(self, predicate: callable, timeout_s: float) -> dict
    def stop(self) -> None
```

### 6.6 Test scenarios (concrete pass criteria)

| File | Scenario | Pass criteria |
|---|---|---|
| `test_a_data_integrity.py` | Echo of 1 MB, 10 MB, 100 MB; chunk sizes 64 B / 1 KB / 8 KB / 64 KB. Pseudo-random PRNG-seeded data. | 0 byte mismatches; ESP32 `dropped == 0`; sent ≈ recv exactly |
| `test_b_throughput_stability.py` | 5-minute sustained transfer; 1 Hz client + ESP32 sampling | stddev < 30% of mean throughput; no stall window > 3 s with < 1 KB/s; final heap ≥ initial heap − 5 KB |
| `test_d_channel_leaks.py` | 50× (open TCP → 100 KB echo → close), 1 s between cycles | `ch=0` observed between each cycle (sampled from STATS); after 50 cycles, heap ≥ initial − 5 KB |
| `test_f_reconnect.py` | Start 10 MB transfer; at 50% mark `docker compose kill sshd`; +5 s `docker compose start sshd` | ESP32 returns to `state=CONNECTED` within 30 s; no panic in serial output; new transfer succeeds after recovery |
| `test_g_backpressure.py` | G1: 10× open to port 22082 (dead) → assert backoff engages, channel on 22080 unaffected. G2: 1 MB burst on slow_echo (22081) → assert session stable, channel on 22080 reaches normal throughput. | G1: `breaker_trips ≥ 1` after ≥3 failures; concurrent 22080 channel works throughout. G2: 22080 throughput stays within 30% of baseline while slow_echo crawls. |

All thresholds defined as named constants in `lib/thresholds.py` for easy tuning without touching test logic.

### 6.7 Runner — Makefile at project root

```makefile
test-native:
	pio test -e native

test-integration: test-integration-up test-integration-run test-integration-down

test-integration-up:
	docker compose -f test/integration/docker/docker-compose.yml up -d
	@sleep 2

test-integration-run:
	cd test/integration/harness && pytest -v --tb=short

test-integration-down:
	docker compose -f test/integration/docker/docker-compose.yml down

test-integration-quick:
	cd test/integration/harness && pytest -v --tb=short

flash-test:
	pio run -e test_integration -t upload
```

**Typical workflow:**
1. `make flash-test` (once, or after firmware change)
2. `make test-integration` (10-15 min, full cycle)
3. Iterative dev: `make test-integration-up` once, then `make test-integration-quick` repeatedly

## 7. Build sequence (4 phases, each shippable independently)

| Phase | Deliverable | Estimated effort | Independent value |
|---|---|---|---|
| **1. Extraction refactors** | `circuit_breaker.h`, `ssh_config_validators.h`, `prepend_buffer.h` + consumer adaptation. Firmware green, behavior identical. | ~2h | Enables Phase 2; user-invisible |
| **2. Native test layer** | `[env:native]`, Unity tests (3 files), CI job `test-native` | ~3h | First real win: circuit breaker testable in 5s |
| **3. Docker stack + test firmware** | `docker-compose.yml`, sshd/echo/slow_echo, `main_test.cpp`, env `test_integration`, Makefile | ~3h | Infrastructure ready; no scenarios yet |
| **4. Integration scenarios** | 5 `test_*.py` files + `lib/` + `conftest.py` + `getBreakerTrips()` in lib | ~4-6h | Real "find the holes" tests runnable |

Each phase ends with a commit. Phase 1 specifically must be a single revert-safe commit titled "Extract circuit_breaker / validators / prepend_buffer (no behavior change)".

## 8. CI policy

- **In CI (GitHub Actions):** `build` (existing) + `test-native` (new). Both required to merge.
- **Not in CI:** Layer 2 integration harness (requires hardware). Documented in `CONTRIBUTING.md`/PR template: *"If the PR touches `ssh_channel`, `ssh_transport`, or `ssh_session`, run `make test-integration` locally and paste the result summary in the PR description."*

## 9. Risks and mitigations

| Risk | Mitigation |
|---|---|
| WSL2 mirrored networking unavailable on user's Windows version | Fallback documented in `test/integration/README.md`: `netsh interface portproxy` script. Harness code unchanged. |
| `/dev/ttyUSB0` not accessible from WSL | Prerequisites documented: `usbipd-win` configured + `usbipd attach --wsl --busid X-Y`. Harness checks at startup with clear error. |
| Phase 1 refactor breaks subtle behavior (logging order, callback timing) | Phase 1 isolated as single commit; firmware must be flashed and smoke-tested manually before Phase 2 starts. Trivially revertable. |
| `prepend_buffer.h` extraction misses a PSRAM-related behavior | The prepend buffer in current code uses `psramAlloc` for storage but reads/writes are plain `memcpy` on a linear buffer — no PSRAM-specific semantics. Native tests use `new uint8_t[Cap]`. The PSRAM allocation stays in `DataRingBuffer`'s constructor, unchanged. |
| Integration tests flaky due to WiFi/Docker timing | All thresholds in `lib/thresholds.py` (named constants), all timing assertions use `wait_for(predicate, timeout)` not `sleep + assert`. |
| Test G fragile to log format changes | `getBreakerTrips()` counter exposed in `STATS_TEST` makes the assertion structural rather than text-based. |

## 10. File-level summary

```
src/
  circuit_breaker.h            NEW (Phase 1)
  ssh_config_validators.h      NEW (Phase 1)
  prepend_buffer.h             NEW (Phase 1)
  ssh_channel.h/.cpp           MODIFIED (uses CircuitBreaker)
  ssh_config.cpp               MODIFIED (delegates to validators)
  ring_buffer.h                MODIFIED (uses PrependBuffer)
  ssh_tunnel.h/.cpp            MODIFIED (exposes getBreakerTrips)
test/
  native/                      NEW (Phase 2)
    test_circuit_breaker/test_circuit_breaker.cpp
    test_ssh_config_validators/test_validators.cpp
    test_prepend_buffer/test_prepend_buffer.cpp
  integration/                 NEW (Phases 3-4)
    README.md
    docker/
      docker-compose.yml
      sshd/{Dockerfile,sshd_config,authorized_keys}
      slow_echo/{Dockerfile,server.py}
    firmware/main_test.cpp
    harness/
      pyproject.toml
      conftest.py
      lib/{__init__.py,serial_stats.py,pattern.py,thresholds.py,docker_ctl.py}
      test_a_data_integrity.py
      test_b_throughput_stability.py
      test_d_channel_leaks.py
      test_f_reconnect.py
      test_g_backpressure.py
platformio.ini                 MODIFIED (+ [env:native], [env:test_integration])
Makefile                       NEW
.github/workflows/ci.yml       MODIFIED (+ test-native job)
```
