# 2.2.0 Stabilization Release — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close Bugs #1 (small-chunk byte loss / re-bind race), #2 (stale tcpip-forward listeners after reconnect) and #3 (channel teardown latency on high-RTT) plus the integration-harness changes they require, and ship as version 2.2.0.

**Architecture:** Three independent firmware fixes plus a deployment-side sshd config change and harness diagnostics. No public C++ API breakage; one additive read-only accessor (`SSHSession::getActiveListenerCount()`). Test build emits a new `listeners_ready=N` field in `STATS_TEST`.

**Tech Stack:** C++ (firmware, ESP32, Arduino + libssh2), PlatformIO, Unity (host-only tests), Python 3 + pytest + pyserial (integration harness), Docker Compose (sshd / echo / slow_echo containers), OpenSSH server.

**Driving spec:** `docs/superpowers/specs/2026-04-29-stabilization-release-design.md`
**Driving test report:** `docs/superpowers/test-reports/2026-04-28-baseline.md`

---

## Task ordering rationale

Tasks are ordered so each one's validation depends only on prior tasks:

1. **Task 1**: tighten sshd config — independent infra change.
2. **Task 2**: firmware exposes `listeners_ready=N` — needed by harness.
3. **Task 3**: harness consumes `listeners_ready` — needed by Test F.
4. **Task 4**: firmware audit/log on listener-bind rejection — completes Bug #2.
5. **Task 5**: Test F retry — closes Bug #2 validation.
6. **Task 6**: Bug #1 repro tests — must reproduce ≥80% before fixing.
7. **Task 7**: Bug #1 Suspect A fix (slot finalize cooldown) — Unity-testable.
8. **Task 8** (conditional): Bug #1 Suspect B fix (drain gate) — only if Task 7 insufficient.
9. **Task 9**: Bug #3 LAN baseline — gates Task 10.
10. **Task 10** (conditional): Bug #3 fast-path EOF.
11. **Task 11**: version bump + CHANGELOG.
12. **Task 12**: release-gate validation — two consecutive LAN passes.

---

## File structure

| File | Role | Action |
|---|---|---|
| `test/integration/docker/sshd/sshd_config` | Sshd config inside test container | Modify (tighten alives) |
| `src/ssh_session.h` | SSH session class declaration | Modify (add `getActiveListenerCount`) |
| `src/ssh_session.cpp` | SSH session impl | Modify (defensive log on bind) |
| `test/integration/firmware/main_test.cpp` | Test firmware sketch | Modify (emit `listeners_ready`) |
| `test/integration/harness/conftest.py` | Pytest fixtures | Modify (`wait_tunnel_ready` accepts expected count) |
| `test/integration/harness/lib/thresholds.py` | Harness constants | Modify (add `EXPECTED_LISTENER_COUNT`) |
| `test/integration/harness/test_f_reconnect.py` | Test F reconnect harness | Modify (retry post-reconnect probe) |
| `test/integration/harness/test_a_data_integrity.py` | Test A integrity harness | Modify (add repeat parametrizations) |
| `src/ssh_channel.h` | Channel manager declaration | Modify (add `lastFinalizeMs`) |
| `src/ssh_channel.cpp` | Channel manager impl | Modify (cooldown in `allocateSlot`, set field in `finalizeClose`) |
| `test/test_circuit_breaker/...` (Unity host) | Existing host suite | New file `test/test_channel_alloc/test_channel_alloc.cpp` |
| `src/ssh_transport.cpp` | Transport pump impl | Modify if Task 8 / Task 10 trigger |
| `library.json` | PlatformIO manifest | Modify (version 2.1.2 → 2.2.0) |
| `library.properties` | Arduino IDE manifest | Modify (version) |
| `CHANGELOG.md` (create if absent) | Public changelog | Create / append |

---

## Task 1: Tighten sshd `ClientAlive*` in test docker stack

Bug #2 layer A. Sshd reaps zombie sessions in ~30s instead of ~90s, freeing stale `tcpip-forward` listeners before the ESP32's reconnect attempt.

**Files:**
- Modify: `test/integration/docker/sshd/sshd_config`

- [ ] **Step 1.1: Edit `ClientAliveInterval` and `ClientAliveCountMax`**

Find:

```
ClientAliveInterval 30
ClientAliveCountMax 3
```

Replace with:

```
ClientAliveInterval 15
ClientAliveCountMax 2
```

- [ ] **Step 1.2: Rebuild the sshd container so the new config is loaded**

Run:

```bash
docker compose -f test/integration/docker/docker-compose.yml build sshd
docker compose -f test/integration/docker/docker-compose.yml up -d --force-recreate sshd
```

Expected: `tunnel_test_sshd` container is recreated, no error in `docker logs tunnel_test_sshd`.

- [ ] **Step 1.3: Verify config is live in the container**

Run:

```bash
docker exec tunnel_test_sshd grep -E '^ClientAlive' /etc/ssh/sshd_config
```

Expected output:

```
ClientAliveInterval 15
ClientAliveCountMax 2
```

- [ ] **Step 1.4: Commit**

```bash
git add test/integration/docker/sshd/sshd_config
git commit -m "test(docker): tighten sshd ClientAlive to 15s/2 for Bug #2"
```

---

## Task 2: Firmware exposes `listeners_ready=N` in `STATS_TEST`

Bug #2 layer B+C. Adds `int SSHSession::getActiveListenerCount() const` and emits the field in the test firmware's per-second telemetry.

**Files:**
- Modify: `src/ssh_session.h:65-69`
- Modify: `test/integration/firmware/main_test.cpp:95-101`

- [ ] **Step 2.1: Add `getActiveListenerCount()` to `SSHSession`**

In `src/ssh_session.h`, in the public section after `getListeners()` (currently around line 68), add:

```cpp
  // Number of listeners that are currently bound on the remote side.
  // Test/diagnostic only; cheap to call.
  int getActiveListenerCount() const {
    int n = 0;
    for (const auto &e : listeners_) {
      if (e.listener != nullptr) ++n;
    }
    return n;
  }
```

- [ ] **Step 2.2: Expose it via `SSHTunnel`**

In `src/ssh_tunnel.h` add a public inline accessor:

```cpp
  int getActiveListenerCount() const {
    return session_.getActiveListenerCount();
  }
```

(Place it next to `getActiveChannels()`.)

- [ ] **Step 2.3: Update `STATS_TEST` line in test firmware**

In `test/integration/firmware/main_test.cpp`, replace the `Serial.printf(...)` block (currently lines 95-101) with:

```cpp
    Serial.printf(
        "STATS_TEST t=%lu state=%s ch=%d sent=%lu recv=%lu dropped=%lu "
        "heap=%u minheap=%u largest=%u breaker_trips=%lu listeners_ready=%d\n",
        now, tunnel.getStateString().c_str(), tunnel.getActiveChannels(),
        tunnel.getBytesSent(), tunnel.getBytesReceived(),
        tunnel.getBytesDropped(), (unsigned)freeHeap, (unsigned)minHeap,
        (unsigned)largest, tunnel.getBreakerTrips(),
        tunnel.getActiveListenerCount());
```

- [ ] **Step 2.4: Build the test firmware**

Run (from repo root, on Windows-side pio because WSL pio cannot flash):

```bash
/mnt/c/Users/Denis/.platformio/penv/Scripts/pio.exe run -e test_integration
```

Expected: build succeeds, `firmware.bin` produced under `.pio/build/test_integration/`. No new warnings tied to our changes.

- [ ] **Step 2.5: Flash to ESP32 and verify the new field on serial**

Flash:

```bash
~/.local/bin/esptool --chip esp32 --port /dev/ttyUSB1 --baud 460800 \
  --after hard-reset write-flash -z \
  0x1000   .pio/build/test_integration/bootloader.bin \
  0x8000   .pio/build/test_integration/partitions.bin \
  0xe000   /mnt/c/Users/Denis/.platformio/packages/framework-arduinoespressif32/tools/partitions/boot_app0.bin \
  0x10000  .pio/build/test_integration/firmware.bin
```

Then watch the serial briefly:

```bash
timeout 30 cat /dev/ttyUSB1 | grep STATS_TEST | head -5
```

Expected: at least one `STATS_TEST ...` line containing `listeners_ready=3` (or `=0` if not yet connected).

- [ ] **Step 2.6: Commit**

```bash
git add src/ssh_session.h src/ssh_tunnel.h test/integration/firmware/main_test.cpp
git commit -m "feat(stats): expose listeners_ready in STATS_TEST telemetry"
```

---

## Task 3: Harness consumes `listeners_ready` in `wait_tunnel_ready`

Bug #2 harness side. `wait_tunnel_ready` becomes parameterised and asserts the listeners are actually bound, not just `state=Connected ch=0`.

**Files:**
- Modify: `test/integration/harness/lib/thresholds.py`
- Modify: `test/integration/harness/conftest.py:37-48`

- [ ] **Step 3.1: Add `EXPECTED_LISTENER_COUNT` to thresholds**

In `test/integration/harness/lib/thresholds.py`, add (group with the other tunnel-readiness constants):

```python
# Number of reverse-tunnel listeners the test firmware should bind:
# 22080 (echo), 22081 (slow_echo), 22082 (placeholder).
EXPECTED_LISTENER_COUNT = 3
```

- [ ] **Step 3.2: Update `wait_tunnel_ready` to accept and check it**

In `test/integration/harness/conftest.py`, replace the `wait_tunnel_ready` fixture (lines 37-48) with:

```python
@pytest.fixture
def wait_tunnel_ready(serial_monitor):
    def _wait(expected_listeners: int = TH.EXPECTED_LISTENER_COUNT):
        # Wait for: session connected, no leftover active channels from a
        # prior test, AND all reverse-tunnel listeners are bound on sshd.
        # The listeners_ready check guards against the "Connected but
        # zero-forward" state caused by stale tcpip-forward listeners
        # surviving an ESP32 reconnect (see Bug #2 in baseline report).
        return serial_monitor.wait_for(
            lambda s: (s.get("state") == TH.TUNNEL_STATE_CONNECTED
                       and s.get("ch", 99) == 0
                       and s.get("listeners_ready", -1) == expected_listeners),
            timeout_s=TH.TUNNEL_READY_TIMEOUT_S)
    return _wait
```

- [ ] **Step 3.3: Run any existing test that uses `wait_tunnel_ready` to verify it still passes**

Run:

```bash
cd test/integration/harness
python3 -m pytest -v test_a_data_integrity.py::test_echo_data_integrity[8192-1048576] 2>&1 | tail -20
```

Expected: PASS. (The new check is now active; if `listeners_ready` is absent or wrong, this test will time out.)

- [ ] **Step 3.4: Commit**

```bash
git add test/integration/harness/lib/thresholds.py test/integration/harness/conftest.py
git commit -m "test(harness): wait_tunnel_ready asserts listeners_ready==N"
```

---

## Task 4: Audit + log defensive line when listener bind is silently refused

Bug #2 layer B. If sshd refuses a `tcpip-forward` and libssh2 still returns a non-null listener handle, surface that with an explicit error log so future debugging is easier. Also ensure `cancelAllListeners()` runs in every teardown path.

**Files:**
- Modify: `src/ssh_session.cpp:705-735` (around `createListenerForMapping`)
- Modify: `src/ssh_session.cpp:155` and around `disconnect()` if needed

- [ ] **Step 4.1: Read the listener creation site**

Read `src/ssh_session.cpp` lines 700-735 to confirm where `libssh2_channel_forward_listen_ex` is called and how its result is checked. Note the variable names used in your repo (`handle`, `entry`, `bindPort`).

- [ ] **Step 4.2: Add an explicit log when bind returns success but bound port is 0 / mismatched**

After the `handle = libssh2_channel_forward_listen_ex(...)` call (currently line 708), augment the existing success branch so that if `*boundPort != mapping.remoteBindPort`, we log a warning. The exact code (adapt to surrounding variable names if they differ):

```cpp
  int boundPort = 0;
  LIBSSH2_LISTENER *handle = libssh2_channel_forward_listen_ex(
      session_, bindHost, bindPort, &boundPort, /*queue_maxsize*/16);
  if (!handle) {
    char *errmsg = nullptr;
    int errlen = 0;
    libssh2_session_last_error(session_, &errmsg, &errlen, 0);
    LOGF_E("SSH",
           "forward_listen_ex rejected by sshd for port %d (%s) — "
           "likely a stale listener from a previous session. "
           "Check sshd ClientAliveInterval / ClientAliveCountMax.",
           bindPort, errmsg ? errmsg : "no detail");
    return false;
  }
  if (boundPort != bindPort) {
    LOGF_W("SSH",
           "Listener bound on port %d but %d was requested — sshd may have "
           "fallen back to a random port",
           boundPort, bindPort);
  }
  entry.listener = handle;
  entry.boundPort = boundPort;
```

(If your existing code already handles the null-handle path, only add the boundPort mismatch branch.)

- [ ] **Step 4.3: Verify `enterErrorState` reliably calls `cancelAllListeners`**

Read `src/ssh_tunnel.cpp:663-715` (`enterErrorState`). Confirm `session_.disconnect()` (called at line 699) runs before the function exits — `disconnect()` calls `cancelAllListeners()` at line 154. No code change needed, but add a 1-line comment above the `session_.disconnect()` call:

```cpp
  // Closes session; also calls cancelAllListeners() so sshd can release
  // tcpip-forward bindings before the next reconnect attempt (Bug #2).
  session_.disconnect();
```

- [ ] **Step 4.4: Build host tests + integration build to confirm no regression**

```bash
pio test -e native
/mnt/c/Users/Denis/.platformio/penv/Scripts/pio.exe run -e test_integration
```

Expected: Layer 1 still 33/33 PASS, integration build still succeeds.

- [ ] **Step 4.5: Commit**

```bash
git add src/ssh_session.cpp src/ssh_tunnel.cpp
git commit -m "fix(ssh): log listener-bind rejection + comment teardown order (Bug #2)"
```

---

## Task 5: Test F retries the post-reconnect probe up to 3×

Bug #2 closure on the harness side. After the ESP32 reconnects, the `tcpip-forward` listeners may still be settling; the probe must tolerate transient `ConnectionResetError`.

**Files:**
- Modify: `test/integration/harness/test_f_reconnect.py`

- [ ] **Step 5.1: Read the existing test**

Read the full `test_f_reconnect.py`, locate the section that opens a socket to the forwarded port after the reconnect and sends the "hello-after-reconnect" probe. Note the function name and variables.

- [ ] **Step 5.2: Wrap the post-reconnect probe in a retry loop**

Replace the single-shot probe block with:

```python
import time
import socket as _socket

def _probe_post_reconnect(open_socket_fn, mapping_port, payload, attempts=3, gap_s=5.0):
    """After a reconnect, sshd may take a few seconds to re-establish the
    tcpip-forward listeners even though the ESP32 reports state=Connected
    and listeners_ready==N. Retry the probe up to `attempts` times.

    Bug #2 in 2026-04-28 baseline report.
    """
    last_err = None
    for i in range(attempts):
        try:
            s = open_socket_fn(mapping_port)
            try:
                s.sendall(payload)
                s.shutdown(_socket.SHUT_WR)
                got = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    got += chunk
                if got == payload:
                    return got
                last_err = AssertionError(
                    f"echo mismatch on attempt {i+1}: got {len(got)} bytes")
            finally:
                s.close()
        except (ConnectionResetError, BrokenPipeError, _socket.timeout) as e:
            last_err = e
        if i < attempts - 1:
            time.sleep(gap_s)
    raise AssertionError(
        f"post-reconnect probe failed after {attempts} attempts: {last_err}")
```

Then replace the inline probe call in the test body with:

```python
    payload = b"hello-after-reconnect-%d" % int(time.time())
    _probe_post_reconnect(tunnel_socket, TH.ECHO_MAPPING_PORT, payload)
```

- [ ] **Step 5.3: Run Test F**

Pre-condition: docker stack up, ESP32 connected, listeners ready. Then:

```bash
cd test/integration/harness
python3 -m pytest -v test_f_reconnect.py 2>&1 | tail -30
```

Expected: PASS (now tolerant of the listener-settling race).

- [ ] **Step 5.4: Commit**

```bash
git add test/integration/harness/test_f_reconnect.py
git commit -m "test(integration): retry post-reconnect probe ×3 to absorb listener race"
```

---

## Task 6: Add Bug #1 reproduction tests (small chunks, repeated cycles)

Build the failing test that the Task 7 fix has to make pass. The narrowing must reproduce the byte-loss / `BrokenPipe` failure ≥ 80 % of runs before any fix is attempted.

**Files:**
- Modify: `test/integration/harness/test_a_data_integrity.py`

- [ ] **Step 6.1: Read the existing test to find the parametrize and helpers**

Read `test_a_data_integrity.py`. Locate:
- The main test function that takes `(chunk_size, total_bytes)` as a parametrize.
- The PRNG payload generator (xorshift32) and verification helper.

- [ ] **Step 6.2: Add `test_echo_repeat_small` (10× cycles, 1024B chunks, 100KB each)**

Append to `test_a_data_integrity.py`:

```python
import pytest

@pytest.mark.parametrize("chunk_size,total_bytes,cycles", [
    (1024, 100 * 1024, 10),
])
def test_echo_repeat_small(chunk_size, total_bytes, cycles,
                           wait_tunnel_ready, tunnel_socket,
                           reset_stats_baseline, serial_monitor):
    """Bug #1 narrowing: 10 small-chunk transfers back-to-back.
    Each cycle is independent; if any single cycle loses bytes or sees
    BrokenPipe, the test fails with the cycle index. The serial log is
    captured between cycles for diagnostic purposes.
    """
    wait_tunnel_ready()
    failures = []
    for cycle in range(cycles):
        baseline = reset_stats_baseline()
        try:
            _run_one_echo_transfer(tunnel_socket, chunk_size, total_bytes)
        except (AssertionError, ConnectionError, BrokenPipeError) as e:
            failures.append((cycle, repr(e)))
        # capture serial events recorded during this cycle for diagnostics
        # (not asserted on, just attached to the test report on failure)
    assert not failures, (
        f"{len(failures)}/{cycles} cycles failed: {failures}")
```

Replace `_run_one_echo_transfer` with whatever helper your existing test uses internally; if the parametrized test currently inlines the transfer, extract it into a module-level helper that takes `(open_socket_fn, chunk_size, total_bytes)` and reuse it from both the existing test and the new repeat tests. Show the extracted helper in this same commit.

- [ ] **Step 6.3: Add `test_echo_repeat_mid` (5× cycles, 256B chunks, 1MB each)**

Append immediately after Step 6.2:

```python
@pytest.mark.parametrize("chunk_size,total_bytes,cycles", [
    (256, 1 * 1024 * 1024, 5),
])
def test_echo_repeat_mid(chunk_size, total_bytes, cycles,
                         wait_tunnel_ready, tunnel_socket,
                         reset_stats_baseline, serial_monitor):
    """Bug #1 narrowing: 5 medium-volume transfers at 256B chunks.
    Same structure as test_echo_repeat_small but pushes more total volume
    through the small-chunk code path."""
    wait_tunnel_ready()
    failures = []
    for cycle in range(cycles):
        try:
            _run_one_echo_transfer(tunnel_socket, chunk_size, total_bytes)
        except (AssertionError, ConnectionError, BrokenPipeError) as e:
            failures.append((cycle, repr(e)))
    assert not failures, (
        f"{len(failures)}/{cycles} cycles failed: {failures}")
```

- [ ] **Step 6.4: Run the new tests on current (unfixed) firmware**

```bash
cd test/integration/harness
python3 -m pytest -v -k "test_echo_repeat" --tb=short 2>&1 | tail -40
```

Expected: at least one of the two new tests **fails** (this is the repro). Record which cycle fails and why in your local notes for Task 7. If neither fails after 3 runs, the bug is not reliably reproducing — **stop and re-evaluate** before doing Task 7.

- [ ] **Step 6.5: Commit**

```bash
git add test/integration/harness/test_a_data_integrity.py
git commit -m "test(integration): add small-chunk repeat tests for Bug #1 narrowing"
```

---

## Task 7: Bug #1 fix — slot-finalize cooldown in `ChannelManager::allocateSlot`

Suspect A from the spec. Add `unsigned long lastFinalizeMs` to `ChannelSlot`, set it in `finalizeClose`, refuse to recycle slots within 50ms of finalize. This is Unity-testable on the host.

**Files:**
- Modify: `src/ssh_channel.h` (struct `ChannelSlot`)
- Modify: `src/ssh_channel.cpp` (`allocateSlot`, `finalizeClose`, `resetSlot`)
- Create: `test/test_channel_alloc/test_channel_alloc.cpp`
- Create: `test/test_channel_alloc/test_main.cpp` (Unity entrypoint, mirror existing test dir style)

- [ ] **Step 7.1: Read existing host-test layout**

Read `test/test_circuit_breaker/` (one of the existing host suites, see its `test_main.cpp` and `test_*.cpp`). Mirror the structure for the new suite — same Unity entrypoint pattern, same naming style. Note the `pio test -e native -f test_circuit_breaker` filter command syntax.

- [ ] **Step 7.2: Write failing host test**

Create `test/test_channel_alloc/test_main.cpp` with the standard Unity boilerplate (mirror `test/test_circuit_breaker/test_main.cpp`).

Create `test/test_channel_alloc/test_channel_alloc.cpp`:

```cpp
#include <unity.h>
#include "../../src/ssh_channel.h"

// Stand-in for millis() that the test can advance manually.
static unsigned long g_now_ms = 1000;
extern "C" unsigned long millis() { return g_now_ms; }

void test_allocate_skips_slot_within_finalize_cooldown(void) {
    ChannelManager mgr;
    TEST_ASSERT_TRUE(mgr.init(/*maxChannels*/2, /*ringBufferSize*/8192));

    // Manually mark slot 0 as just-finalized (active=false but
    // lastFinalizeMs = now). allocateSlot must refuse it.
    auto &slot0 = mgr.getSlot(0);
    slot0.active = false;
    slot0.lastFinalizeMs = g_now_ms; // just finalized

    // Within cooldown window: slot 0 must not be returned; slot 1 yes.
    int s = mgr.allocateSlot();
    TEST_ASSERT_EQUAL_INT(1, s);

    // Advance past 50 ms cooldown: slot 0 becomes available again.
    g_now_ms += 60;
    auto &slot1 = mgr.getSlot(1);
    slot1.active = false; // free slot 1 too so the allocator must pick 0 or 1
    slot1.lastFinalizeMs = 0;

    s = mgr.allocateSlot();
    TEST_ASSERT_TRUE(s == 0 || s == 1);
}

void setUp(void) { g_now_ms = 1000; }
void tearDown(void) {}
```

- [ ] **Step 7.3: Run the test, observe it fails (compile error or assertion)**

```bash
pio test -e native -f test_channel_alloc 2>&1 | tail -20
```

Expected: FAIL — either a compile error (`lastFinalizeMs` not a member of `ChannelSlot`) or an assertion failure once the field is added but the cooldown logic isn't yet there.

- [ ] **Step 7.4: Add `lastFinalizeMs` to `ChannelSlot` and reset it**

In `src/ssh_channel.h`, find the `ChannelSlot` struct and add:

```cpp
  unsigned long lastFinalizeMs = 0; // millis() of last finalizeClose, 0 if never
```

In `src/ssh_channel.cpp::resetSlot` (around line 452), do **not** reset `lastFinalizeMs` — keep its value across resets so the cooldown survives the slot reuse. (Initialize to 0 in the field default; that's enough.)

- [ ] **Step 7.5: Set `lastFinalizeMs` in `finalizeClose`**

In `src/ssh_channel.cpp::finalizeClose` (around line 282-287), just before `slot.state = ChannelSlot::State::Closed;`, add:

```cpp
  slot.lastFinalizeMs = millis();
```

- [ ] **Step 7.6: Apply cooldown gate in `allocateSlot`**

In `src/ssh_channel.cpp::allocateSlot` (around line 80-84), modify the inactive-slot loop:

```cpp
  // First pass: find inactive slot, but skip slots that were finalized
  // within the last 50 ms — libssh2 may not have fully released the
  // channel yet, and reusing the slot can race with in-flight bytes
  // (see Bug #1 in 2026-04-28 baseline report).
  static constexpr unsigned long FINALIZE_COOLDOWN_MS = 50;
  unsigned long now = millis();
  for (int i = 0; i < maxSlots_; ++i) {
    if (!slots_[i].active) {
      if (slots_[i].lastFinalizeMs != 0 &&
          (now - slots_[i].lastFinalizeMs) < FINALIZE_COOLDOWN_MS) {
        continue;
      }
      LOGF_D("SSH", "Channel slot %d selected (inactive)", i);
      return i;
    }
  }
```

(The existing second pass — recycle stale active slot at 30s — is unchanged.)

- [ ] **Step 7.7: Run the host test, expect PASS**

```bash
pio test -e native -f test_channel_alloc 2>&1 | tail -10
```

Expected: PASS. Also re-run the full host suite to confirm no regression:

```bash
pio test -e native 2>&1 | tail -10
```

Expected: 34/34 PASS (the 33 existing + 1 new).

- [ ] **Step 7.8: Build + flash test firmware, then re-run the Bug #1 narrowing tests**

Build:

```bash
/mnt/c/Users/Denis/.platformio/penv/Scripts/pio.exe run -e test_integration
```

Flash (same command as Task 2.5).

Then run:

```bash
cd test/integration/harness
python3 -m pytest -v -k "test_echo_repeat" --tb=short 2>&1 | tail -30
```

Expected: PASS for both `test_echo_repeat_small` and `test_echo_repeat_mid`. If still failing, **proceed to Task 8** (Suspect B). If passing, mark Task 8 as not needed and proceed to Task 9.

- [ ] **Step 7.9: Commit**

```bash
git add src/ssh_channel.h src/ssh_channel.cpp test/test_channel_alloc/
git commit -m "fix(channel): 50ms cooldown after finalizeClose to prevent re-bind race (Bug #1)"
```

---

## Task 8 (conditional — only if Task 7.8 still fails): Drain-gate `Open → Draining`

Suspect B from the spec. Refuse to transition a slot to `Draining` while `toRemote` ring still has bytes or a libssh2 write is pending.

**Files:**
- Modify: `src/ssh_transport.cpp` (`drainLocalToSsh` and / or the `transitionToDraining` site near l.476-510)

- [ ] **Step 8.1: Read the current transition logic**

Read `src/ssh_transport.cpp` lines 460-560. Locate the `Open → Draining` transition. Note whether there is already an `sshWritePending` flag (or equivalent — the slot tracks `eagainCount`, `firstEagainMs`, `firstLocalSendEagainMs`).

- [ ] **Step 8.2: Identify the precise transition site to gate**

In `drainLocalToSsh` you should find a block like:

```cpp
    if (local_recv_returned_zero || local_recv_error) {
      // ... transition to Draining
      slot.state = ChannelSlot::State::Draining;
      ...
    }
```

Replace it with:

```cpp
    if (local_recv_returned_zero || local_recv_error) {
      // Bug #1 Suspect B guard: don't transition to Draining while
      // toRemote still has buffered bytes the SSH side hasn't accepted
      // yet, OR while a libssh2 write is in EAGAIN limbo. Otherwise
      // those tail bytes die when the slot is finalized.
      bool sshWritePending = slot.firstLocalSendEagainMs != 0;
      bool ringNotDrained = slot.toRemote && slot.toRemote->size() > 0;
      if (sshWritePending || ringNotDrained) {
        // Keep the slot in Open this tick; the transport pump will be
        // re-entered next loop iteration and will retry the SSH write.
        // The half-close timeout (existing safety net) still applies.
        continue;
      }
      slot.state = ChannelSlot::State::Draining;
      ...
    }
```

(Replace `continue` with the appropriate flow-control statement for the loop you're inside; if the surrounding code uses `goto`, follow the existing convention. Read first before editing.)

- [ ] **Step 8.3: Build firmware**

```bash
/mnt/c/Users/Denis/.platformio/penv/Scripts/pio.exe run -e test_integration
```

Expected: builds without warnings tied to the change.

- [ ] **Step 8.4: Flash and re-run Bug #1 narrowing tests**

(Same flash + pytest commands as Task 7.8.)

Expected: both `test_echo_repeat_small` and `test_echo_repeat_mid` PASS. If still failing, **stop here and re-investigate** — the spec calls Suspect C (ring-buffer pool) only as a last-resort path and warns it's a larger refactor.

- [ ] **Step 8.5: Commit**

```bash
git add src/ssh_transport.cpp
git commit -m "fix(transport): gate Open→Draining on empty ring + no SSH-write EAGAIN (Bug #1)"
```

---

## Task 9: Bug #3 LAN baseline — gate decision

Re-run Test D on stable LAN to determine whether the high-RTT teardown latency is environmental or a real code bug.

**Files:**
- No code changes. Pure measurement.

- [ ] **Step 9.1: Confirm LAN environment**

Verify (no command, just check):
- ESP32 is on the home Wi-Fi (not a phone hotspot).
- WSL host IP is in 192.168.0.x range and reachable from the ESP32.
- `TEST_DOCKER_HOST_IP` env var matches that IP.
- `TEST_WIFI_SSID` / `TEST_WIFI_PASS` are home-network credentials.
- Test firmware was built with these env vars (PIO env vars need `WSLENV` forwarding when building from WSL).

- [ ] **Step 9.2: Hard-restart sshd to clear any stale state**

```bash
docker kill tunnel_test_sshd
docker start tunnel_test_sshd
```

Wait for ESP32 to reconnect:

```bash
timeout 60 cat /dev/ttyUSB1 | grep -m1 "Reverse listener ready 22082"
```

Expected: line appears within 60 s.

- [ ] **Step 9.3: Run Test D and capture the ch=0 timing**

```bash
cd test/integration/harness
python3 -m pytest -v test_d_channel_leaks.py --tb=short 2>&1 | tee /tmp/test_d_lan.log
```

Capture from `/tmp/test_d_lan.log` (or the test's own assertion message) the time elapsed between `sock.close()` and `ch=0` being observed in `STATS_TEST`.

- [ ] **Step 9.4: Decision**

| Observation | Action |
|---|---|
| ch returns to 0 in < 3 s on LAN | **Skip Task 10**; document in CHANGELOG: "Bug #3 is environmental (high-RTT only); harness threshold may be relaxed for hotspot envs." |
| ch returns to 0 in ≥ 3 s on LAN | **Proceed to Task 10**. |

- [ ] **Step 9.5: Commit (decision record)**

If Task 10 is skipped:

```bash
git commit --allow-empty -m "test(d): LAN baseline shows ch returns to 0 in <3s — Bug #3 is environmental"
```

If Task 10 will run:

```bash
git commit --allow-empty -m "test(d): LAN baseline confirms ch teardown >3s — proceed with fast-path fix"
```

---

## Task 10 (conditional — only if Task 9 says proceed): Fast-path EOF in idle close

**Files:**
- Modify: `src/ssh_transport.cpp` (the EOF + grace step around l.594-626)

- [ ] **Step 10.1: Read the current EOF/grace logic**

Read `src/ssh_transport.cpp` lines 480-630. Find the step labelled "Step 2a: Send EOF + pump transport for channels whose rings are empty" and the subsequent grace check `(now - ch.eofSentMs) >= EOF_GRACE_MS`.

- [ ] **Step 10.2: Add a fast-path**

Just before the existing EOF-send line in step 2a, insert:

```cpp
      // Fast-path (Bug #3): when the channel is fully idle — rings empty,
      // no libssh2 EAGAIN pending, and no bytes in either direction for
      // >100 ms — finalize directly without the 200ms EOF_GRACE_MS wait.
      // Only the truly-idle close path is short-circuited; in-flight
      // closes still get the full grace period.
      bool sshWriteIdle = slot.firstLocalSendEagainMs == 0;
      bool noRecentTraffic =
          (now - slot.lastSuccessfulWrite) > 100 &&
          (now - slot.lastSuccessfulRead) > 100;
      bool ringsEmpty = slot.toLocal && slot.toRemote &&
                        slot.toLocal->size() == 0 &&
                        slot.toRemote->size() == 0;
      if (ringsEmpty && sshWriteIdle && noRecentTraffic) {
        LOGF_I("SSH", "Channel %d: idle close fast-path", i);
        // Send EOF, then immediately finalize without grace.
        libssh2_channel_send_eof(slot.sshChannel);
        // Mark for finalize on next loop tick (caller already handles this
        // path through finalizeClose — set eofSentMs in the past so the
        // grace check passes).
        slot.eofSentMs = now - EOF_GRACE_MS - 1;
        continue;
      }
```

(Adjust the surrounding control flow / `continue` target to fit the actual loop. Read first.)

- [ ] **Step 10.3: Build firmware**

```bash
/mnt/c/Users/Denis/.platformio/penv/Scripts/pio.exe run -e test_integration
```

- [ ] **Step 10.4: Flash and re-run Test D**

(Flash command as Task 2.5.)

```bash
cd test/integration/harness
python3 -m pytest -v test_d_channel_leaks.py --tb=short 2>&1 | tail -20
```

Expected: PASS on LAN with ch returning to 0 in < 1 s.

- [ ] **Step 10.5: Re-run Test A to confirm no throughput regression**

```bash
cd test/integration/harness
python3 -m pytest -v test_a_data_integrity.py::test_echo_data_integrity[8192-1048576] 2>&1 | tail -15
```

Expected: PASS. If throughput dropped, the fast-path is firing inside an active transfer and the `noRecentTraffic` guard needs tightening — investigate before continuing.

- [ ] **Step 10.6: Commit**

```bash
git add src/ssh_transport.cpp
git commit -m "fix(transport): fast-path EOF on idle close to cut teardown latency (Bug #3)"
```

---

## Task 11: Version bump 2.1.2 → 2.2.0 + CHANGELOG entry

**Files:**
- Modify: `library.json`
- Modify: `library.properties`
- Create or modify: `CHANGELOG.md`

- [ ] **Step 11.1: Bump version in `library.json`**

In `library.json`, change:

```
"version": "2.1.2",
```

to:

```
"version": "2.2.0",
```

- [ ] **Step 11.2: Bump version in `library.properties`**

In `library.properties`, change:

```
version=2.1.2
```

to:

```
version=2.2.0
```

- [ ] **Step 11.3: Add CHANGELOG entry**

If `CHANGELOG.md` exists at repo root, prepend the new section. Otherwise create it with:

```markdown
# Changelog

## 2.2.0 — Stabilization

### Fixes
- Channel re-allocation race causing small-chunk byte loss when transfers
  use chunks <= 1 KB or when sessions are torn down and re-opened
  back-to-back (Bug #1 in 2026-04-28 baseline report).
- Stale `tcpip-forward` listeners survived ESP32 reconnects, leaving the
  tunnel in a "Connected but zero-forward" state. Requires sshd-side
  `ClientAliveInterval` to be fully effective (Bug #2).
- Channel teardown latency on high-RTT links: fast-path EOF when no data
  is in flight cuts close time from up to 20s to <1s (Bug #3).
  *(Skipped if Task 9 LAN baseline showed the bug is environmental.)*

### Additions
- `SSHTunnel::getActiveListenerCount()` and `SSHSession::getActiveListenerCount()`
  for diagnostics.
- `STATS_TEST` test telemetry now reports `listeners_ready=N` (test build only).

### Deployment notes
- Recommend setting `ClientAliveInterval 15` and `ClientAliveCountMax 2`
  on your sshd. The library cannot release listeners on a network-killed
  session by itself; sshd needs to reap zombies for the next reconnect to
  succeed.
```

If Task 10 was skipped because of the Task 9 gate, **remove the Bug #3 bullet from "Fixes"** and add it to a new section:

```markdown
### Diagnostics & docs
- Bug #3 (high-RTT teardown latency) confirmed environmental via LAN
  baseline; no code change shipped. Harness thresholds may be relaxed
  for high-RTT environments.
```

- [ ] **Step 11.4: Verify host tests still green**

```bash
pio test -e native 2>&1 | tail -10
```

Expected: 34/34 PASS (or 33/33 if Task 7's Unity test was not added — should not happen).

- [ ] **Step 11.5: Commit**

```bash
git add library.json library.properties CHANGELOG.md
git commit -m "chore(release): bump to 2.2.0 + CHANGELOG"
```

---

## Task 12: Release-gate validation — two consecutive LAN runs

The release ships only after a clean run is reproduced.

**Files:**
- No code changes.

- [ ] **Step 12.1: First run — clean state, full Layer 2 suite**

```bash
docker kill tunnel_test_sshd && docker start tunnel_test_sshd
# wait for the 3 "Reverse listener ready" lines on serial
cd test/integration/harness
python3 -m pytest -v \
    test_g_backpressure.py \
    test_a_data_integrity.py \
    test_d_channel_leaks.py \
    test_f_reconnect.py \
    test_b_throughput_stability.py \
    --tb=short 2>&1 | tee /tmp/release_run1.log
```

Expected: all green. Note the run-1 timing.

- [ ] **Step 12.2: Second run — fresh sshd + same suite**

```bash
docker kill tunnel_test_sshd && docker start tunnel_test_sshd
# wait for listeners again
cd test/integration/harness
python3 -m pytest -v \
    test_g_backpressure.py \
    test_a_data_integrity.py \
    test_d_channel_leaks.py \
    test_f_reconnect.py \
    test_b_throughput_stability.py \
    --tb=short 2>&1 | tee /tmp/release_run2.log
```

Expected: all green.

- [ ] **Step 12.3: Update the test report with the LAN results**

In `docs/superpowers/test-reports/`, create `2026-04-29-release-2.2.0.md` (or similar) summarizing: which tests ran, results from both runs, any notable LAN-specific observations.

- [ ] **Step 12.4: Tag the release**

If both runs are green:

```bash
git tag -a v2.2.0 -m "v2.2.0 stabilization release"
```

If either run failed: **do not tag**. Investigate the failure, file a follow-up plan if needed.

- [ ] **Step 12.5: Final commit (test report)**

```bash
git add -f docs/superpowers/test-reports/2026-04-29-release-2.2.0.md
git commit -m "docs(test-reports): record 2.2.0 release validation runs"
```

---

## Self-review checklist (run before considering the plan done)

- [ ] Spec section "Bug #2" → Task 1 (sshd config) + Task 2 (firmware stats) + Task 3 (harness wait) + Task 4 (defensive log) + Task 5 (Test F retry). ✅
- [ ] Spec section "Bug #1" → Task 6 (repro) + Task 7 (Suspect A) + Task 8 (Suspect B conditional). ✅
- [ ] Spec section "Bug #3" → Task 9 (gate) + Task 10 (conditional fix). ✅
- [ ] Spec section "Testing strategy" → Task 12 (two consecutive LAN runs). ✅
- [ ] Spec section "Versioning" → Task 11 (bump + CHANGELOG). ✅
- [ ] No "TBD" / "TODO" / "implement later" markers in steps.
- [ ] Type names consistent: `lastFinalizeMs` used in both Task 7.4, 7.5, 7.6 and the test (Task 7.2). `listeners_ready` used in Task 2.3, Task 3.1, Task 3.2.
- [ ] Helper `_run_one_echo_transfer` referenced in Task 6.2/6.3 — engineer is told in 6.2 to extract it from the existing test before reuse.
- [ ] Conditional tasks (8 and 10) explicitly state their entry condition so they're not run unconditionally.
