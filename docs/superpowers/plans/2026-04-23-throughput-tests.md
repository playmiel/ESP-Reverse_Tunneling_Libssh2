# Throughput / Integrity / Resilience Test Suite — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a two-layer test suite (host-only Unity tests + Python integration harness driving real ESP32) that detects byte drops, throughput stalls, channel slot leaks, reconnection bugs, and circuit-breaker regressions in `ESP-Reverse_Tunneling_Libssh2`.

**Architecture:** Layer 1 is `[env:native]` PlatformIO running Unity tests against three extracted pure-C++ headers (`circuit_breaker.h`, `ssh_config_validators.h`, `prepend_buffer.h`). Layer 2 is a Python pytest harness that drives a real ESP32 (test firmware) talking to a local Docker stack (sshd + echo + slow_echo containers), parsing serial telemetry to compare client-side and device-side behavior.

**Tech Stack:** C++17, PlatformIO, Unity (test framework), Arduino-ESP32, Docker Compose, Python 3.11+, pytest, pyserial. Spec reference: `docs/superpowers/specs/2026-04-23-throughput-tests-design.md`.

---

## Conventions used in every task

- **TDD order**: write failing test first, run it to confirm failure, write minimal impl, run to confirm pass, commit.
- **Refactor tasks** (Phase 1) follow the same TDD order: tests for the *extracted* unit are written before the extraction, against the future class signature, so the test compile-fails until extraction exists.
- **No `--no-verify`** on commits; the existing `clang-format`/`codespell` lint job in CI must stay green.
- **Commit messages**: present-tense imperative, ≤72 chars on the subject line, optional body.

## File structure (all paths absolute from repo root)

```
src/
  circuit_breaker.h            NEW (Task 2)
  ssh_config_validators.h      NEW (Task 3)
  prepend_buffer.h             NEW (Task 4)
  ssh_channel.h                MODIFIED (Task 2, Task 7)
  ssh_channel.cpp              MODIFIED (Task 2, Task 7)
  ssh_config.cpp               MODIFIED (Task 3)
  ring_buffer.h                MODIFIED (Task 4)
  ssh_tunnel.h                 MODIFIED (Task 7 — getBreakerTrips)
  ssh_tunnel.cpp               MODIFIED (Task 7 — getBreakerTrips)
test/
  native/                      NEW (Tasks 1, 2, 3, 4)
    test_circuit_breaker/test_circuit_breaker.cpp
    test_ssh_config_validators/test_validators.cpp
    test_prepend_buffer/test_prepend_buffer.cpp
  integration/                 NEW (Tasks 6-13)
    README.md
    docker/
      docker-compose.yml
      sshd/{Dockerfile,sshd_config}
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
platformio.ini                 MODIFIED (Tasks 1, 7)
Makefile                       NEW (Task 6)
.github/workflows/ci.yml       MODIFIED (Task 5)
```

---

## Task 1: Bootstrap native test environment

**Files:**
- Modify: `platformio.ini` (add `[env:native]`)
- Create: `test/native/test_smoke/test_smoke.cpp`

- [ ] **Step 1.1: Add `[env:native]` to platformio.ini**

Append to `platformio.ini` (after the existing `[env:arduino-rc]` block):

```ini
[env:native]
platform = native
test_framework = unity
build_flags =
  -std=gnu++17
  -Wall
  -Wextra
  -DUNIT_TEST
test_build_src = no
```

- [ ] **Step 1.2: Create directory structure**

```bash
mkdir -p test/native/test_smoke
```

- [ ] **Step 1.3: Write smoke test that validates the toolchain**

Create `test/native/test_smoke/test_smoke.cpp`:

```cpp
#include <unity.h>

void setUp(void) {}
void tearDown(void) {}

void test_unity_runs(void) {
    TEST_ASSERT_EQUAL_INT(2, 1 + 1);
}

int main(int, char **) {
    UNITY_BEGIN();
    RUN_TEST(test_unity_runs);
    return UNITY_END();
}
```

- [ ] **Step 1.4: Run the smoke test**

Run: `pio test -e native -f test_smoke -v`

Expected output (last lines):
```
test/native/test_smoke/test_smoke.cpp:8: test_unity_runs: PASS

-----------------------
1 Tests 0 Failures 0 Ignored
OK
```

If you get a compilation error mentioning `Arduino.h` or `freertos/...`, the `test_build_src = no` line in `platformio.ini` is missing or the test platform did not pick it up — re-check Step 1.1.

- [ ] **Step 1.5: Commit**

```bash
git add platformio.ini test/native/test_smoke/test_smoke.cpp
git commit -m "test(native): bootstrap [env:native] with Unity smoke test"
```

---

## Task 2: Extract `CircuitBreaker` with TDD

**Files:**
- Create: `src/circuit_breaker.h`
- Create: `test/native/test_circuit_breaker/test_circuit_breaker.cpp`
- Modify: `src/ssh_channel.h` (lines 67-73, 132-145, 152-157)
- Modify: `src/ssh_channel.cpp` (lines 466-549, plus call sites)

- [ ] **Step 2.1: Create `src/circuit_breaker.h` with declarations only**

```cpp
#ifndef CIRCUIT_BREAKER_H
#define CIRCUIT_BREAKER_H

#include <cstddef>
#include <cstdint>

// Per-mapping circuit breaker. Tracks consecutive local-endpoint connect
// failures keyed by remoteBindPort, applies exponential back-off above a
// threshold. Pure C++; no Arduino, FreeRTOS, or logging dependency.
class CircuitBreaker {
public:
    static constexpr int MAX_MAPPING_HEALTH = 8;
    static constexpr uint16_t FAIL_THRESHOLD = 3;
    static constexpr unsigned long BACKOFF_BASE_MS = 1000;
    static constexpr unsigned long BACKOFF_CAP_MS = 60000;

    struct MappingHealth {
        int remoteBindPort = 0;        // 0 = entry unused
        uint16_t consecutiveFails = 0;
        unsigned long backoffUntilMs = 0;
    };

    bool isBackedOff(int port, unsigned long now) const;

    // Returns true iff this call newly engaged the back-off
    // (CLOSED -> OPEN transition). Caller is responsible for logging.
    bool recordFailure(int port, unsigned long now);

    void recordSuccess(int port);

    // Test-only introspection.
    const MappingHealth* peek(int port) const;

    // Total number of CLOSED -> OPEN transitions since construction.
    unsigned long totalTrips() const { return totalTrips_; }

private:
    MappingHealth health_[MAX_MAPPING_HEALTH] = {};
    unsigned long totalTrips_ = 0;

    MappingHealth* findOrAlloc(int port);
    const MappingHealth* find(int port) const;
};

#endif // CIRCUIT_BREAKER_H
```

- [ ] **Step 2.2: Write the first failing test**

Create `test/native/test_circuit_breaker/test_circuit_breaker.cpp`:

```cpp
#include "../../../src/circuit_breaker.h"
#include <unity.h>

void setUp(void) {}
void tearDown(void) {}

void test_initial_state_not_backed_off(void) {
    CircuitBreaker cb;
    TEST_ASSERT_FALSE(cb.isBackedOff(22080, 0));
    TEST_ASSERT_FALSE(cb.isBackedOff(22080, 999999));
}

int main(int, char **) {
    UNITY_BEGIN();
    RUN_TEST(test_initial_state_not_backed_off);
    return UNITY_END();
}
```

- [ ] **Step 2.3: Run test, expect link error**

Run: `pio test -e native -f test_circuit_breaker -v`

Expected: link error like `undefined reference to 'CircuitBreaker::isBackedOff'`.

- [ ] **Step 2.4: Implement `CircuitBreaker` methods inline in the header**

Append to `src/circuit_breaker.h` *before* the `#endif`:

```cpp
inline bool CircuitBreaker::isBackedOff(int port, unsigned long now) const {
    const MappingHealth* h = find(port);
    if (!h || h->backoffUntilMs == 0) {
        return false;
    }
    // Unsigned subtraction handles millis() wrap correctly: if now has
    // passed backoffUntilMs, the difference stays small (positive).
    return (long)(now - h->backoffUntilMs) < 0;
}

inline bool CircuitBreaker::recordFailure(int port, unsigned long now) {
    if (port == 0) {
        return false;
    }
    MappingHealth* h = findOrAlloc(port);
    if (!h) {
        return false; // table full — silently skip
    }
    bool wasOpen = h->backoffUntilMs != 0 && (long)(now - h->backoffUntilMs) < 0;
    if (h->consecutiveFails < 100) {
        h->consecutiveFails++;
    }
    if (h->consecutiveFails >= FAIL_THRESHOLD) {
        int exp = h->consecutiveFails - FAIL_THRESHOLD;
        if (exp > 16) {
            exp = 16;
        }
        unsigned long delay = BACKOFF_BASE_MS << exp;
        if (delay > BACKOFF_CAP_MS) {
            delay = BACKOFF_CAP_MS;
        }
        h->backoffUntilMs = now + delay;
        if (!wasOpen) {
            totalTrips_++;
            return true;
        }
    }
    return false;
}

inline void CircuitBreaker::recordSuccess(int port) {
    if (port == 0) {
        return;
    }
    MappingHealth* h = findOrAlloc(port);
    if (!h) {
        return;
    }
    h->consecutiveFails = 0;
    h->backoffUntilMs = 0;
}

inline const CircuitBreaker::MappingHealth* CircuitBreaker::peek(int port) const {
    return find(port);
}

inline CircuitBreaker::MappingHealth* CircuitBreaker::findOrAlloc(int port) {
    for (int i = 0; i < MAX_MAPPING_HEALTH; ++i) {
        if (health_[i].remoteBindPort == port) {
            return &health_[i];
        }
    }
    for (int i = 0; i < MAX_MAPPING_HEALTH; ++i) {
        if (health_[i].remoteBindPort == 0) {
            health_[i].remoteBindPort = port;
            health_[i].consecutiveFails = 0;
            health_[i].backoffUntilMs = 0;
            return &health_[i];
        }
    }
    return nullptr;
}

inline const CircuitBreaker::MappingHealth* CircuitBreaker::find(int port) const {
    for (int i = 0; i < MAX_MAPPING_HEALTH; ++i) {
        if (health_[i].remoteBindPort == port) {
            return &health_[i];
        }
    }
    return nullptr;
}
```

- [ ] **Step 2.5: Run test, expect PASS**

Run: `pio test -e native -f test_circuit_breaker -v`

Expected: `1 Tests 0 Failures 0 Ignored / OK`.

- [ ] **Step 2.6: Add the remaining 11 test cases**

Replace the body of `test/native/test_circuit_breaker/test_circuit_breaker.cpp` with:

```cpp
#include "../../../src/circuit_breaker.h"
#include <unity.h>

void setUp(void) {}
void tearDown(void) {}

void test_initial_state_not_backed_off(void) {
    CircuitBreaker cb;
    TEST_ASSERT_FALSE(cb.isBackedOff(22080, 0));
    TEST_ASSERT_FALSE(cb.isBackedOff(22080, 999999));
}

void test_below_threshold_not_backed_off(void) {
    CircuitBreaker cb;
    cb.recordFailure(22080, 100);
    cb.recordFailure(22080, 200);
    TEST_ASSERT_FALSE(cb.isBackedOff(22080, 300));
}

void test_at_threshold_engages_backoff(void) {
    CircuitBreaker cb;
    cb.recordFailure(22080, 100);
    cb.recordFailure(22080, 200);
    bool tripped = cb.recordFailure(22080, 300);
    TEST_ASSERT_TRUE(tripped);
    TEST_ASSERT_TRUE(cb.isBackedOff(22080, 300));
    TEST_ASSERT_TRUE(cb.isBackedOff(22080, 300 + CircuitBreaker::BACKOFF_BASE_MS - 1));
}

void test_backoff_expires(void) {
    CircuitBreaker cb;
    cb.recordFailure(22080, 100);
    cb.recordFailure(22080, 200);
    cb.recordFailure(22080, 300);
    TEST_ASSERT_FALSE(cb.isBackedOff(22080, 300 + CircuitBreaker::BACKOFF_BASE_MS));
}

void test_exponential_growth(void) {
    CircuitBreaker cb;
    for (int i = 0; i < 3; ++i) cb.recordFailure(22080, 100);
    auto* h1 = cb.peek(22080);
    unsigned long delay1 = h1->backoffUntilMs - 100;

    cb.recordFailure(22080, 100);
    auto* h2 = cb.peek(22080);
    unsigned long delay2 = h2->backoffUntilMs - 100;

    TEST_ASSERT_EQUAL_UINT32(delay1 * 2, delay2);
}

void test_backoff_capped(void) {
    CircuitBreaker cb;
    for (int i = 0; i < 100; ++i) cb.recordFailure(22080, 100);
    auto* h = cb.peek(22080);
    TEST_ASSERT_EQUAL_UINT32(100 + CircuitBreaker::BACKOFF_CAP_MS, h->backoffUntilMs);
}

void test_recovery_resets_state(void) {
    CircuitBreaker cb;
    for (int i = 0; i < 5; ++i) cb.recordFailure(22080, 100);
    TEST_ASSERT_TRUE(cb.isBackedOff(22080, 200));
    cb.recordSuccess(22080);
    TEST_ASSERT_FALSE(cb.isBackedOff(22080, 200));
    auto* h = cb.peek(22080);
    TEST_ASSERT_EQUAL_UINT16(0, h->consecutiveFails);
    TEST_ASSERT_EQUAL_UINT32(0, h->backoffUntilMs);
}

void test_multi_port_isolation(void) {
    CircuitBreaker cb;
    for (int i = 0; i < 3; ++i) cb.recordFailure(22080, 100);
    TEST_ASSERT_TRUE(cb.isBackedOff(22080, 200));
    TEST_ASSERT_FALSE(cb.isBackedOff(22081, 200));
}

void test_table_saturation_silent(void) {
    CircuitBreaker cb;
    // Fill 8 distinct ports
    for (int i = 0; i < CircuitBreaker::MAX_MAPPING_HEALTH; ++i) {
        cb.recordFailure(20000 + i, 100);
    }
    // 9th distinct port should be silently ignored, not crash, not overwrite
    bool tripped = cb.recordFailure(99999, 100);
    TEST_ASSERT_FALSE(tripped);
    TEST_ASSERT_FALSE(cb.isBackedOff(99999, 200));
    // Existing ports unaffected
    TEST_ASSERT_NOT_NULL(cb.peek(20000));
}

void test_millis_wrap(void) {
    CircuitBreaker cb;
    unsigned long nearMax = 0xFFFFFFFEUL;
    for (int i = 0; i < 3; ++i) cb.recordFailure(22080, nearMax);
    // backoffUntilMs has wrapped past 0
    TEST_ASSERT_TRUE(cb.isBackedOff(22080, nearMax));
    TEST_ASSERT_TRUE(cb.isBackedOff(22080, 0));        // just after wrap, still in backoff
    TEST_ASSERT_FALSE(cb.isBackedOff(22080, CircuitBreaker::BACKOFF_BASE_MS));
}

void test_sentinel_port_zero_is_noop(void) {
    CircuitBreaker cb;
    bool tripped = cb.recordFailure(0, 100);
    TEST_ASSERT_FALSE(tripped);
    cb.recordSuccess(0);  // must not crash
    TEST_ASSERT_NULL(cb.peek(0));
}

void test_re_arm_after_recovery(void) {
    CircuitBreaker cb;
    for (int i = 0; i < 3; ++i) cb.recordFailure(22080, 100);
    cb.recordSuccess(22080);
    for (int i = 0; i < 2; ++i) cb.recordFailure(22080, 200);
    TEST_ASSERT_FALSE(cb.isBackedOff(22080, 250));
    bool tripped = cb.recordFailure(22080, 300);
    TEST_ASSERT_TRUE(tripped);
    TEST_ASSERT_TRUE(cb.isBackedOff(22080, 300));
}

int main(int, char **) {
    UNITY_BEGIN();
    RUN_TEST(test_initial_state_not_backed_off);
    RUN_TEST(test_below_threshold_not_backed_off);
    RUN_TEST(test_at_threshold_engages_backoff);
    RUN_TEST(test_backoff_expires);
    RUN_TEST(test_exponential_growth);
    RUN_TEST(test_backoff_capped);
    RUN_TEST(test_recovery_resets_state);
    RUN_TEST(test_multi_port_isolation);
    RUN_TEST(test_table_saturation_silent);
    RUN_TEST(test_millis_wrap);
    RUN_TEST(test_sentinel_port_zero_is_noop);
    RUN_TEST(test_re_arm_after_recovery);
    return UNITY_END();
}
```

- [ ] **Step 2.7: Run all 12 cases**

Run: `pio test -e native -f test_circuit_breaker -v`

Expected: `12 Tests 0 Failures 0 Ignored / OK`.

If any test fails, the implementation in Step 2.4 has a bug — fix before continuing. Do NOT proceed to refactoring `ssh_channel` until all 12 are green.

- [ ] **Step 2.8: Refactor `ssh_channel.h` to use `CircuitBreaker`**

In `src/ssh_channel.h`:

1. After line 6 (the `#include <libssh2_esp.h>` line), add:
   ```cpp
   #include "circuit_breaker.h"
   ```

2. **Delete** lines 67-73 (the `struct MappingHealth { ... };` block).

3. In the public section (around line 132-134), **replace**:
   ```cpp
   bool isMappingBackedOff(int remoteBindPort, unsigned long now) const;
   ```
   with:
   ```cpp
   bool isMappingBackedOff(int remoteBindPort, unsigned long now) const {
       return breaker_.isBackedOff(remoteBindPort, now);
   }
   unsigned long getBreakerTrips() const { return breaker_.totalTrips(); }
   ```

4. In the private section (around line 141-145), **delete** the four method declarations:
   ```cpp
   void recordMappingFailure(int remoteBindPort, unsigned long now);
   void recordMappingSuccess(int remoteBindPort);
   MappingHealth *findOrAllocHealth(int remoteBindPort);
   const MappingHealth *findHealth(int remoteBindPort) const;
   ```

5. **Delete** lines 152-157 (the `MAX_MAPPING_HEALTH`, `MAPPING_FAIL_THRESHOLD`, `MAPPING_BACKOFF_BASE_MS`, `MAPPING_BACKOFF_CAP_MS` constants and the `MappingHealth mappingHealth_[MAX_MAPPING_HEALTH]` member).

6. **Add** in their place:
   ```cpp
   CircuitBreaker breaker_;
   ```

- [ ] **Step 2.9: Refactor `ssh_channel.cpp`**

In `src/ssh_channel.cpp`:

1. **Delete** the entire block from line 466 (the `// Circuit breaker per mapping` comment) to the end of `findHealth()` (around line 549).

2. Find every call site of the deleted methods and replace:
   - `isMappingBackedOff(port, now)` → unchanged (now inline in header, still works)
   - `recordMappingFailure(port, now)` → replace with:
     ```cpp
     if (breaker_.recordFailure(port, now)) {
         LOGF_W("SSH",
                "Mapping port %d: circuit breaker engaged",
                port);
     }
     ```
   - `recordMappingSuccess(port)` → `breaker_.recordSuccess(port);`

3. To find all call sites, run:
   ```bash
   grep -n -E "(recordMappingFailure|recordMappingSuccess|findOrAllocHealth|findHealth)" src/ssh_channel.cpp
   ```
   Each match must be updated.

- [ ] **Step 2.10: Build the firmware to verify the refactor compiles**

Run: `pio run -e arduino-3`

Expected: clean build, no errors. If you get an `incomplete type 'MappingHealth'` error, you missed a reference to the old struct — search and replace.

- [ ] **Step 2.11: Re-run native tests to confirm no regression**

Run: `pio test -e native -f test_circuit_breaker -v`

Expected: still `12 Tests 0 Failures 0 Ignored / OK`.

- [ ] **Step 2.12: Commit (single revert-safe commit)**

```bash
git add src/circuit_breaker.h src/ssh_channel.h src/ssh_channel.cpp \
        test/native/test_circuit_breaker/test_circuit_breaker.cpp
git commit -m "refactor(ssh_channel): extract CircuitBreaker + add native tests

Pure-C++ extraction with 12 Unity test cases covering threshold,
exponential backoff, multi-port isolation, millis() wrap, and
table saturation. No behavior change at the call sites; logging
moves to ssh_channel.cpp via recordFailure() return value."
```

---

## Task 3: Extract `ssh_config_validators` with TDD

**Files:**
- Create: `src/ssh_config_validators.h`
- Create: `test/native/test_ssh_config_validators/test_validators.cpp`
- Modify: `src/ssh_config.cpp` (the `validateSSHConfig`, `validateTunnelConfig`, `validateConnectionConfig` methods)

- [ ] **Step 3.1: Create `src/ssh_config_validators.h`**

```cpp
#ifndef SSH_CONFIG_VALIDATORS_H
#define SSH_CONFIG_VALIDATORS_H

#include <cstddef>
#include <string_view>

namespace ssh_validators {

inline bool isValidPort(int port) {
    return port >= 1 && port <= 65535;
}

inline bool isValidHostname(std::string_view host) {
    if (host.empty() || host.size() > 253) return false;
    for (char c : host) {
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') return false;
    }
    return true;
}

inline bool isValidKeepAlive(int seconds) {
    return seconds == 0 || seconds >= 5;
}

inline bool isValidBufferSize(int bytes) {
    if (bytes < 512 || bytes > 65536) return false;
    // Power of two
    return (bytes & (bytes - 1)) == 0;
}

inline bool isValidReconnectDelay(int ms) {
    return ms > 0 && ms < 60000;
}

inline bool isValidMaxChannels(int n) {
    return n >= 1 && n <= 32;
}

inline bool isPlausibleSshPrivateKey(std::string_view content) {
    constexpr std::string_view marker = "-----BEGIN";
    if (content.size() < marker.size()) return false;
    return content.substr(0, marker.size()) == marker;
}

} // namespace ssh_validators

#endif // SSH_CONFIG_VALIDATORS_H
```

- [ ] **Step 3.2: Write the test file**

Create `test/native/test_ssh_config_validators/test_validators.cpp`:

```cpp
#include "../../../src/ssh_config_validators.h"
#include <unity.h>

using namespace ssh_validators;

void setUp(void) {}
void tearDown(void) {}

void test_port_boundaries(void) {
    TEST_ASSERT_FALSE(isValidPort(0));
    TEST_ASSERT_TRUE(isValidPort(1));
    TEST_ASSERT_TRUE(isValidPort(22));
    TEST_ASSERT_TRUE(isValidPort(65535));
    TEST_ASSERT_FALSE(isValidPort(65536));
    TEST_ASSERT_FALSE(isValidPort(-1));
}

void test_hostname_basic(void) {
    TEST_ASSERT_TRUE(isValidHostname("example.com"));
    TEST_ASSERT_TRUE(isValidHostname("192.168.1.1"));
    TEST_ASSERT_TRUE(isValidHostname("localhost"));
}

void test_hostname_empty_rejected(void) {
    TEST_ASSERT_FALSE(isValidHostname(""));
}

void test_hostname_with_whitespace_rejected(void) {
    TEST_ASSERT_FALSE(isValidHostname("bad host"));
    TEST_ASSERT_FALSE(isValidHostname("\t"));
    TEST_ASSERT_FALSE(isValidHostname("a\nb"));
}

void test_hostname_too_long_rejected(void) {
    std::string s(254, 'a');
    TEST_ASSERT_FALSE(isValidHostname(s));
}

void test_keepalive(void) {
    TEST_ASSERT_TRUE(isValidKeepAlive(0));      // disabled
    TEST_ASSERT_FALSE(isValidKeepAlive(1));     // too low
    TEST_ASSERT_FALSE(isValidKeepAlive(4));
    TEST_ASSERT_TRUE(isValidKeepAlive(5));
    TEST_ASSERT_TRUE(isValidKeepAlive(60));
    TEST_ASSERT_FALSE(isValidKeepAlive(-1));
}

void test_buffer_size_power_of_two(void) {
    TEST_ASSERT_FALSE(isValidBufferSize(0));
    TEST_ASSERT_FALSE(isValidBufferSize(511));
    TEST_ASSERT_TRUE(isValidBufferSize(512));
    TEST_ASSERT_TRUE(isValidBufferSize(8192));
    TEST_ASSERT_FALSE(isValidBufferSize(8193));    // not power of 2
    TEST_ASSERT_TRUE(isValidBufferSize(65536));
    TEST_ASSERT_FALSE(isValidBufferSize(131072));  // too large
}

void test_reconnect_delay(void) {
    TEST_ASSERT_FALSE(isValidReconnectDelay(0));
    TEST_ASSERT_TRUE(isValidReconnectDelay(1));
    TEST_ASSERT_TRUE(isValidReconnectDelay(5000));
    TEST_ASSERT_TRUE(isValidReconnectDelay(59999));
    TEST_ASSERT_FALSE(isValidReconnectDelay(60000));
}

void test_max_channels(void) {
    TEST_ASSERT_FALSE(isValidMaxChannels(0));
    TEST_ASSERT_TRUE(isValidMaxChannels(1));
    TEST_ASSERT_TRUE(isValidMaxChannels(32));
    TEST_ASSERT_FALSE(isValidMaxChannels(33));
}

void test_pem_key_marker(void) {
    TEST_ASSERT_TRUE(isPlausibleSshPrivateKey(
        "-----BEGIN OPENSSH PRIVATE KEY-----\nABC...\n-----END OPENSSH PRIVATE KEY-----"));
    TEST_ASSERT_TRUE(isPlausibleSshPrivateKey(
        "-----BEGIN RSA PRIVATE KEY-----\n..."));
    TEST_ASSERT_FALSE(isPlausibleSshPrivateKey(""));
    TEST_ASSERT_FALSE(isPlausibleSshPrivateKey("ssh-rsa AAAA..."));
    TEST_ASSERT_FALSE(isPlausibleSshPrivateKey("-----BEGI"));  // too short
}

int main(int, char **) {
    UNITY_BEGIN();
    RUN_TEST(test_port_boundaries);
    RUN_TEST(test_hostname_basic);
    RUN_TEST(test_hostname_empty_rejected);
    RUN_TEST(test_hostname_with_whitespace_rejected);
    RUN_TEST(test_hostname_too_long_rejected);
    RUN_TEST(test_keepalive);
    RUN_TEST(test_buffer_size_power_of_two);
    RUN_TEST(test_reconnect_delay);
    RUN_TEST(test_max_channels);
    RUN_TEST(test_pem_key_marker);
    return UNITY_END();
}
```

- [ ] **Step 3.3: Run, expect all PASS**

Run: `pio test -e native -f test_ssh_config_validators -v`

Expected: `10 Tests 0 Failures 0 Ignored / OK`.

- [ ] **Step 3.4: Update `ssh_config.cpp` to delegate to validators**

Find the three private methods `validateSSHConfig`, `validateTunnelConfig`, `validateConnectionConfig` in `src/ssh_config.cpp`.

For each rule that maps to a validator (port checks, hostname non-empty, keepalive sec, buffer size, reconnect delay, max channels, key content sniffing), replace the inline expression with a call to `ssh_validators::isValidXxx(...)`. Add at top of file:

```cpp
#include "ssh_config_validators.h"
```

Use `String::c_str()` to convert Arduino `String` to `std::string_view`-compatible argument:
```cpp
if (!ssh_validators::isValidHostname(sshConfig.host.c_str())) { ... }
```

Do not change the surrounding `LOGF_E`/return logic — just the boolean expressions inside the `if` statements.

- [ ] **Step 3.5: Build firmware to verify**

Run: `pio run -e arduino-3`

Expected: clean build.

- [ ] **Step 3.6: Re-run native tests**

Run: `pio test -e native -f test_ssh_config_validators -v`

Expected: still `10 Tests 0 Failures 0 Ignored / OK`.

- [ ] **Step 3.7: Commit**

```bash
git add src/ssh_config_validators.h src/ssh_config.cpp \
        test/native/test_ssh_config_validators/test_validators.cpp
git commit -m "refactor(ssh_config): extract validators + add native tests

10 Unity test cases covering port range, hostname rules, keepalive,
buffer size power-of-two constraint, reconnect delay, max channels,
and PEM private-key marker. SSHConfiguration::validateXxx methods
now delegate to ssh_validators namespace."
```

---

## Task 4: Extract `PrependBuffer` with TDD

**Files:**
- Create: `src/prepend_buffer.h`
- Create: `test/native/test_prepend_buffer/test_prepend_buffer.cpp`
- Modify: `src/ring_buffer.h` (lines 30-42, 131-164, 182-184, 195-203)

- [ ] **Step 4.1: Create `src/prepend_buffer.h`**

```cpp
#ifndef PREPEND_BUFFER_H
#define PREPEND_BUFFER_H

#include <cstddef>
#include <cstdint>
#include <cstring>

// Holds data that must be read BEFORE the main ring. Used to put back
// bytes that a partial write returned via EAGAIN, preserving FIFO order.
// Storage is provided by the owner (template param Storage*) so the
// host-side tests can use a stack array while DataRingBuffer can keep
// using its PSRAM allocation.
template <size_t Cap>
class PrependBuffer {
public:
    // Returns number of bytes stored, or 0 on rejection.
    // Rejected if: data null/zero-length, len > Cap, or buffer not yet drained.
    size_t writeToFront(const uint8_t* data, size_t len) {
        if (!data || len == 0 || len > Cap) return 0;
        if (len_ > off_) return 0;  // not drained
        std::memcpy(buf_, data, len);
        len_ = len;
        off_ = 0;
        return len;
    }

    // Read up to `len` bytes, returns actual number read.
    size_t read(uint8_t* out, size_t len) {
        if (!out || len == 0 || len_ <= off_) return 0;
        size_t avail = len_ - off_;
        size_t copy = avail < len ? avail : len;
        std::memcpy(out, buf_ + off_, copy);
        off_ += copy;
        if (off_ >= len_) {
            len_ = 0;
            off_ = 0;
        }
        return copy;
    }

    bool empty() const { return len_ <= off_; }
    size_t pending() const { return (len_ > off_) ? (len_ - off_) : 0; }
    size_t capacity() const { return Cap; }

    void clear() { len_ = 0; off_ = 0; }

private:
    uint8_t buf_[Cap]{};
    size_t len_ = 0;
    size_t off_ = 0;
};

#endif // PREPEND_BUFFER_H
```

- [ ] **Step 4.2: Write test file**

Create `test/native/test_prepend_buffer/test_prepend_buffer.cpp`:

```cpp
#include "../../../src/prepend_buffer.h"
#include <unity.h>

void setUp(void) {}
void tearDown(void) {}

void test_initially_empty(void) {
    PrependBuffer<128> pb;
    TEST_ASSERT_TRUE(pb.empty());
    TEST_ASSERT_EQUAL_size_t(0, pb.pending());
}

void test_write_and_read_full(void) {
    PrependBuffer<128> pb;
    uint8_t data[] = {1, 2, 3, 4};
    TEST_ASSERT_EQUAL_size_t(4, pb.writeToFront(data, 4));
    TEST_ASSERT_FALSE(pb.empty());
    TEST_ASSERT_EQUAL_size_t(4, pb.pending());

    uint8_t out[8] = {};
    TEST_ASSERT_EQUAL_size_t(4, pb.read(out, 8));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(data, out, 4);
    TEST_ASSERT_TRUE(pb.empty());
}

void test_partial_read(void) {
    PrependBuffer<128> pb;
    uint8_t data[] = {1, 2, 3, 4, 5};
    pb.writeToFront(data, 5);
    uint8_t out[3] = {};
    TEST_ASSERT_EQUAL_size_t(3, pb.read(out, 3));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(data, out, 3);
    TEST_ASSERT_EQUAL_size_t(2, pb.pending());

    uint8_t out2[8] = {};
    TEST_ASSERT_EQUAL_size_t(2, pb.read(out2, 8));
    uint8_t expected[] = {4, 5};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, out2, 2);
    TEST_ASSERT_TRUE(pb.empty());
}

void test_oversized_write_rejected(void) {
    PrependBuffer<8> pb;
    uint8_t data[16] = {};
    TEST_ASSERT_EQUAL_size_t(0, pb.writeToFront(data, 16));
    TEST_ASSERT_TRUE(pb.empty());
}

void test_write_when_non_empty_rejected(void) {
    PrependBuffer<128> pb;
    uint8_t a[] = {1, 2, 3};
    uint8_t b[] = {9, 9};
    pb.writeToFront(a, 3);
    TEST_ASSERT_EQUAL_size_t(0, pb.writeToFront(b, 2));
    TEST_ASSERT_EQUAL_size_t(3, pb.pending());
}

void test_write_after_full_drain_succeeds(void) {
    PrependBuffer<128> pb;
    uint8_t a[] = {1, 2};
    uint8_t b[] = {7, 8, 9};
    pb.writeToFront(a, 2);
    uint8_t tmp[8] = {};
    pb.read(tmp, 8);
    TEST_ASSERT_EQUAL_size_t(3, pb.writeToFront(b, 3));
}

void test_null_or_zero_rejected(void) {
    PrependBuffer<128> pb;
    TEST_ASSERT_EQUAL_size_t(0, pb.writeToFront(nullptr, 4));
    uint8_t data[] = {1};
    TEST_ASSERT_EQUAL_size_t(0, pb.writeToFront(data, 0));
    uint8_t out[8] = {};
    TEST_ASSERT_EQUAL_size_t(0, pb.read(nullptr, 8));
    TEST_ASSERT_EQUAL_size_t(0, pb.read(out, 0));
}

void test_clear(void) {
    PrependBuffer<128> pb;
    uint8_t a[] = {1, 2, 3};
    pb.writeToFront(a, 3);
    pb.clear();
    TEST_ASSERT_TRUE(pb.empty());
    TEST_ASSERT_EQUAL_size_t(3, pb.writeToFront(a, 3));  // can write again
}

void test_capacity_exact_fit(void) {
    PrependBuffer<4> pb;
    uint8_t data[] = {1, 2, 3, 4};
    TEST_ASSERT_EQUAL_size_t(4, pb.writeToFront(data, 4));
    uint8_t one_more[] = {5};
    pb.read(data, 4);
    TEST_ASSERT_EQUAL_size_t(1, pb.writeToFront(one_more, 1));
}

void test_read_when_empty(void) {
    PrependBuffer<128> pb;
    uint8_t out[8] = {};
    TEST_ASSERT_EQUAL_size_t(0, pb.read(out, 8));
}

int main(int, char **) {
    UNITY_BEGIN();
    RUN_TEST(test_initially_empty);
    RUN_TEST(test_write_and_read_full);
    RUN_TEST(test_partial_read);
    RUN_TEST(test_oversized_write_rejected);
    RUN_TEST(test_write_when_non_empty_rejected);
    RUN_TEST(test_write_after_full_drain_succeeds);
    RUN_TEST(test_null_or_zero_rejected);
    RUN_TEST(test_clear);
    RUN_TEST(test_capacity_exact_fit);
    RUN_TEST(test_read_when_empty);
    return UNITY_END();
}
```

- [ ] **Step 4.3: Run tests, expect all PASS**

Run: `pio test -e native -f test_prepend_buffer -v`

Expected: `10 Tests 0 Failures 0 Ignored / OK`.

- [ ] **Step 4.4: Refactor `src/ring_buffer.h` to use `PrependBuffer`**

In `src/ring_buffer.h`:

1. After the existing includes (around line 9), add:
   ```cpp
   #include "prepend_buffer.h"
   ```

2. **Delete** the `static constexpr size_t PREPEND_CAP = 8192;` and the three fields `prepend_`, `prependLen_`, `prependOff_` (around lines 33-35). Replace with:
   ```cpp
   static constexpr size_t PREPEND_CAP = 8192;
   PrependBuffer<PREPEND_CAP> prepend_;
   ```

3. In the constructor, **remove** the `prepend_ = static_cast<uint8_t *>(psramAlloc(PREPEND_CAP));` line and the `if (!handle || !prepend_)` checks involving `prepend_`. The check becomes simply `if (!handle)`. Remove the `psramFree(prepend_); prepend_ = nullptr;` lines from both the constructor's error path and the destructor.

4. Replace `writeToFront()` body (around lines 131-142) with:
   ```cpp
   size_t writeToFront(const uint8_t *data, size_t len) {
       return prepend_.writeToFront(data, len);
   }
   ```

5. In `read()` (around lines 145-180), replace the prepend-drain section (the `if (prependLen_ > prependOff_) { ... }` block) with:
   ```cpp
   if (!prepend_.empty()) {
       size_t copied = prepend_.read(data, len);
       total += copied;
       if (total >= len) return total;
   }
   ```

6. In `clear()` (around line 182), replace `prependLen_ = 0; prependOff_ = 0;` with `prepend_.clear();`

7. In `size()` (around line 195), replace the `prependRemain` calculation with `prepend_.pending()`.

- [ ] **Step 4.5: Build firmware**

Run: `pio run -e arduino-3`

Expected: clean build.

- [ ] **Step 4.6: Re-run native tests for prepend_buffer + circuit_breaker + validators**

Run: `pio test -e native -v`

Expected: all three test suites green (smoke + 12 + 10 + 10 = 33 tests total; smoke is 1, so 33).

- [ ] **Step 4.7: Commit**

```bash
git add src/prepend_buffer.h src/ring_buffer.h \
        test/native/test_prepend_buffer/test_prepend_buffer.cpp
git commit -m "refactor(ring_buffer): extract PrependBuffer + add native tests

10 Unity test cases covering empty state, partial reads, oversize
rejection, write-when-occupied, exact-capacity fit, and clear.
DataRingBuffer now composes PrependBuffer<8192> instead of managing
its own buffer/offset/length fields. PSRAM behavior unchanged."
```

---

## Task 5: Add `test-native` job to GitHub Actions CI

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 5.1: Add the new job**

In `.github/workflows/ci.yml`, after the `lint:` job block (after line 76), append:

```yaml
  test-native:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Cache PlatformIO
        uses: actions/cache@v4
        with:
          path: |
            ~/.platformio
          key: pio-native-${{ runner.os }}-${{ hashFiles('platformio.ini') }}
          restore-keys: |
            pio-native-${{ runner.os }}-

      - name: Install PlatformIO
        run: |
          python -m pip install --upgrade pip
          pip install platformio

      - name: Run native tests
        run: pio test -e native -v
```

- [ ] **Step 5.2: Validate the YAML locally**

Run: `python -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"`

Expected: no output (no exception). If it raises, fix indentation.

- [ ] **Step 5.3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add test-native job for host-side Unity tests"
```

- [ ] **Step 5.4: Push and verify on GitHub**

If the maintainer wants to push at this point:
```bash
git push origin dev
```
Then check the Actions tab on GitHub — the new `test-native` job should appear and pass within ~30s.

---

## Task 6: Build the Docker stack

**Files:**
- Create: `test/integration/docker/docker-compose.yml`
- Create: `test/integration/docker/sshd/Dockerfile`
- Create: `test/integration/docker/sshd/sshd_config`
- Create: `test/integration/docker/slow_echo/Dockerfile`
- Create: `test/integration/docker/slow_echo/server.py`
- Create: `test/integration/README.md`
- Create: `Makefile` (root)

- [ ] **Step 6.1: Create directory structure**

```bash
mkdir -p test/integration/docker/sshd test/integration/docker/slow_echo
mkdir -p test/integration/firmware test/integration/harness/lib
```

- [ ] **Step 6.2: sshd config**

Create `test/integration/docker/sshd/sshd_config`:

```
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin no
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM no
AllowTcpForwarding yes
GatewayPorts yes
AllowAgentForwarding no
PermitTunnel no
X11Forwarding no
ClientAliveInterval 30
ClientAliveCountMax 3
MaxSessions 10
MaxStartups 10:30:60
LogLevel INFO
Subsystem sftp /usr/lib/ssh/sftp-server
```

- [ ] **Step 6.3: sshd Dockerfile**

Create `test/integration/docker/sshd/Dockerfile`:

```dockerfile
FROM alpine:3.19

RUN apk add --no-cache openssh-server bash && \
    ssh-keygen -A && \
    adduser -D -s /bin/bash testuser && \
    echo 'testuser:testpass' | chpasswd

COPY sshd_config /etc/ssh/sshd_config

EXPOSE 22 22080 22081 22082

CMD ["/usr/sbin/sshd", "-D", "-e"]
```

- [ ] **Step 6.4: slow_echo server**

Create `test/integration/docker/slow_echo/server.py`:

```python
#!/usr/bin/env python3
"""Slow TCP echo server: echoes received bytes throttled to ~1 KB/s.

Used by integration test G2 (backpressure) to verify that a slow
consumer on one channel does not destabilize the SSH session or
starve other channels.
"""
import socket
import threading
import time

HOST = "0.0.0.0"
PORT = 9001
RATE_BYTES_PER_SEC = 1024
CHUNK = 64  # send in small chunks so throttling is smooth


def handle(conn: socket.socket, addr) -> None:
    print(f"[slow_echo] connect from {addr}", flush=True)
    try:
        conn.settimeout(60.0)
        while True:
            data = conn.recv(4096)
            if not data:
                break
            for i in range(0, len(data), CHUNK):
                piece = data[i:i + CHUNK]
                conn.sendall(piece)
                time.sleep(len(piece) / RATE_BYTES_PER_SEC)
    except (socket.timeout, ConnectionResetError, BrokenPipeError) as e:
        print(f"[slow_echo] {addr} closed: {e}", flush=True)
    finally:
        conn.close()
        print(f"[slow_echo] disconnect {addr}", flush=True)


def main() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(8)
    print(f"[slow_echo] listening on {HOST}:{PORT}", flush=True)
    try:
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        srv.close()


if __name__ == "__main__":
    main()
```

- [ ] **Step 6.5: slow_echo Dockerfile**

Create `test/integration/docker/slow_echo/Dockerfile`:

```dockerfile
FROM python:3.11-alpine
WORKDIR /app
COPY server.py .
EXPOSE 9001
CMD ["python", "server.py"]
```

- [ ] **Step 6.6: docker-compose.yml**

Create `test/integration/docker/docker-compose.yml`:

```yaml
services:
  sshd:
    build: ./sshd
    container_name: tunnel_test_sshd
    ports:
      - "2222:22"
      - "22080:22080"
      - "22081:22081"
      - "22082:22082"
    restart: unless-stopped

  echo:
    image: alpine:3.19
    container_name: tunnel_test_echo
    command: sh -c "apk add --no-cache socat && socat -d TCP-LISTEN:9000,reuseaddr,fork EXEC:cat"
    ports:
      - "9000:9000"
    restart: unless-stopped

  slow_echo:
    build: ./slow_echo
    container_name: tunnel_test_slow_echo
    ports:
      - "9001:9001"
    restart: unless-stopped
```

- [ ] **Step 6.7: Bring the stack up and validate**

```bash
docker compose -f test/integration/docker/docker-compose.yml up -d --build
```

Expected: three containers running. Verify:
```bash
docker compose -f test/integration/docker/docker-compose.yml ps
```
Expected: `tunnel_test_sshd`, `tunnel_test_echo`, `tunnel_test_slow_echo` all `running`.

Quick functional check of echo:
```bash
echo "hello" | nc -q 1 127.0.0.1 9000
```
Expected: prints `hello` back.

Quick functional check of sshd auth:
```bash
ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null testuser@127.0.0.1 echo OK
```
(Password: `testpass`.) Expected: prints `OK`.

- [ ] **Step 6.8: Bring the stack down**

```bash
docker compose -f test/integration/docker/docker-compose.yml down
```

- [ ] **Step 6.9: Create root Makefile**

Create `Makefile` at repo root:

```makefile
.PHONY: test-native test-integration test-integration-up test-integration-run \
        test-integration-down test-integration-quick flash-test

test-native:
	pio test -e native -v

test-integration: test-integration-up test-integration-run test-integration-down

test-integration-up:
	docker compose -f test/integration/docker/docker-compose.yml up -d --build
	@sleep 3

test-integration-run:
	cd test/integration/harness && pytest -v --tb=short

test-integration-down:
	docker compose -f test/integration/docker/docker-compose.yml down

test-integration-quick:
	cd test/integration/harness && pytest -v --tb=short

flash-test:
	pio run -e test_integration -t upload
```

- [ ] **Step 6.10: Create README for integration**

Create `test/integration/README.md`:

```markdown
# Integration test harness

Drives a real ESP32 (running `firmware/main_test.cpp`) through reverse SSH
tunnels exposed by a local Docker stack (sshd + echo + slow_echo).

## Prerequisites

- Docker Compose v2
- ESP32 attached via USB, accessible from WSL as `/dev/ttyUSB0`
  (use `usbipd-win` on Windows to attach: `usbipd attach --wsl --busid X-Y`)
- WSL2 with mirrored networking enabled, OR a `netsh interface portproxy`
  setup forwarding 2222/9000/9001 to the WSL host (see Fallback below)
- Python 3.11+
- Environment variables exported (see Setup)

## Setup

```bash
export TEST_WIFI_SSID="your-wifi"
export TEST_WIFI_PASS="your-wifi-password"
export TEST_DOCKER_HOST_IP="192.168.1.42"   # IP of WSL host on your LAN
make flash-test                              # one-time, or after firmware change
```

## Run

```bash
make test-integration         # full cycle: docker up + tests + docker down
make test-integration-up      # bring stack up once
make test-integration-quick   # run tests against already-up stack
make test-integration-down    # tear stack down
```

## Fallback if WSL2 mirrored networking is unavailable

On the Windows host, run as Administrator (one-time):

```powershell
netsh interface portproxy add v4tov4 listenport=2222 listenaddress=0.0.0.0 connectport=2222 connectaddress=<WSL_IP>
netsh interface portproxy add v4tov4 listenport=9000 listenaddress=0.0.0.0 connectport=9000 connectaddress=<WSL_IP>
netsh interface portproxy add v4tov4 listenport=9001 listenaddress=0.0.0.0 connectport=9001 connectaddress=<WSL_IP>
```

Get `<WSL_IP>` with `wsl hostname -I` from PowerShell.
```

- [ ] **Step 6.11: Commit**

```bash
git add test/integration/docker test/integration/README.md Makefile
git commit -m "test(integration): add Docker stack (sshd + echo + slow_echo) + Makefile"
```

---

## Task 7: Build the test firmware (`main_test.cpp`)

**Files:**
- Create: `test/integration/firmware/main_test.cpp`
- Modify: `platformio.ini` (add `[env:test_integration]`)
- Modify: `src/ssh_tunnel.h` (add `getBreakerTrips()` getter)
- Modify: `src/ssh_tunnel.cpp` (implement getter)

- [ ] **Step 7.1: Add `getBreakerTrips()` to `ssh_tunnel.h`**

In the public section of `class SSHTunnel` in `src/ssh_tunnel.h`, near the existing stat getters (`getBytesSent`, `getBytesReceived`, `getActiveChannels`), add:

```cpp
unsigned long getBreakerTrips() const;
```

- [ ] **Step 7.2: Implement in `ssh_tunnel.cpp`**

Add to `src/ssh_tunnel.cpp` (near the other getter implementations):

```cpp
unsigned long SSHTunnel::getBreakerTrips() const {
    return channels_.getBreakerTrips();
}
```

`channels_` is the `ChannelManager channels_;` member declared at `src/ssh_tunnel.h:122`. The `ChannelManager::getBreakerTrips()` accessor was added in Task 2 Step 2.8.

- [ ] **Step 7.3: Build firmware to verify the new getter compiles**

Run: `pio run -e arduino-3`

Expected: clean build.

- [ ] **Step 7.4: Create the test firmware**

Create `test/integration/firmware/main_test.cpp`:

```cpp
#include "ESP-Reverse_Tunneling_Libssh2.h"
#include <Arduino.h>
#include <WiFi.h>
#include <esp_heap_caps.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

// All values come from build flags (see [env:test_integration] in platformio.ini)
#ifndef WIFI_SSID
#error "WIFI_SSID must be defined via -D"
#endif
#ifndef WIFI_PASS
#error "WIFI_PASS must be defined via -D"
#endif
#ifndef DOCKER_HOST_IP
#error "DOCKER_HOST_IP must be defined via -D"
#endif

static constexpr unsigned long STATS_INTERVAL_MS = 1000;

SSHTunnel tunnel;
unsigned long lastStatsReport = 0;

static const char* stateString(SSHTunnel& t) {
    return t.getStateString().c_str();
}

void setup() {
    Serial.begin(115200);
    while (!Serial) vTaskDelay(pdMS_TO_TICKS(10));

    Serial.println("BOOT_TEST firmware=main_test");

    // SSH server: testuser@DOCKER_HOST_IP:2222 password testpass
    globalSSHConfig.setSSHServer(DOCKER_HOST_IP, 2222, "testuser", "testpass");

    // Three tunnel mappings:
    //   22080 -> DOCKER_HOST_IP:9000  (echo, used by tests A/B/D/F)
    //   22081 -> DOCKER_HOST_IP:9001  (slow_echo, used by test G2)
    //   22082 -> DOCKER_HOST_IP:65500 (dead port, used by test G1)
    globalSSHConfig.clearTunnelMappings();
    globalSSHConfig.setMaxReverseListeners(3);
    globalSSHConfig.addTunnelMapping("127.0.0.1", 22080, DOCKER_HOST_IP, 9000);
    globalSSHConfig.addTunnelMapping("127.0.0.1", 22081, DOCKER_HOST_IP, 9001);
    globalSSHConfig.addTunnelMapping("127.0.0.1", 22082, DOCKER_HOST_IP, 65500);

    globalSSHConfig.setConnectionConfig(30, 5000, 100, 30);
    globalSSHConfig.setBufferConfig(8192, 5, 1800000);
    globalSSHConfig.setDebugConfig(true, 115200);

    WiFi.begin(WIFI_SSID, WIFI_PASS);
    int attempts = 0;
    while (WiFi.status() != WL_CONNECTED && attempts < 30) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        Serial.print(".");
        attempts++;
    }
    Serial.println();
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("WIFI_FAIL");
        return;
    }
    Serial.printf("WIFI_OK ip=%s rssi=%d\n",
                  WiFi.localIP().toString().c_str(), WiFi.RSSI());

    if (!tunnel.init() || !tunnel.connectSSH()) {
        Serial.println("TUNNEL_INIT_FAIL");
        return;
    }
    Serial.println("TUNNEL_INIT_OK");
}

void loop() {
    if (WiFi.status() != WL_CONNECTED) {
        WiFi.reconnect();
        vTaskDelay(pdMS_TO_TICKS(500));
        return;
    }

    tunnel.loop();

    unsigned long now = millis();
    if (now - lastStatsReport >= STATS_INTERVAL_MS) {
        lastStatsReport = now;
        size_t freeHeap = ESP.getFreeHeap();
        size_t minHeap = ESP.getMinFreeHeap();
        size_t largest = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);

        // Single-line, key=value, prefix STATS_TEST. Parsed by harness.
        Serial.printf(
            "STATS_TEST t=%lu state=%s ch=%d sent=%lu recv=%lu dropped=%lu "
            "heap=%u minheap=%u largest=%u breaker_trips=%lu\n",
            now, stateString(tunnel), tunnel.getActiveChannels(),
            tunnel.getBytesSent(), tunnel.getBytesReceived(),
            tunnel.getBytesDropped(), (unsigned)freeHeap, (unsigned)minHeap,
            (unsigned)largest, tunnel.getBreakerTrips());
    }

    vTaskDelay(pdMS_TO_TICKS(1));
}
```

- [ ] **Step 7.5: Add `[env:test_integration]` to platformio.ini**

Append to `platformio.ini`:

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

- [ ] **Step 7.6: Build the test firmware**

```bash
export TEST_WIFI_SSID="your-wifi"
export TEST_WIFI_PASS="your-wifi-password"
export TEST_DOCKER_HOST_IP="192.168.1.42"
pio run -e test_integration
```

Expected: clean build. If you get `WIFI_SSID must be defined via -D`, the env vars are not exported.

- [ ] **Step 7.7: Flash and smoke-test on real hardware**

```bash
make flash-test
pio device monitor -e test_integration
```

Expected serial output (within 10-30 seconds):
```
BOOT_TEST firmware=main_test
.....
WIFI_OK ip=192.168.1.123 rssi=-55
TUNNEL_INIT_OK
STATS_TEST t=15234 state=CONNECTED ch=0 sent=0 recv=0 dropped=0 heap=180432 minheap=174000 largest=120000 breaker_trips=0
STATS_TEST t=16234 state=CONNECTED ch=0 sent=0 recv=0 dropped=0 ...
```

If `state` stays at `CONNECTING` or `RECONNECTING`, check that the Docker stack is up and reachable from the ESP32's network (`make test-integration-up` first).

- [ ] **Step 7.8: Commit**

```bash
git add test/integration/firmware/main_test.cpp platformio.ini \
        src/ssh_tunnel.h src/ssh_tunnel.cpp
git commit -m "test(integration): add test firmware + getBreakerTrips() getter

main_test.cpp emits one machine-parsable STATS_TEST line per second
with state, channel count, byte counters, heap snapshot, and circuit
breaker trip count. Uses three hardcoded mappings: echo (22080),
slow_echo (22081), dead port (22082)."
```

---

## Task 8: Build the Python harness library

**Files:**
- Create: `test/integration/harness/pyproject.toml`
- Create: `test/integration/harness/conftest.py`
- Create: `test/integration/harness/lib/__init__.py`
- Create: `test/integration/harness/lib/serial_stats.py`
- Create: `test/integration/harness/lib/pattern.py`
- Create: `test/integration/harness/lib/thresholds.py`
- Create: `test/integration/harness/lib/docker_ctl.py`

- [ ] **Step 8.1: pyproject.toml**

Create `test/integration/harness/pyproject.toml`:

```toml
[project]
name = "tunnel-integration-harness"
version = "0.1.0"
description = "Integration test harness for ESP-Reverse_Tunneling_Libssh2"
requires-python = ">=3.11"
dependencies = [
  "pytest>=7.4",
  "pyserial>=3.5",
]

[tool.pytest.ini_options]
testpaths = ["."]
python_files = "test_*.py"
addopts = "--tb=short -ra"
log_cli = true
log_cli_level = "INFO"
```

- [ ] **Step 8.2: lib/__init__.py**

Create `test/integration/harness/lib/__init__.py`:

```python
"""Shared utilities for the ESP32 SSH tunnel integration harness."""
```

- [ ] **Step 8.3: lib/thresholds.py**

Create `test/integration/harness/lib/thresholds.py`:

```python
"""Centralized pass/fail thresholds for integration tests.

Tune these instead of touching test bodies.
"""

# Test A — data integrity
A_TRANSFER_SIZES = [1 * 1024 * 1024, 10 * 1024 * 1024]  # 100 MB optional via -m slow
A_CHUNK_SIZES = [64, 1024, 8 * 1024, 64 * 1024]
A_PRNG_SEED = 0xC0FFEE

# Test B — throughput stability
B_DURATION_S = 300                       # 5 minutes
B_SAMPLE_HZ = 1
B_MAX_STALL_S = 3.0                      # any 2s window with < 1 KB/s = stall
B_MIN_STALL_BYTES_PER_S = 1024
B_MAX_STDDEV_RATIO = 0.30                # stddev / mean
B_MAX_HEAP_DRIFT_BYTES = 5 * 1024

# Test D — channel leaks
D_CYCLES = 50
D_CHUNK_BYTES = 100 * 1024
D_INTER_CYCLE_DELAY_S = 1.0
D_MAX_HEAP_DRIFT_BYTES = 5 * 1024

# Test F — reconnect
F_TRANSFER_BYTES = 10 * 1024 * 1024
F_KILL_AT_FRACTION = 0.5
F_DOWN_S = 5.0
F_RECONNECT_TIMEOUT_S = 30.0

# Test G — backpressure
G1_DEAD_PORT_MAPPING = 22082
G1_ATTEMPTS = 10
G1_PARALLEL_LIVE_MAPPING = 22080
G2_SLOW_MAPPING = 22081
G2_LIVE_MAPPING = 22080
G2_BURST_BYTES = 1 * 1024 * 1024
G2_LIVE_THROUGHPUT_TOLERANCE = 0.30

# Common
TUNNEL_READY_TIMEOUT_S = 30.0
SERIAL_PORT = "/dev/ttyUSB0"
SERIAL_BAUD = 115200
DOCKER_HOST_FOR_CLIENT = "127.0.0.1"     # forwarded port targets
```

- [ ] **Step 8.4: lib/pattern.py**

Create `test/integration/harness/lib/pattern.py`:

```python
"""Deterministic byte-stream generator + verifier (xorshift32).

Reproducible across platforms — does not use Python's random module.
"""
from __future__ import annotations


def _xorshift32(state: int) -> int:
    state ^= (state << 13) & 0xFFFFFFFF
    state ^= (state >> 17) & 0xFFFFFFFF
    state ^= (state << 5) & 0xFFFFFFFF
    return state & 0xFFFFFFFF


def make_stream(seed: int, length: int) -> bytes:
    """Produce a deterministic byte sequence of `length` bytes from `seed`."""
    out = bytearray(length)
    state = seed & 0xFFFFFFFF
    if state == 0:
        state = 1
    i = 0
    while i + 4 <= length:
        state = _xorshift32(state)
        out[i] = state & 0xFF
        out[i + 1] = (state >> 8) & 0xFF
        out[i + 2] = (state >> 16) & 0xFF
        out[i + 3] = (state >> 24) & 0xFF
        i += 4
    while i < length:
        state = _xorshift32(state)
        out[i] = state & 0xFF
        i += 1
    return bytes(out)


def verify_stream(seed: int, received: bytes) -> tuple[int, int]:
    """Compare received bytes against the deterministic stream.

    Returns (mismatches, first_mismatch_offset). first_mismatch_offset is -1
    if no mismatch.
    """
    expected = make_stream(seed, len(received))
    if expected == received:
        return (0, -1)
    mismatches = 0
    first = -1
    for i, (e, r) in enumerate(zip(expected, received)):
        if e != r:
            mismatches += 1
            if first < 0:
                first = i
    return (mismatches, first)
```

- [ ] **Step 8.5: lib/serial_stats.py**

Create `test/integration/harness/lib/serial_stats.py`:

```python
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
```

- [ ] **Step 8.6: lib/docker_ctl.py**

Create `test/integration/harness/lib/docker_ctl.py`:

```python
"""Thin wrapper around `docker compose` for use in pytest fixtures."""
from __future__ import annotations

import subprocess
from pathlib import Path

COMPOSE_FILE = (
    Path(__file__).resolve().parents[2]
    / "docker"
    / "docker-compose.yml"
)


def _compose(*args: str) -> subprocess.CompletedProcess:
    cmd = ["docker", "compose", "-f", str(COMPOSE_FILE), *args]
    return subprocess.run(cmd, check=True, capture_output=True, text=True)


def up() -> None:
    _compose("up", "-d", "--build")


def down() -> None:
    _compose("down")


def kill(service: str) -> None:
    _compose("kill", service)


def start(service: str) -> None:
    _compose("start", service)


def is_running(service: str) -> bool:
    cp = subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE),
         "ps", "--services", "--filter", "status=running"],
        capture_output=True, text=True)
    return service in cp.stdout.splitlines()
```

- [ ] **Step 8.7: conftest.py with fixtures**

Create `test/integration/harness/conftest.py`:

```python
"""Pytest fixtures for the ESP32 tunnel integration harness."""
from __future__ import annotations

import socket
import time

import pytest

from lib import docker_ctl, thresholds as TH
from lib.serial_stats import StatsMonitor


@pytest.fixture(scope="session", autouse=True)
def _docker_stack():
    docker_ctl.up()
    time.sleep(3)
    yield
    docker_ctl.down()


@pytest.fixture(scope="session")
def serial_monitor():
    sm = StatsMonitor(port=TH.SERIAL_PORT, baud=TH.SERIAL_BAUD)
    sm.start()
    # Wait for at least one stats line so the ESP32 is alive
    sm.wait_for(lambda s: True, timeout_s=15.0)
    yield sm
    sm.stop()


@pytest.fixture
def wait_tunnel_ready(serial_monitor):
    def _wait():
        return serial_monitor.wait_for(
            lambda s: s.get("state") == "CONNECTED",
            timeout_s=TH.TUNNEL_READY_TIMEOUT_S)
    return _wait


@pytest.fixture
def tunnel_socket():
    """Factory: open a TCP socket to the forwarded sshd port for `mapping_port`.
    The harness reaches the listener via 127.0.0.1:<port> on the docker host
    (the WSL host with mirrored networking)."""
    sockets = []

    def _open(mapping_port: int, timeout_s: float = 30.0) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout_s)
        s.connect((TH.DOCKER_HOST_FOR_CLIENT, mapping_port))
        sockets.append(s)
        return s

    yield _open

    for s in sockets:
        try:
            s.close()
        except OSError:
            pass


@pytest.fixture
def reset_stats_baseline(serial_monitor):
    """Returns a snapshot dict captured at the moment of the call."""
    def _snapshot():
        return serial_monitor.latest()
    return _snapshot
```

- [ ] **Step 8.8: Smoke-validate the harness library imports**

```bash
cd test/integration/harness
python -c "import lib.serial_stats, lib.pattern, lib.thresholds, lib.docker_ctl; print('OK')"
```

Expected: prints `OK` (after `pip install pyserial pytest`).

- [ ] **Step 8.9: Commit**

```bash
git add test/integration/harness/pyproject.toml \
        test/integration/harness/conftest.py \
        test/integration/harness/lib/
git commit -m "test(integration): add Python harness library + pytest fixtures

StatsMonitor: thread-safe parser of STATS_TEST serial telemetry.
pattern.py: deterministic xorshift32 byte-stream generator/verifier.
thresholds.py: centralized pass/fail constants.
docker_ctl.py: compose up/down/kill helpers.
conftest.py: session-scoped docker_stack + serial_monitor fixtures."
```

---

## Task 9: Test A — Data integrity scenarios

**Files:**
- Create: `test/integration/harness/test_a_data_integrity.py`

- [ ] **Step 9.1: Write the test**

Create `test/integration/harness/test_a_data_integrity.py`:

```python
"""Test A — Data integrity through the reverse tunnel.

For each (size, chunk_size) combination, send a deterministic byte stream
through 22080 → echo container → back, then verify byte-for-byte equality
and that the ESP32 reports zero drops.
"""
from __future__ import annotations

import pytest

from lib import thresholds as TH
from lib.pattern import make_stream, verify_stream


def _send_recv_echo(sock, payload: bytes, chunk: int) -> bytes:
    """Send payload in `chunk`-sized writes; receive exactly len(payload) bytes."""
    # Sender thread is unnecessary because echo container immediately reflects;
    # we interleave write/read to keep socket buffers from blocking.
    received = bytearray()
    sent = 0
    while sent < len(payload):
        end = min(sent + chunk, len(payload))
        sock.sendall(payload[sent:end])
        sent = end
        # Drain whatever is available without blocking
        sock.settimeout(0.1)
        try:
            while True:
                buf = sock.recv(min(chunk, len(payload) - len(received)))
                if not buf:
                    break
                received.extend(buf)
                if len(received) >= len(payload):
                    break
        except (TimeoutError, OSError):
            pass
        sock.settimeout(30.0)

    # Drain remainder
    while len(received) < len(payload):
        buf = sock.recv(min(64 * 1024, len(payload) - len(received)))
        if not buf:
            break
        received.extend(buf)
    return bytes(received)


@pytest.mark.parametrize("size", TH.A_TRANSFER_SIZES)
@pytest.mark.parametrize("chunk", TH.A_CHUNK_SIZES)
def test_echo_data_integrity(size, chunk, wait_tunnel_ready, tunnel_socket,
                              reset_stats_baseline, serial_monitor):
    wait_tunnel_ready()
    baseline = reset_stats_baseline()

    payload = make_stream(TH.A_PRNG_SEED, size)
    sock = tunnel_socket(22080)
    received = _send_recv_echo(sock, payload, chunk)
    sock.close()

    assert len(received) == size, (
        f"expected {size} bytes, got {len(received)}")

    mismatches, first_off = verify_stream(TH.A_PRNG_SEED, received)
    assert mismatches == 0, (
        f"{mismatches} byte mismatches; first at offset {first_off}")

    # Allow ESP32 a moment to update its counters
    import time
    time.sleep(2.0)
    final = serial_monitor.latest()
    dropped_delta = final["dropped"] - baseline.get("dropped", 0)
    assert dropped_delta == 0, (
        f"ESP32 reports {dropped_delta} bytes dropped during transfer")
```

- [ ] **Step 9.2: Run the test**

```bash
make test-integration-up         # if not already up
make flash-test                  # if firmware not flashed
cd test/integration/harness
pytest -v test_a_data_integrity.py
```

Expected: 8 parametrized cases (2 sizes × 4 chunks), all PASS within ~3-5 minutes.

If a case fails with mismatches > 0: a real "hole" was found — capture the failing `(size, chunk)` and the `first_off` value, that's already enough to start debugging.

If a case fails with `dropped_delta > 0`: similar; the ESP32 confirms it dropped bytes silently.

- [ ] **Step 9.3: Commit**

```bash
git add test/integration/harness/test_a_data_integrity.py
git commit -m "test(integration): add Test A — data integrity (echo)"
```

---

## Task 10: Test B — Throughput stability

**Files:**
- Create: `test/integration/harness/test_b_throughput_stability.py`

- [ ] **Step 10.1: Write the test**

Create `test/integration/harness/test_b_throughput_stability.py`:

```python
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
    while not stop_event.is_set():
        try:
            sock.settimeout(0.5)
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
    initial_heap = baseline["heap"]

    sock = tunnel_socket(22080)
    stop = threading.Event()
    sent = [0]
    recv = [0]
    t_send = threading.Thread(target=_continuous_send,
                              args=(sock, stop, sent), daemon=True)
    t_recv = threading.Thread(target=_continuous_recv,
                              args=(sock, stop, recv), daemon=True)
    t_send.start()
    t_recv.start()

    samples = []  # (t, recv_bps, heap)
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

    # Skip first 5s ramp-up
    samples = [s for s in samples if s[0] >= 5.0]
    bps_values = [s[1] for s in samples]

    # Stall detection: any 2-sample window below threshold
    stalls = []
    for i in range(len(samples) - 1):
        win_bps = (samples[i][1] + samples[i + 1][1]) / 2
        if win_bps < TH.B_MIN_STALL_BYTES_PER_S:
            stalls.append(samples[i][0])

    mean_bps = statistics.mean(bps_values) if bps_values else 0
    stddev = statistics.pstdev(bps_values) if bps_values else 0
    ratio = stddev / mean_bps if mean_bps > 0 else float("inf")

    final_heap = serial_monitor.latest().get("heap", 0)
    heap_drift = initial_heap - final_heap

    print(f"[B] mean={mean_bps:.0f} B/s stddev={stddev:.0f} ratio={ratio:.3f}")
    print(f"[B] stalls={len(stalls)} heap_drift={heap_drift} bytes")

    assert mean_bps > 0, "no throughput observed"
    assert ratio < TH.B_MAX_STDDEV_RATIO, (
        f"throughput stddev/mean = {ratio:.2f} > {TH.B_MAX_STDDEV_RATIO}")
    assert len(stalls) == 0, (
        f"{len(stalls)} stall windows below "
        f"{TH.B_MIN_STALL_BYTES_PER_S} B/s; first at t={stalls[0]:.1f}s")
    assert heap_drift <= TH.B_MAX_HEAP_DRIFT_BYTES, (
        f"heap drifted down by {heap_drift} bytes > "
        f"{TH.B_MAX_HEAP_DRIFT_BYTES}")
```

- [ ] **Step 10.2: Run**

```bash
cd test/integration/harness
pytest -v test_b_throughput_stability.py
```

Expected: PASS in ~5 minutes (`B_DURATION_S = 300`). The test prints the mean/stddev/stall/heap-drift summary line, useful for tracking baseline over time.

- [ ] **Step 10.3: Commit**

```bash
git add test/integration/harness/test_b_throughput_stability.py
git commit -m "test(integration): add Test B — throughput stability + heap drift"
```

---

## Task 11: Test D — Channel slot leaks

**Files:**
- Create: `test/integration/harness/test_d_channel_leaks.py`

- [ ] **Step 11.1: Write the test**

Create `test/integration/harness/test_d_channel_leaks.py`:

```python
"""Test D — Channel slot leaks across open/close cycles.

Open a TCP connection through the tunnel, transfer D_CHUNK_BYTES via echo,
close it. Repeat D_CYCLES times. After each cycle, verify the ESP32
returns to ch=0. After the full run, verify heap has not drifted.
"""
from __future__ import annotations

import time

from lib import thresholds as TH
from lib.pattern import make_stream


def _round_trip(sock, payload: bytes) -> bytes:
    received = bytearray()
    sock.settimeout(15.0)

    def _drain_some(target_total: int):
        try:
            while len(received) < target_total:
                sock.settimeout(0.2)
                buf = sock.recv(8192)
                if not buf:
                    return
                received.extend(buf)
        except (TimeoutError, OSError):
            pass

    sock.sendall(payload)
    while len(received) < len(payload):
        _drain_some(len(payload))
        if len(received) < len(payload):
            time.sleep(0.05)
    return bytes(received)


def test_channel_no_leak_over_cycles(wait_tunnel_ready, tunnel_socket,
                                      reset_stats_baseline, serial_monitor):
    wait_tunnel_ready()
    baseline = reset_stats_baseline()
    initial_heap = baseline["heap"]
    payload = make_stream(0xABCD, TH.D_CHUNK_BYTES)

    settled_observations = 0

    for i in range(TH.D_CYCLES):
        sock = tunnel_socket(22080)
        received = _round_trip(sock, payload)
        assert received == payload, f"cycle {i}: byte mismatch ({len(received)} bytes)"
        sock.close()

        time.sleep(TH.D_INTER_CYCLE_DELAY_S)

        # Wait up to 3s for ch to return to 0
        try:
            serial_monitor.wait_for(lambda s: s.get("ch", 99) == 0,
                                    timeout_s=3.0)
            settled_observations += 1
        except TimeoutError:
            snap = serial_monitor.latest()
            raise AssertionError(
                f"cycle {i}: ch did not return to 0 within 3s "
                f"(last snap: {snap})")

    final_heap = serial_monitor.latest().get("heap", 0)
    heap_drift = initial_heap - final_heap
    print(f"[D] settled={settled_observations}/{TH.D_CYCLES} "
          f"heap_drift={heap_drift} bytes")

    assert settled_observations == TH.D_CYCLES
    assert heap_drift <= TH.D_MAX_HEAP_DRIFT_BYTES, (
        f"heap drifted down {heap_drift} > {TH.D_MAX_HEAP_DRIFT_BYTES}")
```

- [ ] **Step 11.2: Run**

```bash
pytest -v test_d_channel_leaks.py
```

Expected: PASS in ~70 seconds (50 cycles × ~1.4s). Failure messages either pinpoint the cycle where `ch` did not settle, or report heap drift.

- [ ] **Step 11.3: Commit**

```bash
git add test/integration/harness/test_d_channel_leaks.py
git commit -m "test(integration): add Test D — channel slot leak detection"
```

---

## Task 12: Test F — Reconnect resilience

**Files:**
- Create: `test/integration/harness/test_f_reconnect.py`

- [ ] **Step 12.1: Write the test**

Create `test/integration/harness/test_f_reconnect.py`:

```python
"""Test F — Reconnect after sshd loss mid-transfer.

Start a 10 MB transfer; at 50% progress kill the sshd container; wait
F_DOWN_S; restart sshd; assert ESP32 returns to CONNECTED within
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
    baseline = reset_stats_baseline()

    # Kick off transfer
    payload = make_stream(0x1F1F, TH.F_TRANSFER_BYTES)
    sock = tunnel_socket(22080)
    sent_event = threading.Event()
    half = int(len(payload) * TH.F_KILL_AT_FRACTION)

    def _send():
        try:
            sock.sendall(payload[:half])
            sent_event.set()
            time.sleep(0.1)
            try:
                sock.sendall(payload[half:])
            except OSError:
                pass
        except OSError:
            sent_event.set()

    threading.Thread(target=_send, daemon=True).start()
    assert sent_event.wait(timeout=30.0), "did not reach 50% in 30s"

    # Kill sshd
    docker_ctl.kill("sshd")
    time.sleep(TH.F_DOWN_S)
    docker_ctl.start("sshd")

    # Wait for reconnect
    serial_monitor.wait_for(
        lambda s: s.get("state") == "CONNECTED",
        timeout_s=TH.F_RECONNECT_TIMEOUT_S)

    try:
        sock.close()
    except OSError:
        pass

    # Verify no panic in serial log
    raw = serial_monitor.raw_log()
    panic_markers = ["Guru Meditation", "abort()", "assertion", "CORRUPT HEAP"]
    panics = [line for line in raw if any(m in line for m in panic_markers)]
    assert not panics, f"panic markers in serial log: {panics[:3]}"

    # New transfer must work
    sock2 = tunnel_socket(22080)
    sock2.sendall(b"hello")
    sock2.settimeout(5.0)
    echoed = sock2.recv(16)
    sock2.close()
    assert echoed == b"hello", f"new transfer failed: got {echoed!r}"
```

- [ ] **Step 12.2: Run**

```bash
pytest -v test_f_reconnect.py
```

Expected: PASS within ~45 seconds. The test brings sshd back up itself, so subsequent tests still see a healthy stack.

- [ ] **Step 12.3: Commit**

```bash
git add test/integration/harness/test_f_reconnect.py
git commit -m "test(integration): add Test F — reconnect after sshd loss"
```

---

## Task 13: Test G — Backpressure / circuit breaker

**Files:**
- Create: `test/integration/harness/test_g_backpressure.py`

- [ ] **Step 13.1: Write the test**

Create `test/integration/harness/test_g_backpressure.py`:

```python
"""Test G — Circuit breaker + backpressure.

G1: repeatedly open channels through 22082 (mapped to dead port 65500
on Docker host), assert breaker_trips increments and a parallel channel
on 22080 keeps working.

G2: open a sustained burst on 22081 (slow_echo, 1 KB/s) while
simultaneously transferring on 22080; assert 22080's throughput stays
within G2_LIVE_THROUGHPUT_TOLERANCE of baseline.
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

    # Hammer the dead port; each attempt opens a channel that fails to connect
    # locally on the ESP32 side, incrementing the breaker counter.
    for i in range(TH.G1_ATTEMPTS):
        try:
            s = tunnel_socket(TH.G1_DEAD_PORT_MAPPING, timeout_s=5.0)
            time.sleep(0.5)
            s.close()
        except OSError:
            pass
        time.sleep(0.5)

    # Allow ESP32 telemetry to catch up
    time.sleep(3.0)
    final = serial_monitor.latest()
    delta_trips = final.get("breaker_trips", 0) - base_trips
    assert delta_trips >= 1, (
        f"breaker did not engage after {TH.G1_ATTEMPTS} attempts; "
        f"trips delta={delta_trips}")

    # Live mapping must still work
    live = tunnel_socket(TH.G1_PARALLEL_LIVE_MAPPING)
    live.sendall(b"ping\n")
    live.settimeout(5.0)
    got = live.recv(16)
    live.close()
    assert got == b"ping\n", f"live channel broken: got {got!r}"


def test_g2_slow_consumer_does_not_starve_others(wait_tunnel_ready,
                                                  tunnel_socket,
                                                  reset_stats_baseline,
                                                  serial_monitor):
    wait_tunnel_ready()

    # Baseline: measure 22080 throughput alone for 5s
    def _measure(sock, duration_s: float) -> int:
        sock.settimeout(0.5)
        end = time.monotonic() + duration_s
        recv = 0
        chunk = b"X" * 4096
        while time.monotonic() < end:
            try:
                sock.sendall(chunk)
            except OSError:
                break
            try:
                buf = sock.recv(8192)
                if buf:
                    recv += len(buf)
            except (TimeoutError, OSError):
                continue
        return recv

    live1 = tunnel_socket(TH.G2_LIVE_MAPPING)
    baseline_recv = _measure(live1, 5.0)
    live1.close()
    assert baseline_recv > 0, "no throughput on baseline measurement"

    # Now: start a slow_echo burst in background, re-measure 22080
    slow = tunnel_socket(TH.G2_SLOW_MAPPING, timeout_s=120.0)

    def _slow_burst():
        try:
            slow.sendall(make_stream(0xBADC, TH.G2_BURST_BYTES))
        except OSError:
            pass

    t = threading.Thread(target=_slow_burst, daemon=True)
    t.start()

    live2 = tunnel_socket(TH.G2_LIVE_MAPPING)
    under_load_recv = _measure(live2, 5.0)
    live2.close()
    slow.close()

    ratio = under_load_recv / baseline_recv if baseline_recv > 0 else 0
    print(f"[G2] baseline={baseline_recv} B/5s under_load={under_load_recv} "
          f"ratio={ratio:.3f}")

    # Allow a tolerance: under_load may be slightly slower but must be
    # within G2_LIVE_THROUGHPUT_TOLERANCE of baseline
    assert ratio >= (1.0 - TH.G2_LIVE_THROUGHPUT_TOLERANCE), (
        f"live channel throughput dropped from {baseline_recv} to "
        f"{under_load_recv} ({ratio:.2%}) when slow_echo was busy")
```

- [ ] **Step 13.2: Run**

```bash
pytest -v test_g_backpressure.py
```

Expected: both subtests PASS within ~30 seconds. G1 prints the trip delta; G2 prints the baseline/under_load/ratio summary.

- [ ] **Step 13.3: Run the full integration suite once**

```bash
make test-integration
```

Expected: all 5 test files green. Total runtime ~10-15 minutes (Test B alone is 5 min).

- [ ] **Step 13.4: Commit**

```bash
git add test/integration/harness/test_g_backpressure.py
git commit -m "test(integration): add Test G — circuit breaker + backpressure"
```

---

## Self-review checklist (run by the executor before declaring done)

- [ ] All 13 tasks committed with message prefixes `refactor:`, `test:`, `ci:`, `feat:` consistent with existing project style.
- [ ] `pio run -e arduino-3` is green on the final tip of the branch (firmware still builds with all refactors applied).
- [ ] `pio test -e native -v` reports 33 tests (1 smoke + 12 circuit breaker + 10 validators + 10 prepend buffer), zero failures.
- [ ] `make test-integration` runs to completion against a real ESP32 + Docker stack with all 5 scenarios green at least once.
- [ ] No new files contain `TBD`, `TODO`, or `xxx` placeholders.
- [ ] `clang-format --dry-run --Werror` (run by existing `lint:` CI job) passes on all newly created `.h` files.
- [ ] `.github/workflows/ci.yml` includes the `test-native` job and the YAML is syntactically valid.
- [ ] `docs/superpowers/specs/2026-04-23-throughput-tests-design.md` requirements are all addressed (every section in the spec maps to at least one task above).
