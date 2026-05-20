# Stabilization release design — 2.2.0

Target version: **2.2.0** (minor bump from 2.1.2)
Driving artifact: `docs/superpowers/test-reports/2026-04-28-baseline.md`
Goal: close the three reliability bugs surfaced by the first end-to-end
integration run, plus the harness improvements they depend on, in a single
release.

## Scope

Single release ("stabilization") delivering:

- Bug #1 — small-chunk byte loss / channel re-allocation race (HIGH)
- Bug #2 — stale `tcpip-forward` listeners survive ESP32 reconnect (HIGH)
- Bug #3 — channel teardown latency on high-RTT links (MEDIUM)
- Harness: `listeners_ready=N` in `STATS_TEST`, `wait_tunnel_ready` waits on
  it, Test F retries the post-reconnect probe, Test A repeat variants for
  Bug #1 reproduction.

**Public C++ API**: unchanged. One additive read-only accessor on
`SSHSession` (`getActiveListenerCount()`) for diagnostics.

**Deployment contract**: sshd-side `ClientAliveInterval` is recommended to
get the full benefit of Bug #2's fix. Documented in CHANGELOG, not enforced.

## Non-goals (this release)

- Adaptive `EOF_GRACE_MS` based on measured RTT.
- Ring-buffer pool to avoid alloc/free thrash on rapid bind/unbind cycles
  (only if Bug #1's narrowing rules out the simpler fixes).
- Any refactor of `ssh_transport.cpp` beyond the fast-path EOF needed for
  Bug #3.
- Layer 1 (host-only Unity) test additions — current 33/33 stays as
  regression baseline.

---

## Bug #2 — stale `tcpip-forward` listeners

### Root cause

When the ESP32's TCP link dies (Wi-Fi loss, keepalive failure), libssh2
cannot deliver `cancel-tcpip-forward` to sshd. Sshd keeps the listener
bound on 22080/22081/22082. The next session the firmware opens succeeds
at the SSH layer but its `tcpip-forward` requests are rejected by sshd
with `bind [::]:22080: Address in use`. From the firmware's point of view
`libssh2_channel_forward_listen_ex` returns a handle and the session
appears healthy, but no traffic flows.

### Fix — three layers

#### Layer A — Sshd config (`test/integration/docker/sshd/sshd_config`)

Add:

```
ClientAliveInterval 15
ClientAliveCountMax 2
```

Sshd reaps zombie sessions in ~30 s and frees their listeners regardless
of what the firmware does. This is the only layer that works when the
firmware crashes or loses power — it must be present.

#### Layer B — Firmware (`src/ssh_session.cpp`)

1. Audit `libssh2_channel_forward_listen_ex` (l.708) usage. Confirm that
   when sshd refuses the bind, libssh2 reports it (return code or session
   error). If it does not, treat it as a known limitation and rely on
   layer A; document in code comment.
2. Verify `cancelAllListeners()` is called in every teardown path that
   may precede a reconnect:
   - `disconnect()` — already does (l.154).
   - `enterErrorState()` in `ssh_tunnel.cpp` — calls `session_.disconnect()`
     (l.699), confirm cancellation runs even when the socket is unhealthy.
3. Add public read-only accessor `int getActiveListenerCount() const` on
   `SSHSession`, returning the number of `ListenerEntry` currently bound.
   Cheap getter, no lock required if `listeners_` mutation is already
   serialized via the session lock.

#### Layer C — Test telemetry (`test/integration/firmware/main_test.cpp`)

Extend the `STATS_TEST` line at l.96:

```
STATS_TEST t=... state=... ch=... sent=... recv=... dropped=... listeners_ready=N heap=...
```

`N` = `tunnel.session_.getActiveListenerCount()`, exposed via a thin
accessor on `SSHTunnel` if needed (test-only, can live behind
`TUNNEL_TEST_BUILD`).

### Harness changes (Bug #2)

- `test/integration/harness/lib/serial_stats.py` (or wherever stats are
  parsed): parse `listeners_ready` field; add `expected_listeners` arg to
  `wait_tunnel_ready()` defaulting to the number of mappings.
- `test_f_reconnect.py`: after reconnect, retry the
  "hello-after-reconnect" probe up to 3 times with 5 s spacing before
  failing. Listeners-ready alone may not be a sufficient signal (sshd may
  still be settling).

### Acceptance

- Test F passes 3 consecutive runs on LAN.
- After a manual `docker kill` + restart of sshd, the next reconnect
  shows `listeners_ready=3` within 35 s and a fresh data transfer
  succeeds.

---

## Bug #1 — small-chunk byte loss / re-bind race

### Symptoms recap

Chunks ≤ 1024 B, or back-to-back Test A runs in the same pytest session,
trigger:

- `BrokenPipeError` on the next `sock.sendall()`.
- `recv()` returning 0 before any data arrives.
- One observed partial transfer: 1048339 / 1048576 bytes (237 missing).

ESP32 reports `state=Connected dropped=0`, occasionally
"Rejecting accepted channel after bind failure", heap is healthy.

### Strategy: reproduce before fixing

#### 1.1 Repro narrowing (must succeed before any fix)

Add to `test/integration/harness/test_a_data_integrity.py`:

- `test_echo_repeat_small[1024-100KB-x10]` — 10 sequential transfers,
  same pytest session, 1024 B chunks, 100 KB each.
- `test_echo_repeat_mid[256-1MB-x5]` — 5 sequential transfers at 256 B
  chunks × 1 MB.

Each iteration must:

- Capture the full serial log between cycles (not just `STATS_TEST`)
  including `bindChannel` / `finalizeClose` / "Rejecting accepted channel"
  lines.
- Record byte loss as `expected_total - received_total` per cycle.

**Success criterion for narrowing**: the failure reproduces in ≥ 80 % of
runs. If the repro is unstable, fix is speculative — pause and reconsider
before coding.

#### 1.2 Candidate fixes (validate after narrowing pinpoints the path)

Three suspects ranked by likelihood and cost:

**Suspect A — premature slot reuse in `ChannelManager::allocateSlot()`**
(`src/ssh_channel.cpp` l.74-98). The function returns the first slot with
`!slot.active`, but `finalizeClose()` flips `active=false` (l.283) before
libssh2 has fully digested the channel free. A new `bindChannel` arriving
in the same `loop()` tick can claim that slot and run with stale-adjacent
state.

Fix: add `unsigned long lastFinalizeMs` to `ChannelSlot`. In
`allocateSlot`, skip slots where `now - lastFinalizeMs < 50 ms`. Set the
field at the end of `finalizeClose`. Cheap, contained, no behavior change
when traffic is normal.

**Suspect B — bytes lost on `Open → Draining` while ring not flushed**
(`src/ssh_transport.cpp` `drainLocalToSsh`, l.332+ and l.476+). When the
local socket sends EOF (peer's `sock.shutdown(1)`), the transition to
Draining can fire while `toRemote` still holds bytes the libssh2 write
loop has not flushed. Those bytes die with the slot.

Fix: gate the `Open → Draining` transition on
`toRemote->size() == 0 && !sshWritePending`. If either is non-zero, keep
pumping for one more cycle. The half-close timeout already exists
(l.516+) as a safety net.

**Suspect C — heap fragmentation on rapid bind/unbind**. The heap guard
in `bindChannel` (l.169-193) checks `largest_free_block`. After several
back-to-back close + open cycles, PSRAM may be technically free but
fragmented enough to refuse a contiguous ring buffer allocation. The
"Rejecting accepted channel after bind failure" log line in the report
(l.79) is consistent with this.

Fix (if A and B don't close it): a small pool of pre-allocated ring
buffers reused across bind cycles. Larger change — only attempt if the
narrowing rules out A and B.

### Acceptance

- The repro narrowing tests pass 100 consecutive cycles.
- No "Rejecting accepted channel after bind failure" lines during the
  100-cycle run.
- `dropped=0` and `sent==recv` at the end of every cycle.

---

## Bug #3 — channel teardown latency on high-RTT

### Gate before any fix: LAN baseline

Re-run Test D on stable LAN (home Wi-Fi).

- **If `ch` returns to 0 in < 3 s on LAN**: bug is environmental, no code
  fix. Document the high-RTT threshold in the harness and close the item.
- **If `ch` stays > 3 s on LAN too**: continue with the fix below.

This gate is in the test report (l.255) — no speculative fix.

### Fix (conditional on the gate)

Target: `TransportPump::drainLocalToSsh`, EOF + grace step around
`ssh_transport.cpp` l.594-626.

Add a fast-path before the 200 ms `EOF_GRACE_MS` wait:

```
if rings empty
   and no libssh2 write EAGAIN in flight
   and no bytes flowed in either direction for >100 ms
then finalize immediately, skip the grace wait
```

The grace period stays for cases where bytes may still be in libssh2's
internal buffers. Only the truly idle close path is fast-pathed.

### Why not lower `EOF_GRACE_MS` globally

200 ms protects against losing fragments libssh2 has not yet flushed.
Lowering it everywhere risks regressing Bug #1's territory. A conditional
fast-path is safer.

### Acceptance

- Test D on LAN: `ch` returns to 0 in < 1 s in the idle-close case.
- No regression on Test A throughput (the fast-path must not trigger
  during active transfers).

---

## Testing strategy

### Layer 1 — host-only Unity

No additions. The 33 existing tests stay green as a regression baseline.

### Layer 2 — integration

#### Pre-test setup (codified in `Makefile` target `test-clean`)

```
docker kill tunnel_test_sshd && docker start tunnel_test_sshd
# wait for "Reverse listener ready 22080/22081/22082" on serial
# wait for listeners_ready=3 in STATS_TEST
```

This avoids the contamination patterns the report flags (Bug #2 stale
listeners, Test D cycle 0, Test G post-Test-F state).

#### Test order in pytest

`G1, G2 → A → A repeat (new) → D → F → B`

G1/G2 first to avoid post-F contamination. B last because it is the
longest (5 min).

#### Per-test acceptance

| Test | Criterion |
|---|---|
| Test A original (8 KB / 64 KB chunks × 1 MB) | PASS |
| Test A repeat 1024-100KB × 10 (new) | PASS — Bug #1 |
| Test A repeat 256-1MB × 5 (new) | PASS — Bug #1 |
| Test B 5 min on LAN | stddev/mean < 0.30, stalls = 0 |
| Test D | `ch` returns to 0 in < 3 s on LAN |
| Test F (with retry × 3) | PASS — Bug #2 |
| Test G1 breaker | `breaker_trips ≥ 1` after 10 dead-port attempts |
| Test G2 slow consumer | PASS |

### Hardware / environment

LAN (home Wi-Fi) required for release validation. Hotspot is acceptable
for iterating during development but not for closing the release.

### Release gate

All Layer 2 tests pass **two consecutive runs** on LAN with hard sshd
restart between runs. A single green run can mask intermittent bugs;
two consecutive greens is the minimum bar.

---

## Versioning and release notes

### Version bump

`library.json` and `library.properties`: 2.1.2 → **2.2.0** (minor).

Justification:

- New public read-only API: `SSHSession::getActiveListenerCount()`.
- New `STATS_TEST` field (`listeners_ready=N`) — additive but parsers
  that key by position rather than by name will need update.
- Deployment recommendation around sshd `ClientAliveInterval` is a
  contract change in spirit, even though no C++ symbol changes.

### CHANGELOG entry (draft)

```
## 2.2.0 — Stabilization

### Fixes
- Channel re-allocation race causing small-chunk byte loss when transfers
  use chunks <= 1 KB or when sessions are torn down and re-opened
  back-to-back (Bug #1).
- Stale tcpip-forward listeners survived ESP32 reconnects, leaving the
  tunnel in a "Connected but zero-forward" state. Requires sshd-side
  ClientAliveInterval to be fully effective (Bug #2).
- Channel teardown latency on high-RTT links: fast-path EOF when no data
  is in flight cuts close time from up to 20s to <1s (Bug #3).

### Additions
- SSHSession::getActiveListenerCount() for diagnostics.
- STATS_TEST now reports listeners_ready=N (test build only).

### Deployment notes
- Recommend setting ClientAliveInterval 15 / ClientAliveCountMax 2 on
  your sshd. The library cannot release listeners on a network-killed
  session by itself; sshd needs to reap zombies.
```

---

## Implementation order (single release, but coded in this sequence)

1. **Bug #2 layer A + C + harness `listeners_ready`** — gives the
   diagnostic signal everything else relies on.
2. **Bug #2 layer B + Test F retry** — closes Bug #2.
3. **Bug #1 repro narrowing** — must reproduce ≥ 80 % before fixing.
4. **Bug #1 fix** (Suspect A first, then B if needed, then C if needed).
5. **Bug #3 LAN baseline** — gate.
6. **Bug #3 fast-path EOF** if gate says so.
7. **Two green runs on LAN** — release gate.
8. Bump 2.1.2 → 2.2.0, write CHANGELOG, tag.

This is one release, but the sequence is required because each step's
validation depends on the previous step's signal.
