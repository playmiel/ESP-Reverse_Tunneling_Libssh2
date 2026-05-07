# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.0] — 2026-04-30 — Stabilization

### Fixes

- **Bug #1 — channel re-allocation race causing small-chunk byte loss.**
  Two-part fix:
  - 50 ms cooldown after `finalizeClose` before a slot can be re-bound,
    so libssh2's channel free has time to settle before the slot is
    reused (`082e8d4`).
  - Forward the SSH EOF to the local TCP socket via `shutdown(SHUT_WR)`
    as soon as `remoteEof` is set and the outbound ring is drained.
    Echo-style backends only respond to bytes we send them; without
    this, they never volunteer EOF on their own and the channel stayed
    in half-close until `HALF_CLOSE_TIMEOUT_MS` (5 s) fired, blocking
    back-to-back tunnel reuse (`4e174d2`).

  Repro count via `test_echo_repeat` (1 KB and 256 B chunks):
  - Pre-fix: 15/15 cycles fail
  - After cooldown only: 4/15 cycles fail
  - After EOF forwarding: 0/15 in 10+ consecutive runs

- **Bug #2 — stale `tcpip-forward` listeners survived ESP32 reconnects.**
  When the ESP32's TCP link died, libssh2 could not deliver
  `cancel-tcpip-forward` to sshd, which kept the listener bound. The
  next reconnect's forward request was rejected with
  `bind [::]:22080: Address in use`, leaving the tunnel in a
  "Connected but zero-forward" state. Logged at warning level now and
  documented as requiring sshd-side `ClientAliveInterval` to fully
  reap zombie sessions (`3449d82`).

### Additions

- `SSHSession::getActiveListenerCount()` (and matching forwarder on
  `SSHTunnel`) for diagnostics.
- `STATS_TEST` integration-test telemetry now reports
  `listeners_ready=N` so harness fixtures can wait deterministically
  for all configured forwards to be bound (test build only).

### Diagnostics & docs

- **Bug #3 — channel teardown latency on high-RTT links** is resolved
  as a side-effect of Bug #1's EOF-forwarding fix: with the local
  socket now being shut down on remote EOF, the echo-side EOF arrives
  promptly and the existing `(remoteEof && localEof)` branch closes
  the channel without burning the 5 s grace window. Test D (50 cycles
  on LAN) returns to `ch=0` well within the 3 s threshold for every
  cycle. No dedicated fast-path needed.
- New integration test suites under `test/integration/harness/`:
  Tests B (throughput stability), D (channel leak), F (reconnect),
  G (circuit breaker + slow consumer), and a Bug #1 narrowing
  variant of Test A (`test_echo_repeat_small`/`_mid`).
- New host-only Unity tests for `circuit_breaker`, `ssh_config`
  validators, and `prepend_buffer` (33/33 PASS in CI).
- Test reports under `docs/superpowers/test-reports/` (untracked,
  local-only) record the validation runs.

### Deployment notes

- **Recommended sshd config** for the remote bastion:
  `ClientAliveInterval 15` and `ClientAliveCountMax 2`. The library
  cannot release listeners on a network-killed session by itself —
  sshd needs to reap zombies for the next reconnect's
  `tcpip-forward` to bind cleanly. Without this, Bug #2 can still
  manifest after a hard network drop even with this release's
  firmware fixes.
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.0] — 2026-04-30 — Stabilization

### Fixes

- **Bug #1 — channel re-allocation race causing small-chunk byte loss.**
  Two-part fix:
  - 50 ms cooldown after `finalizeClose` before a slot can be re-bound,
    so libssh2's channel free has time to settle before the slot is
    reused (`082e8d4`).
  - Forward the SSH EOF to the local TCP socket via `shutdown(SHUT_WR)`
    as soon as `remoteEof` is set and the outbound ring is drained.
    Echo-style backends only respond to bytes we send them; without
    this, they never volunteer EOF on their own and the channel stayed
    in half-close until `HALF_CLOSE_TIMEOUT_MS` (5 s) fired, blocking
    back-to-back tunnel reuse (`4e174d2`).

  Repro count via `test_echo_repeat` (1 KB and 256 B chunks):
  - Pre-fix: 15/15 cycles fail
  - After cooldown only: 4/15 cycles fail
  - After EOF forwarding: 0/15 in 10+ consecutive runs

- **Bug #2 — stale `tcpip-forward` listeners survived ESP32 reconnects.**
  When the ESP32's TCP link died, libssh2 could not deliver
  `cancel-tcpip-forward` to sshd, which kept the listener bound. The
  next reconnect's forward request was rejected with
  `bind [::]:22080: Address in use`, leaving the tunnel in a
  "Connected but zero-forward" state. Logged at warning level now and
  documented as requiring sshd-side `ClientAliveInterval` to fully
  reap zombie sessions (`3449d82`).

### Additions

- `SSHSession::getActiveListenerCount()` (and matching forwarder on
  `SSHTunnel`) for diagnostics.
- `STATS_TEST` integration-test telemetry now reports
  `listeners_ready=N` so harness fixtures can wait deterministically
  for all configured forwards to be bound (test build only).

### Diagnostics & docs

- **Bug #3 — channel teardown latency on high-RTT links** is resolved
  as a side-effect of Bug #1's EOF-forwarding fix: with the local
  socket now being shut down on remote EOF, the echo-side EOF arrives
  promptly and the existing `(remoteEof && localEof)` branch closes
  the channel without burning the 5 s grace window. Test D (50 cycles
  on LAN) returns to `ch=0` well within the 3 s threshold for every
  cycle. No dedicated fast-path needed.
- New integration test suites under `test/integration/harness/`:
  Tests B (throughput stability), D (channel leak), F (reconnect),
  G (circuit breaker + slow consumer), and a Bug #1 narrowing
  variant of Test A (`test_echo_repeat_small`/`_mid`).
- New host-only Unity tests for `circuit_breaker`, `ssh_config`
  validators, and `prepend_buffer` (33/33 PASS in CI).
- Test reports under `docs/superpowers/test-reports/` (untracked,
  local-only) record the validation runs.

### Deployment notes

- **Recommended sshd config** for the remote bastion:
  `ClientAliveInterval 15` and `ClientAliveCountMax 2`. The library
  cannot release listeners on a network-killed session by itself —
  sshd needs to reap zombies for the next reconnect's
  `tcpip-forward` to bind cleanly. Without this, Bug #2 can still
  manifest after a hard network drop even with this release's
  firmware fixes.
