# Integration test harness

Drives a real ESP32 (running `firmware/main_test.cpp`) through reverse SSH
tunnels exposed by a local Docker stack (sshd + echo + slow_echo).

## Prerequisites

- Docker Compose v2
- ESP32 attached via USB, accessible directly as a Windows COM port or from
  Linux/WSL as `/dev/ttyUSB*`
- Python 3.11+
- Environment variables exported (see Setup)

## Setup

```bash
export TEST_WIFI_SSID="your-wifi"
export TEST_WIFI_PASS="your-wifi-password"
export TEST_DOCKER_HOST_IP="192.168.1.42"   # IP of WSL host on your LAN
export TEST_SERIAL_PORT="/dev/ttyUSB1"
make flash-test                              # one-time, or after firmware change
```

On Windows PowerShell, credentials may be omitted when the ESP32 already has
working Wi-Fi credentials stored in NVS:

```powershell
$env:TEST_DOCKER_HOST_IP = "192.168.1.42"
$env:TEST_SERIAL_PORT = "COM5"
pio run -e test_integration -t upload --upload-port COM5
uv run --project test/integration/harness pytest test/integration/harness
```

## Run

```bash
make test-integration         # full cycle: docker up + tests + docker down
make test-integration-up      # bring stack up once
make test-integration-quick   # run tests against already-up stack
make test-integration-down    # tear stack down
```

## Stack components

| Service | Container | Port (host) | Purpose |
|---|---|---|---|
| `sshd` | `tunnel_test_sshd` | 2222→22 (SSH), 22080-22082 (reverse listeners) | ESP32 connects here; remote ports forwarded back through the tunnel |
| `echo` | `tunnel_test_echo` | 9000 | TCP echo (socat) — used by tests A, B, D, F |
| `slow_echo` | `tunnel_test_slow_echo` | 9001 | TCP echo throttled to 1 KB/s (Python) — used by test G2 |

The test firmware maps:
- `22080 → DOCKER_HOST_IP:9000` (live target)
- `22081 → DOCKER_HOST_IP:9001` (slow consumer)
- `22082 → DOCKER_HOST_IP:65500` (dead port, triggers circuit breaker)

Tests A and B pace the synthetic echo stream at 128 KiB/s. Unlike the Modlink
production path, this Docker echo topology crosses the ESP32 Wi-Fi link four
times per round trip; the controlled rate tests tunnel stability without
turning Wi-Fi saturation into the pass/fail criterion. The Docker sshd uses
the same 30 s × 6 client-alive tolerance observed on Modlink. `GatewayPorts`
remains enabled only so Windows can reach the published Docker listener ports.

SSH credentials in the test environment: `testuser` / `testpass` (hardcoded
in the sshd Dockerfile — never use this stack outside isolated dev networks).

## Fallback if WSL2 mirrored networking is unavailable

On the Windows host, run as Administrator (one-time):

```powershell
netsh interface portproxy add v4tov4 listenport=2222 listenaddress=0.0.0.0 connectport=2222 connectaddress=<WSL_IP>
netsh interface portproxy add v4tov4 listenport=9000 listenaddress=0.0.0.0 connectport=9000 connectaddress=<WSL_IP>
netsh interface portproxy add v4tov4 listenport=9001 listenaddress=0.0.0.0 connectport=9001 connectaddress=<WSL_IP>
```

Get `<WSL_IP>` with `wsl hostname -I` from PowerShell.
