# Examples – ESP-Reverse_Tunneling_Libssh2

This folder contains ready-to-build sketches that demonstrate how to use the
library on a standard ESP32 board.

## Layout

- `platformio.ini` – minimal PlatformIO project definition referencing the
  library from the repository root.
- `src/main.cpp` – fully working reverse-tunnel example (Wi-Fi setup, SSH
  configuration, tunnel loop, periodic stats).
- `sdkconfig.*` – generated PlatformIO SDK defaults (kept for convenience).

No `.ino` sketches or helper scripts are required; everything builds from
`src/main.cpp`.

## Build

```bash
cd examples
pio run          # compile the example
pio run -t upload  # flash your connected ESP32
pio device monitor  # watch serial logs (115200 by default)
```

## Customize

Edit `src/main.cpp` and adjust:

- Wi-Fi credentials (`WIFI_SSID`, `WIFI_PASSWORD`)
- SSH server settings (`globalSSHConfig.setSSHServer` /
  `setSSHKeyAuthFromMemory`)
- Tunnel parameters (`setTunnelConfig`)
- Optional tuning (`setBufferConfig`, `setKeepAliveOptions`, `setLogLevel`, …)

### Multi-tunnel demo

`src/main.cpp` now ships with an optional multi-tunnel scenario guarded by the
`ENABLE_MULTI_TUNNEL_DEMO` flag at the top of the file. When the flag is set to
`1` (default), `configureMultiTunnelMappings()` clears the legacy single tunnel,
enables up to three reverse listeners via `setMaxReverseListeners()`, and adds
several sample mappings:

```cpp
globalSSHConfig.clearTunnelMappings();
globalSSHConfig.setMaxReverseListeners(3);

globalSSHConfig.addTunnelMapping("0.0.0.0", 22080, "192.168.1.100", 80);
globalSSHConfig.addTunnelMapping("0.0.0.0", 22081, "192.168.1.150", 5020);
globalSSHConfig.addTunnelMapping("127.0.0.1", 22082, "192.168.1.200", 22);
```

If you prefer the original single-listener behaviour, set
`#define ENABLE_MULTI_TUNNEL_DEMO 0` and the sketch will revert to
`setTunnelConfig()`.

### Callback helpers

To illustrate the new `SSHTunnelEvents` interface, the example registers a
handful of lightweight callbacks (`registerTunnelCallbacks()`), printing when
the SSH session connects/disconnects, when channels open/close (with reasons),
and when large transfers start or end. Replace the logging lambdas with your
own application logic if you need deeper integration.

## Troubleshooting

- Make sure the root library dependencies are installed (`pio pkg install`,
  automatically handled in CI).
- If you change the target board, update `examples/platformio.ini`.
- Use `globalSSHConfig.setDebugConfig(true, 115200);` to increase log verbosity.
