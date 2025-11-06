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

## Troubleshooting

- Make sure the root library dependencies are installed (`pio pkg install`,
  automatically handled in CI).
- If you change the target board, update `examples/platformio.ini`.
- Use `globalSSHConfig.setDebugConfig(true, 115200);` to increase log verbosity.
