# Native ESP-IDF example

This project uses the same `playmiel/libssh2_esp32` fork as the Arduino build,
through the pinned `components/libssh2_esp` submodule. For integration into
another project, see the [ESP-IDF guide](../../docs/ESP_IDF.md).

```bash
git submodule update --init --recursive
cd examples/esp-idf
idf.py set-target esp32
idf.py menuconfig
idf.py -p COM5 build flash monitor  # replace COM5 with your serial port
```

Set the Wi-Fi SSID/password, SSH host/port/user/password, verified SHA256 host
key fingerprint, and reverse tunnel destination under **Reverse tunnel example**
in menuconfig. For the local Docker integration stack, use the PC's LAN IPv4
address as both SSH host and destination host, SSH port `2222`, remote bind
port `22080`, and destination port `9000` (the echo service). The destination
must be reachable from the ESP32 before opening a forwarded connection.

The example reserves an 8 KiB main-task stack. When PSRAM is available, it
uses up to 10 channels with two 64 KiB ring buffers per active channel. With
PSRAM disabled or absent, it uses one channel with two 8 KiB rings. To enable
PSRAM on a board that has it, run `idf.py menuconfig` and select **Component
config → ESP PSRAM → Support for external, SPI-connected RAM**. Keep the chip
type on **Auto-detect**, choose the board's supported RAM speed, then rebuild
and check the boot log for detected PSRAM. If an existing `sdkconfig` predates
`sdkconfig.defaults`, set `CONFIG_ESP_MAIN_TASK_STACK_SIZE=8192` before
building. See [PSRAM details](../../docs/ESP_IDF.md#psram-and-channel-buffers).

After the monitor reports `Tunnel connected, bound port 22080`, test the echo
path from inside the SSH container:

```sh
docker exec tunnel_test_sshd sh -lc 'printf "ESP-IDF tunnel test\n" | nc -w 8 ::1 22080'
```

The command should print `ESP-IDF tunnel test`. The SSH container in this
stack listens on IPv6 for the reverse port, so `::1` is the local listener
address to use for this check.
