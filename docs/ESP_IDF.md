# Native ESP-IDF integration

The library works as an ESP-IDF component. It uses the pinned
[`libssh2_esp32`](https://github.com/playmiel/libssh2_esp32) submodule in
`components/libssh2_esp`. Arduino/PlatformIO uses the same fork as a library
dependency; see the [Arduino example](../examples/README.md).

## Add both components to an ESP-IDF project

Clone this repository into your project's `components` directory and initialize
the nested submodule:

```sh
git clone --branch esp-idf --recurse-submodules https://github.com/playmiel/ESP-Reverse_Tunneling_Libssh2.git components/ESP-Reverse_Tunneling_Libssh2
```

The `--branch esp-idf` option is needed until these changes are merged into
`main`; after the merge, use the default branch.

In the consuming project's top-level `CMakeLists.txt`, before `project.cmake`,
add both component paths:

```cmake
cmake_minimum_required(VERSION 3.16)
set(TUNNEL_COMPONENT "${CMAKE_CURRENT_LIST_DIR}/components/ESP-Reverse_Tunneling_Libssh2")
set(EXTRA_COMPONENT_DIRS
    "${TUNNEL_COMPONENT}"
    "${TUNNEL_COMPONENT}/components/libssh2_esp")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(my_project)
```

In the consuming app's `main/CMakeLists.txt`, declare the tunnel component in
`REQUIRES` (and `esp_wifi`, `esp_netif`, and `nvs_flash` if the app connects to
Wi-Fi as the example does). Include `ESP-Reverse_Tunneling_Libssh2.h`, configure
`globalSSHConfig`, then call `SSHTunnel::init()`, `connectSSH()`, and `loop()`
from a task. The [native example](../examples/esp-idf/README.md) provides a
complete starting point and `menuconfig` entries for network settings.

The example reserves an 8 KiB main-task stack through `sdkconfig.defaults`.
An app that runs the tunnel on another task must give that task enough stack
for the SSH handshake and its own work.

## PSRAM and channel buffers

PSRAM is optional. On a board that physically has PSRAM, enable it in
`idf.py menuconfig` under **Component config → ESP PSRAM → Support for external,
SPI-connected RAM**. For a classic ESP32, keep chip type **Auto-detect**, use
the board's supported SPI RAM speed, and select **Make RAM allocatable using
malloc() as well**. Build and flash again, then check the boot log for detected
PSRAM. `CONFIG_SPIRAM=y` in `sdkconfig` alone does not prove that the chip is
present or working.

The native example checks available PSRAM at runtime. With PSRAM it configures
up to 10 channels and 64 KiB per directional ring buffer; without PSRAM it
uses one channel and 8 KiB per direction. The latter mode was tested on an
ESP32 with PSRAM disabled in `sdkconfig`. Tune this in
[`main.cpp`](../examples/esp-idf/main/main.cpp) for your board and traffic.
Each active channel allocates two rings and additional transport storage.

`sdkconfig` can contain Wi-Fi and SSH passwords. Keep it out of Git; the native
example's `.gitignore` rule does this for its own configuration file.

## Authentication and test

Use `setSSHServer()` for password authentication or
`setSSHKeyAuthFromMemory()` for keys supplied by the application. The native
`setSSHKeyAuth()` path reads the private key and `.pub` file from a mounted
ESP-IDF VFS. Configure `setHostKeyVerification()` with the SSH server's actual
SHA256 host-key fingerprint.

For a local Docker SSH server and echo target, follow the
[ESP-IDF example's Docker test](../examples/esp-idf/README.md). It covers
ports, the serial monitor, and a complete echo round trip through the ESP32.
