# ESP-Reverse_Tunneling_Libssh2

Reverse SSH tunnels and a SOCKS5 reverse proxy for ESP32, with **Arduino** and
**native ESP-IDF** support. Both options use
[playmiel/libssh2_esp32](https://github.com/playmiel/libssh2_esp32).

## Choose a framework

| Framework | Dependency | Build and example |
|-----------|------------|-------------------|
| Arduino / PlatformIO | `lib_deps` fetches `libssh2_esp32` from its `codex/esp-idf-component` branch | [Arduino example](examples/README.md) · `pio run -e arduino-3` |
| Native ESP-IDF | The pinned `components/libssh2_esp` submodule provides the same fork as an ESP-IDF component | [ESP-IDF guide](docs/ESP_IDF.md) · [ESP-IDF example](examples/esp-idf/README.md) |

### Arduino / PlatformIO

Add both libraries to your project's `platformio.ini`:

```ini
lib_deps =
    https://github.com/playmiel/ESP-Reverse_Tunneling_Libssh2.git
    https://github.com/playmiel/libssh2_esp32.git#codex/esp-idf-component
```

The repository's [PlatformIO configuration](platformio.ini) already uses
these dependencies. In Arduino IDE, install this library and the
`libssh2_esp32` fork in your libraries folder.

### Native ESP-IDF

Clone with `--recurse-submodules`, then use the
[native integration guide](docs/ESP_IDF.md) to add both components to your
project. To try the ready-made project:

```bash
git submodule update --init --recursive
cd examples/esp-idf
idf.py set-target esp32
idf.py menuconfig
idf.py build flash monitor
```

The ESP-IDF example configures Wi-Fi, SSH credentials, host key verification,
and the tunnel destination through `menuconfig`. PSRAM can be enabled there
when the board has it; the example also runs without PSRAM using smaller
buffers.

## Arduino usage

```cpp
#include "ESP-Reverse_Tunneling_Libssh2.h"
#include <Arduino.h>
#include <WiFi.h>

SSHTunnel tunnel;

void setup() {
    Serial.begin(115200);
    
    // WiFi configuration
    WiFi.begin("YOUR_SSID", "YOUR_PASSWORD");
    while (WiFi.status() != WL_CONNECTED) delay(100);
    
    // SSH tunnel configuration with password
    globalSSHConfig.setSSHServer("server.com", 22, "user", "password");
    
    globalSSHConfig.setTunnelConfig("127.0.0.1", 8080, "192.168.1.100", 80);
    globalSSHConfig.setHostKeyVerification("SHA256:REPLACE_WITH_REAL_FINGERPRINT");

    if (tunnel.init()) tunnel.connectSSH();
}

void loop() {
    tunnel.loop();
}
```

### SSH Key Authentication

This library supports three methods for SSH key authentication:

1. **Memory-based authentication** (recommended for ESP32/LittleFS):
   ```cpp
   globalSSHConfig.setSSHKeyAuth("server.com", 22, "user", "/ssh_key");
   ```

2. **Direct memory loading**:
   ```cpp
   globalSSHConfig.setSSHKeyAuthFromMemory("server.com", 22, "user", privateKey, publicKey);
   ```

3. **Manual key loading**:
   ```cpp
   globalSSHConfig.loadSSHKeysFromLittleFS("/ssh_key");
   ```

📖 **Detailed guide**: [SSH Keys with Memory Authentication](docs/SSH_KEYS_MEMORY.md)

### Host Key Verification (Security)

For production environments, enable host key verification to prevent Man-in-the-Middle attacks:

```cpp
// Configure SSH with host key verification
globalSSHConfig.setSSHKeyAuthFromMemory("server.com", 22, "user", privateKey, publicKey);

// Enable host key verification (recommended for production)
globalSSHConfig.setHostKeyVerification(
    "SHA256:abcd1234efgh5678ijkl9012mnop3456qrst7890uvwx1234yz56",  // Accept OpenSSH format or 64-char hex
    "ssh-rsa",
    true
);

// Optional: receive a diagnostic callback if the fingerprint changes
globalSSHConfig.setHostKeyMismatchCallback(
    [](const String& expected, const String& actual, const String& keyType, void*) {
        LOGF_W("HOSTKEY", "Mismatch for %s (expected %s, got %s)", keyType.c_str(), expected.c_str(), actual.c_str());
    }
);
```

📖 **Security guide**: [Host Key Verification Documentation](docs/HOST_KEY_VERIFICATION.md)

### Compilation

```bash
pio run                    # Compilation
pio run --target upload    # Upload to ESP32
```

## 📁 Examples Structure

This project provides two example formats:

### Arduino / PlatformIO example
- **File**: [`examples/src/main.cpp`](examples/src/main.cpp)
- **Build**: `pio run -e arduino-3` from the repository root

### Native ESP-IDF example
- **File**: [`examples/esp-idf/main/main.cpp`](examples/esp-idf/main/main.cpp)
- **Build**: `idf.py build` from `examples/esp-idf`


## 📚 Technical Documentation

For more technical details:

- [`examples/`](examples/) - Usage examples
- [`docs/ESP_IDF.md`](docs/ESP_IDF.md) - Native ESP-IDF integration and PSRAM
- [`docs/SSH_KEYS_MEMORY.md`](docs/SSH_KEYS_MEMORY.md) - SSH Key authentication guide
- [`docs/HOST_KEY_VERIFICATION.md`](docs/HOST_KEY_VERIFICATION.md) - Security and host verification

## 🎯 Specifications

- **Platform**: ESP32 only
- **Framework**: Arduino and ESP-IDF
- **Cryptographic Backend**: mbedTLS
- **Protocol**: SSH2 with reverse tunneling
- **Memory**: Depends on the board, enabled PSRAM, and configured channels

## Connection tuning

```cpp
// Configure libssh2 keepalives alongside the existing periodic send
globalSSHConfig.setKeepAliveOptions(true, 30); // want-reply=1, 30s

// Adjust logging without toggling the debugEnabled flag
globalSSHConfig.setLogLevel(LOG_INFO);

// Advanced data-path tuning:
// - 3rd argument: channel inactivity timeout (5 minutes here)
// - 4th argument: capacity per direction. Two 64 KiB rings are allocated
//   per active channel (about 128 KiB of configured ring storage per channel).
globalSSHConfig.setBufferConfig(8192, 10, 300000, 64 * 1024);
```

Retrieve the effective reverse tunnel port when you bind to `remoteBindPort = 0`:

```cpp
SSHTunnel tunnel;
tunnel.init();
if (tunnel.connectSSH()) {
    LOGF_I("SSH", "Remote listener bound on %d", tunnel.getBoundPort());
}
```

Listeners can also be added or removed without reconnecting. Increase the
listener limit before connecting if more than one listener will be active:

```cpp
globalSSHConfig.setMaxReverseListeners(2);
tunnel.connectSSH();

TunnelConfig extra;
extra.remoteBindHost = "127.0.0.1";
extra.remoteBindPort = 22081;
extra.localHost = "192.168.1.150";
extra.localPort = 502;

tunnel.addReverseTunnel(extra);                  // active immediately
tunnel.removeReverseTunnel("127.0.0.1", 22081); // stops new connections
```

Removing a listener does not interrupt channels that are already open.

### SOCKS5 reverse proxy

SOCKS5 listeners select their destination per connection instead of using a
fixed local target:

```cpp
globalSSHConfig.setMaxReverseListeners(2);
globalSSHConfig.addTunnelMapping("127.0.0.1", 22080,
                                 "192.168.1.150", 80);
globalSSHConfig.addSocks5TunnelMapping("127.0.0.1", 22083);
```

The current SOCKS5 subset supports `NO AUTH`, `CONNECT`, IPv4 addresses and
domain names. DNS resolution runs on the ESP32. IPv6, `BIND`, `UDP ASSOCIATE`
and username/password authentication are rejected. Negotiation times out after
5 seconds.

Keep the remote listener bound to `127.0.0.1` and expose it only through an
authenticated/private path. Binding a `NO AUTH` SOCKS listener publicly (for
example on `0.0.0.0`) creates an open proxy.

When the SSH session is already connected, the equivalent dynamic call is:

```cpp
tunnel.addSocks5Tunnel("127.0.0.1", 22083);
```

### Channel lifecycle

Accepted SSH channels are attached before their destination is opened. Fixed
reverse tunnels then advance through `Resolving -> Connecting -> Open`; close
processing uses `Draining -> Closed`. SOCKS5 uses `Negotiating` to select its
destination after the SSH channel is accepted.
DNS runs outside the libssh2 session lock, and destination connections are
polled cooperatively without a blocking wait, so a slow TCP connect cannot
hold the SSH transport lock.

## Contributing

Contributions are welcome! See documentation guides for more details.

## License

See LICENSE file for details.
