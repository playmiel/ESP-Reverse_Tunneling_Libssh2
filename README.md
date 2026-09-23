# ESP-Reverse_Tunneling_Libssh2

Library for ESP32 Arduino and native ESP-IDF enabling reverse SSH tunnels using libssh2. This branch includes the 3.0 SOCKS5 reverse proxy changes.

### Native ESP-IDF

Clone this repository with `--recurse-submodules`. The submodule at
`components/libssh2_esp` tracks [playmiel/libssh2_esp32](https://github.com/playmiel/libssh2_esp32),
which contains the ESP-IDF backend. Arduino/PlatformIO continues to use
[playmiel/libssh2_esp](https://github.com/playmiel/libssh2_esp) through
`platformio.ini`.

In an ESP-IDF project's top-level `CMakeLists.txt`, before including
`project.cmake`, add both components:

```cmake
set(EXTRA_COMPONENT_DIRS
    "${CMAKE_CURRENT_LIST_DIR}/components/ESP-Reverse_Tunneling_Libssh2"
    "${CMAKE_CURRENT_LIST_DIR}/components/ESP-Reverse_Tunneling_Libssh2/components/libssh2_esp")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(my_project)
```

Initialize the submodule after cloning or updating:

```bash
git submodule update --init --recursive
```

The [ESP-IDF example](examples/esp-idf) uses Wi-Fi station mode. Set Wi-Fi,
SSH server credentials and the server's SHA256 host-key fingerprint with
`idf.py menuconfig`, then run `idf.py build flash monitor` from that directory.
For key authentication, `setSSHKeyAuthFromMemory` needs no filesystem; the
native `setSSHKeyAuth` path reads the private key and `.pub` file from an
already mounted ESP-IDF VFS.

### 1. Adding the Library

**Option A: PlatformIO**
```bash
# Add to your platformio.ini
lib_deps = 
    https://github.com/playmiel/ESP-Reverse_Tunneling_Libssh2.git
    https://github.com/playmiel/libssh2_esp  # libssh2 backend for ESP32
```

**Option B: Arduino IDE**
1. Download the project
2. Copy files to your libraries folder

### 2. Usage in Your Code

```cpp
#include "ESP-Reverse_Tunneling_Libssh2.h"

void setup() {
    Serial.begin(115200);
    
    // WiFi configuration
    WiFi.begin("YOUR_SSID", "YOUR_PASSWORD");
    
    // SSH tunnel configuration with password
    globalSSHConfig.setSSHServer("server.com", 22, "user", "password");
    
    // OR with SSH key from memory (recommended for LittleFS)
    globalSSHConfig.setSSHKeyAuth("server.com", 22, "user", "/ssh_key");
    
    // Create and start tunnel
    SSHTunnel tunnel;
    tunnel.init();
    tunnel.connectSSH();
}
```

### 3. SSH Key Authentication

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

### 4. Host Key Verification (Security)

For production environments, enable host key verification to prevent Man-in-the-Middle attacks:

```cpp
// Configure SSH with host key verification
globalSSHConfig.setSSHKeyAuthFromMemory("server.com", 22, "user", privateKey, publicKey);

// Enable host key verification (recommended for production)
globalSSHConfig.setHostKeyVerification(
    "SHA256:abcd1234efgh5678ijkl9012mnop3456qrst7890uvwx1234yz56",  // Accept OpenSSH format or 64-char hex
    "ssh-ed25519",
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

### 5. Compilation

```bash
pio run                    # Compilation
pio run --target upload    # Upload to ESP32
```

## 📁 Examples Structure

This project provides two example formats:

### PlatformIO Example (Recommended)
- **File**: [`examples/src/main.cpp`](examples/src/main.cpp)
- **Usage**: Compiled when running `pio run` in the examples/ directory
- **Features**: Full PlatformIO integration with advanced logging


## 📚 Technical Documentation

For more technical details:

- [`examples/`](examples/) - Usage examples
- [`docs/SSH_KEYS_MEMORY.md`](docs/SSH_KEYS_MEMORY.md) - SSH Key authentication guide
- [`docs/HOST_KEY_VERIFICATION.md`](docs/HOST_KEY_VERIFICATION.md) - Security and host verification

## 🎯 Specifications

- **Platform**: ESP32 only
- **Framework**: Arduino
- **Cryptographic Backend**: mbedTLS
- **Protocol**: SSH2 with reverse tunneling
- **Memory**: 
- ~19% RAM (used 46252 bytes from 327680 bytes)
- ~65% Flash (used 897321 bytes from 1310720 bytes)

## 🤝 Contributing

Contributions are welcome! See documentation guides for more details.

## 📄 License

See LICENSE file for details.
### 6. Connection Tuning

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
