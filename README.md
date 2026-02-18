# ESP-Reverse_Tunneling_Libssh2

Library for ESP32 Arduino enabling creation of reverse SSH tunnels using libssh2.

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

// Advanced data-path tuning
// 4th argument = ring buffer size per channel ( per direction, default 64KB total)
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
