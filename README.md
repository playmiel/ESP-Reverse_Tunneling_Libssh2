# ESP-Reverse_Tunneling_Libssh2

Library for ESP32 Arduino enabling creation of reverse SSH tunnels using libssh2.

### 1. Adding the Library

**Option A: PlatformIO**
```bash
# Add to your platformio.ini
lib_deps = 
    https://github.com/playmiel/ESP-Reverse_Tunneling_Libssh2.git
    https://github.com/playmiel/libssh2_esp32
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
    "a1b2c3d4e5f67890123456789012345678901234567890abcdef1234567890ab",  // SHA256 fingerprint
    "ssh-ed25519",                                                      // Key type
    true                                                               // Enable verification
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
