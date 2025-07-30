# ESP-Reverse_Tunneling_Libssh2

Library for ESP32 Arduino enabling creation of reverse SSH tunnels using libssh2.

### 1. Adding the Library

**Option A: PlatformIO**
```bash
# Add to your platformio.ini
lib_deps = 
    https://github.com/playmiel/ESP-Reverse_Tunneling_Libssh2.git
    https://github.com/skuodi/libssh2_esp.git
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

### 3. Compilation

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

## 🎯 Specifications

- **Platform**: ESP32 only
- **Framework**: Arduino
- **Cryptographic Backend**: mbedTLS
- **Protocol**: SSH2 with reverse tunneling
- **Memory**: ~19% RAM, ~65% Flash

## 🤝 Contributing

Contributions are welcome! See documentation guides for more details.

## 📄 License

See LICENSE file for details.