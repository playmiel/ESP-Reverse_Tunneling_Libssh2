# ESP-Reverse_Tunneling_Libssh2 Documentation

This library supports Arduino/PlatformIO and native ESP-IDF. Both use the
`playmiel/libssh2_esp32` fork: PlatformIO fetches it through `lib_deps`, while
ESP-IDF builds the pinned submodule.

| Framework | Start here |
|-----------|------------|
| Arduino / PlatformIO | [Arduino example](../examples/README.md) |
| Native ESP-IDF | [Integration and PSRAM guide](ESP_IDF.md) · [ESP-IDF example](../examples/esp-idf/README.md) |

## 📖 Main Guides

### [SSH_KEYS_MEMORY.md](SSH_KEYS_MEMORY.md)
Complete guide for SSH key authentication with in-memory storage:

- SSH key configuration
- Secure LittleFS storage  
- Supported key formats
- Practical examples

### [HOST_KEY_VERIFICATION.md](HOST_KEY_VERIFICATION.md)
Security guide for host key verification:

- Protection against Man-in-the-Middle attacks
- Server fingerprint configuration
- Verification API
- Security best practices
- Migration and troubleshooting

## 🔧 Configuration

### Password authentication (simple)

```cpp
globalSSHConfig.setSSHServer("server.com", 22, "username", "password");
```

### SSH key authentication (recommended)

```cpp
globalSSHConfig.setSSHKeyAuthFromMemory(
    "server.com", 22, "username", 
    privateKeyData, publicKeyData, ""
);
```

### Secure full configuration

```cpp
// SSH authentication
globalSSHConfig.setSSHKeyAuthFromMemory(
    "server.com", 22, "username",
    privateKeyData, publicKeyData, ""
);

// Server identity verification
globalSSHConfig.setHostKeyVerification(
    "SHA256:server_fingerprint",
    "ssh-rsa",
    true
);

// Tunnel configuration
globalSSHConfig.setTunnelConfig(
    "127.0.0.1", 8080,    // Remote server bind
    "192.168.1.100", 80 // Local target (ESP32)
);
```

## 📊 Supported Key Formats

| Format | Compatibility | Recommendation |
|--------|---------------|----------------|
| Modern OpenSSH (`-----BEGIN OPENSSH PRIVATE KEY-----`) | ⚠️ Variable | Convert to PKCS#8 |
| PKCS#8 (`-----BEGIN PRIVATE KEY-----`) | ✅ Excellent | **Recommended** |
| PEM RSA (`-----BEGIN RSA PRIVATE KEY-----`) | ✅ Excellent | OK for RSA |
| PEM EC (`-----BEGIN EC PRIVATE KEY-----`) | ✅ Good | OK for ECDSA |

## 🔐 Supported Key Algorithms

| Algorithm | Support | Recommended Size |
|-----------|---------|------------------|
| Ed25519 | ❌ Not enabled in the fork's mbedTLS backend | — |
| RSA | ✅ Enabled | Server-dependent |
| ECDSA | ✅ If `MBEDTLS_ECDSA_C` is enabled | Curve-dependent |
| DSA | ❌ Disabled | — |

## 🛡️ Security Levels

### Development (level 1)

```cpp
globalSSHConfig.setSSHServer("server.com", 22, "user", "password");
// No host verification
```

### Basic production (level 2)  

```cpp
globalSSHConfig.setSSHKeyAuthFromMemory(/* SSH keys */);
// Key-based auth but no host verification
```

### Secure production (level 3) - **Recommended**

```cpp
globalSSHConfig.setSSHKeyAuthFromMemory(/* SSH keys */);
globalSSHConfig.setHostKeyVerification(/* server fingerprint */);
// Key-based auth + host verification
```

## 🚀 Quick Start

### Arduino / PlatformIO installation

```ini
# platformio.ini
lib_deps = 
    https://github.com/playmiel/ESP-Reverse_Tunneling_Libssh2.git
    https://github.com/playmiel/libssh2_esp32.git#codex/esp-idf-component
```

For native ESP-IDF, follow the [component setup](ESP_IDF.md). It includes
both the tunnel library and its libssh2 submodule in `EXTRA_COMPONENT_DIRS`.

### 2. Minimal code

```cpp
#include "ESP-Reverse_Tunneling_Libssh2.h"

SSHTunnel tunnel;

void setup() {
    // WiFi configuration
    WiFi.begin("SSID", "PASSWORD");
    
    // SSH configuration
    globalSSHConfig.setSSHKeyAuthFromMemory(/* parameters */);
    
    // Initialization
    tunnel.init();
    tunnel.connectSSH();
}

void loop() {
    tunnel.loop();
}
```

### 3. Status check

```cpp
if (tunnel.isConnected()) {
    Serial.println("Tunnel active");
    Serial.printf("Active channels: %d\n", tunnel.getActiveChannels());
    Serial.printf("Bytes received: %lu bytes\n", tunnel.getBytesReceived());
    Serial.printf("Bytes sent: %lu bytes\n", tunnel.getBytesSent());
}
```

## 🔍 Troubleshooting

### Common issues

#### "Authentication failed"
- ✅ Check key format (prefer PKCS#8)
- ✅ Ensure public key is in `authorized_keys`
- ✅ Test manual SSH connection from a PC

#### "Host key verification failed"  
- ✅ Get the real server fingerprint
- ✅ Check configured fingerprint
- ✅ Ensure it's not an attack

#### "Connection timeout"
- ✅ Verify network connectivity
- ✅ Check SSH port open
- ✅ Test with a standard SSH client

### Useful logs
```cpp
// Enable detailed debug
globalSSHConfig.setDebugConfig(true, 115200);

// Diagnose SSH keys
globalSSHConfig.diagnoseSSHKeys();
```

## 📈 Performance Optimizations

### Memory
- Enable PSRAM in ESP-IDF `menuconfig` if the board provides it; see the
  [PSRAM guide](ESP_IDF.md#psram-and-channel-buffers).
- Adjust `bufferSize` and the per-direction ring buffer size according to usage
- Limit `maxChannels` to what you need

### Network
- Tune `keepAliveIntervalSec`
- Use built-in network optimizations and backpressure

### Recommended configuration
```cpp
globalSSHConfig.setConnectionConfig(
    30,    // Keep-alive: 30s
    5000,  // Reconnect delay: 5s
    10,    // Max reconnect attempts
    30     // Connection timeout: 30s
);

globalSSHConfig.setBufferConfig(
    8192,       // Buffer size: 8KB
    5,          // Max channels: 5
    300000,     // Channel inactivity timeout: 5 minutes
    64 * 1024   // 64 KiB per direction; two rings per active channel
);
```

The fourth argument is the capacity of each directional ring buffer, not a
total shared by both directions. The configuration above therefore reserves
about 128 KiB of ring storage per active channel, plus implementation overhead.
On boards without enabled PSRAM, start with smaller buffers such as the
[native ESP-IDF example](../examples/esp-idf/main/main.cpp).

### Multi-tunnel / multiple listeners

Use `addTunnelMapping()` and `setMaxReverseListeners()` to expose several
local services through a single SSH connection:

```cpp
globalSSHConfig.clearTunnelMappings();
globalSSHConfig.setMaxReverseListeners(3);

globalSSHConfig.addTunnelMapping("127.0.0.1", 22080, "192.168.1.100", 80);
globalSSHConfig.addTunnelMapping("127.0.0.1", 22081, "192.168.1.150", 502);
globalSSHConfig.addTunnelMapping("127.0.0.1", 22082, "192.168.1.200", 22);
```

Mappings configured with `addTunnelMapping()` are created by `connectSSH()`.
To change a running session, use `SSHTunnel::addReverseTunnel()` and
`SSHTunnel::removeReverseTunnel()` instead. These methods update both the live
listener and the stored configuration, so the change survives reconnection.
Removing a listener only prevents new connections; existing channels continue
until they close normally.

Set `remoteBindPort` to `0` to let sshd choose an ephemeral port. For the first
listener, retrieve the selected port with `SSHTunnel::getBoundPort()`.

## 📞 Support

For questions or issues:

1. Consult this documentation
2. Check the [examples/](../examples/)
3. Enable debug logs
4. Open a GitHub issue

---

**Documentation version:** 1.0  
**Last update:** 2025-02-04
