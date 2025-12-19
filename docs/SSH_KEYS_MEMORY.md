# Using SSH Keys with libssh2_userauth_publickey_frommemory

This guide explains how to use SSH public key authentication with keys stored directly in memory instead of filesystem files, which is often more reliable with LittleFS on ESP32.

## Advantages of in‑memory key authentication

- **LittleFS compatibility**: Avoids file read issues
- **Performance**: No disk access during authentication
- **Security**: Keys can be loaded once at boot
- **Reliability**: Prevents path resolution errors

## Usage Methods

### 1. Configuration with keys directly in memory

```cpp
String privateKey = R"(-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAFwAAAAdzc2gtcn
... (your full private key here)
-----END OPENSSH PRIVATE KEY-----)";

String publicKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB... user@host";

globalSSHConfig.setSSHKeyAuthFromMemory(
  "your-remote-server.com",
  22,
  "your_username",
  privateKey,
  publicKey,
  ""  // Passphrase optionnelle
);
```

### 2. Automatic loading from LittleFS

```cpp
// This method automatically loads keys into memory
globalSSHConfig.setSSHKeyAuth(
  "your-remote-server.com",
  22,
  "your_username",
  "/ssh_key",       // Path to private key in LittleFS
  ""                // Passphrase optionnelle
);
```

### 3. Manual loading from LittleFS

```cpp
// Initialiser LittleFS
if (!LittleFS.begin(true)) {
  LOG_E("CONFIG", "Failed to initialize LittleFS");
  return;
}

// Load keys into memory
if (globalSSHConfig.loadSSHKeysFromLittleFS("/ssh_key")) {
  LOG_I("CONFIG", "SSH keys loaded successfully");
} else {
  LOG_E("CONFIG", "Failed to load SSH keys");
}
```

## Preparing SSH Keys

### Key generation

```bash
# Generate an SSH key pair
ssh-keygen -t rsa -b 2048 -f ssh_key -N ""

# This creates:
# - ssh_key (private key)
# - ssh_key.pub (public key)
```

### Upload to LittleFS

1. **Via ESP32 Sketch Data Upload tool**:
  - Put your keys in the project `data/` directory
  - Use the "ESP32 Sketch Data Upload" tool in Arduino IDE

2. **Programmatically**:
   ```cpp
   File privateKeyFile = LittleFS.open("/ssh_key", "w");
   privateKeyFile.print(privateKeyString);
   privateKeyFile.close();
   
   File publicKeyFile = LittleFS.open("/ssh_key.pub", "w");
   publicKeyFile.print(publicKeyString);
   publicKeyFile.close();
   ```

## Full example

```cpp
#include <WiFi.h>
#include <LittleFS.h>
#include "ESP-Reverse_Tunneling_Libssh2.h"

void setup() {
  Serial.begin(115200);
  
  // Initialize LittleFS
  if (!LittleFS.begin(true)) {
    LOG_E("MAIN", "Failed to initialize LittleFS");
    return;
  }
  
  // WiFi configuration
  WiFi.begin("YOUR_SSID", "YOUR_PASSWORD");
  while (WiFi.status() != WL_CONNECTED) {
    delay(1000);
  }
  
  // SSH configuration with keys from LittleFS
  globalSSHConfig.setSSHKeyAuth(
    "your-server.com",
    22,
    "your_username",
    "/ssh_key",
    ""  // Pas de passphrase
  );
  
  // Tunnel configuration
  globalSSHConfig.setTunnelConfig("127.0.0.1", 8080, "192.168.1.100", 80);
  
  // Initialize and connect tunnel
  SSHTunnel tunnel;
  if (tunnel.init() && tunnel.connectSSH()) {
    LOG_I("MAIN", "SSH tunnel established successfully");
  }
}
```

## Troubleshooting

### Issue: "SSH keys not available in memory"
- Check LittleFS initialized
- Check key files exist in LittleFS
- Check read permissions

### Issue: "Authentication by public key from memory failed"
- Validate key formats (OpenSSH or PEM)
- Ensure public key matches private key
- Ensure passphrase (if any) is correct

### Issue: Unsupported key format
- libssh2 supports OpenSSH and PEM formats
- Convert if needed: `ssh-keygen -p -m PEM -f ssh_key`

## Security notes

1. **Never** commit real private keys to source
2. Use device-dedicated keys
3. Store keys securely (encryption, restricted access)
4. Consider temporary/rotated credentials when possible

## Compatibility

- ✅ OpenSSH private key format
- ✅ PEM private key format  
- ✅ RSA keys
- ✅ ED25519 keys (if supported by libssh2)
- ✅ Keys with or without passphrase
