# Host Key Verification (Known Hosts)

## Introduction

Host key verification is a critical security mechanism that protects against **Man-in-the-Middle (MITM)** attacks. It validates the SSH server’s identity by comparing its cryptographic fingerprint to an expected value.

## Why It Matters

### Without host key verification

```text
Internet → [Attacker] → [Your ESP32] → [Real server]
           ↑
    Impersonates your server
    Can intercept/modify all traffic
```

### With verification

- ✅ **Detects MITM attacks**
- ✅ **Verifies server identity**
- ✅ **Protects sensitive data**
- ✅ **Follows security best practices**

## Configuration

### 1. Obtain the server fingerprint

#### On your Linux server

```bash
# Get the SHA256 fingerprint of the Ed25519 key
ssh-keygen -l -f /etc/ssh/ssh_host_ed25519_key.pub -E sha256

# Or from a client
ssh-keyscan -t ed25519 your-server.com | ssh-keygen -lf - -E sha256
```

#### Example output

```text
256 SHA256:abcd1234efgh5678ijkl9012mnop3456qrst7890uvwx1234yz56 root@server (ED25519)
```

### 2. ESP32 Code Configuration

#### Method 1: Full configuration

```cpp
#include "ESP-Reverse_Tunneling_Libssh2.h"

void setup() {
    // Standard SSH configuration
    globalSSHConfig.setSSHKeyAuthFromMemory(
        "your-server.com",
        22,
        "username",
        privateKey,
        publicKey,
        ""  // No passphrase
    );

    // Enable verification with expected fingerprint
    globalSSHConfig.setHostKeyVerification(
    "abcd1234efgh5678ijkl9012mnop3456qrst7890uvwx1234yz56", // SHA256 fingerprint
    "ssh-ed25519",  // Expected key type
    true           // Enable verification
    );
}
```

#### Method 2: Step-by-step configuration

```cpp
// First configure SSH normally
globalSSHConfig.setSSHKeyAuthFromMemory(/* SSH parameters */);

// Then configure verification
globalSSHConfig.setHostKeyVerification(true);
globalSSHConfig.setExpectedHostKey(
    "abcd1234efgh5678ijkl9012mnop3456qrst7890uvwx1234yz56",
    "ssh-ed25519"
);
```

#### Method 3: Discovery mode (first connection)

```cpp
// Enable verification but leave the expected fingerprint empty (discovery/TOFU)
// The connection will be accepted once and the server fingerprint will be printed.
globalSSHConfig.setHostKeyVerification(true);

// Logs will show:
// [INFO] Store this fingerprint (hex): ...
// [INFO] Store this fingerprint (OpenSSH): SHA256:...
// Copy that fingerprint into setExpectedHostKey() for subsequent connections.
```

## Configuration API

### Available methods

```cpp
class SSHConfiguration {
public:
    // Enable/disable verification
    void setHostKeyVerification(bool enable);
    
    // Set expected fingerprint
    void setExpectedHostKey(const String& fingerprint, const String& keyType = "");
    
    // Full configuration helper
    void setHostKeyVerification(const String& fingerprint, const String& keyType = "", bool enable = true);
};
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `fingerprint` | String | SHA256 fingerprint (`SHA256:base64` or 64 hex characters) |
| `keyType` | String | Key type: "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-*" |
| `enable` | bool | Enable/disable verification |

## Supported key types

| Type | libssh2 Constant | Config string |
|------|------------------|---------------|
| RSA | `LIBSSH2_HOSTKEY_TYPE_RSA` | `"ssh-rsa"` |
| DSA | `LIBSSH2_HOSTKEY_TYPE_DSS` | `"ssh-dss"` |
| ECDSA P-256 | `LIBSSH2_HOSTKEY_TYPE_ECDSA_256` | `"ecdsa-sha2-nistp256"` |
| ECDSA P-384 | `LIBSSH2_HOSTKEY_TYPE_ECDSA_384` | `"ecdsa-sha2-nistp384"` |
| ECDSA P-521 | `LIBSSH2_HOSTKEY_TYPE_ECDSA_521` | `"ecdsa-sha2-nistp521"` |
| Ed25519 | `LIBSSH2_HOSTKEY_TYPE_ED25519` | `"ssh-ed25519"` |

## Logs and Debug

### Normal logs (verification success)

```text
[INFO] Server host key: ssh-ed25519
[INFO] Server fingerprint (SHA256 hex): abcd1234efgh5678ijkl9012mnop3456qrst7890uvwx1234yz56
[INFO] Server fingerprint (OpenSSH): SHA256:abcd1234efgh5678ijkl9012mnop3456qrst7890uvwx1234yz56
[INFO] Host key verification successful
```

### Error logs (fingerprint mismatch)

```text
[ERROR] HOST KEY VERIFICATION FAILED!
[ERROR] This could indicate a Man-in-the-Middle attack!
[ERROR] Expected (OpenSSH): SHA256:abcd1234efgh5678ijkl9012mnop3456qrst7890uvwx1234yz56
[ERROR] Got      (OpenSSH): SHA256:xyz9876fedcba5432109876543210abcdef1234567890abcdef12
[ERROR] Key type: ssh-ed25519
```

### Discovery mode

```text
[WARN] Host key verification disabled - connection accepted without verification
[INFO] Server host key: ssh-ed25519
[INFO] Server fingerprint (SHA256 hex): abcd1234efgh5678ijkl9012mnop3456qrst7890uvwx1234yz56
[INFO] Server fingerprint (OpenSSH): SHA256:abcd1234efgh5678ijkl9012mnop3456qrst7890uvwx1234yz56
[WARN] No expected fingerprint configured - accepting and storing current fingerprint
[INFO] Store this fingerprint in your configuration: SHA256:abcd1234efgh5678ijkl9012mnop3456qrst7890uvwx1234yz56
```

## Usage Examples

### Example 1: Production configuration

```cpp
void configureSecureSSH() {
    // SSH keys
    String privateKey = R"(-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIBxK5c3j7kJ9QZ8fG3mVlM2fk8WdlMJq5018faI4C4eA
-----END PRIVATE KEY-----)";
    
    String publicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAebBChSTfMPbiXfphT6KUzZ+TxZ2UwmrnTXx9ojgLh4 esp32-device";
    
    // Full secure configuration
    globalSSHConfig.setSSHKeyAuthFromMemory(
        "production-server.com",
        22,
        "tunnel-user",
        privateKey,
        publicKey,
        ""
    );
    
    // Mandatory verification in production
    globalSSHConfig.setHostKeyVerification(
        "SHA256:a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef",
        "ssh-ed25519",
        true
    );
}
```

### Example 2: Development configuration

```cpp
void configureDevSSH() {
    // Standard SSH configuration
    globalSSHConfig.setSSHKeyAuthFromMemory(/* parameters */);
    
    // Discovery mode to get fingerprint
    globalSSHConfig.setHostKeyVerification(false);
    
    // TODO: Replace with real fingerprint once obtained
    // globalSSHConfig.setHostKeyVerification("FINGERPRINT_HERE", "ssh-ed25519", true);
}

### Host key mismatch callback (optional)

Register `setHostKeyMismatchCallback()` to be notified when the fingerprint on the wire does not
match the expected value. The callback runs on the SSH worker context and is intended for logging or
telemetry; it does not override the verification result.

```cpp
globalSSHConfig.setHostKeyMismatchCallback(
    [](const String& expected, const String& actual, const String& keyType, void* ctx) {
        (void)ctx; // Optional user context pointer
        LOGF_W("HOSTKEY", "Expected %s for %s, got %s", expected.c_str(), keyType.c_str(), actual.c_str());
    },
    myContextPointer
);
```

The `expected` string mirrors what you configured (hex or `SHA256:` syntax) while `actual` follows
the OpenSSH format (`SHA256:...`).

### Example 3: Flexible configuration

```cpp
void configureFlexibleSSH() {
    // SSH configuration
    globalSSHConfig.setSSHKeyAuthFromMemory(/* parameters */);
    
    #ifdef PRODUCTION
    // Strict verification in production
        globalSSHConfig.setHostKeyVerification(
            "SHA256:a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef",
            "ssh-ed25519",
            true
        );
    #else
    // Permissive mode in development
        globalSSHConfig.setHostKeyVerification(false);
        LOG_W("SSH", "Host key verification disabled in development mode");
    #endif
}
```

## Security and Best Practices

### ✅ Recommendations

1. **Always enable in production**
   ```cpp
   globalSSHConfig.setHostKeyVerification(true);
   ```

2. **Use full fingerprints**

    - Prefer SHA256 (`SHA256:base64` or 64 hex chars)
    - Avoid SHA1 (deprecated)

3. **Specify key type**
   ```cpp
    globalSSHConfig.setExpectedHostKey("fingerprint", "ssh-ed25519");
   ```

4. **Monitor logs**

    - Automatic alerts on verification failure
    - Watch for fingerprint changes

### ❌ Avoid

1. **Never disable in production**
   ```cpp
    // DANGEROUS in production!
   globalSSHConfig.setHostKeyVerification(false);
   ```

2. **Do not ignore verification failures**
- A failure can indicate an attack
- Investigate any fingerprint change

3. **Do not use partial fingerprints**
- Always use the full fingerprint
- Check case and characters

## Troubleshooting

### Issue: "Host key verification failed"

**Possible causes:**
- Server reconfigured with new keys
- Man-in-the-Middle attack
- Configuration error (wrong fingerprint)

**Solutions:**
1. Check the fingerprint on the server
2. Compare with configured fingerprint
3. Update if server legitimately changed

### Issue: "Failed to get host key from server"

**Possible causes:**
- Network connectivity issue
- SSH server unavailable
- Incompatible libssh2 version

**Solutions:**
1. Verify network connectivity
2. Test manual SSH connection
3. Check server logs

### Issue: Unrecognized key type

**Solutions:**
1. Use a supported key type
2. Update libssh2 if needed
3. Configure server with supported algorithm

## Configuration Structure

### In ssh_config.h
```cpp
struct SSHServerConfig {
    String host;
    int port;
    String username;
    String password;
    bool useSSHKey;
    String privateKeyData;
    String publicKeyData;
    
    // Known hosts configuration
    bool verifyHostKey;                    // Enable/disable
    String expectedHostKeyFingerprint;     // SHA256 fingerprint
    String hostKeyType;                    // Expected key type
};
```

### Default values
```cpp
SSHServerConfig() : 
    // ... other parameters ...
    verifyHostKey(false),                  // Disabled by default
    expectedHostKeyFingerprint(""),       // No fingerprint
    hostKeyType("") {}                    // All types accepted
```

## Migration from a version without verification

### Step 1: Update code
```cpp
// Initial configuration without verification

globalSSHConfig.setSSHKeyAuthFromMemory(host, port, user, privKey, pubKey, "");
globalSSHConfig.setHostKeyVerification(false); // Temporary discovery mode
```

### Step 2: Get the fingerprint
1. Build and flash in discovery mode
2. Note the fingerprint from logs
3. Store fingerprint securely

### Step 3: Enable verification
```cpp
// Final secure configuration
globalSSHConfig.setSSHKeyAuthFromMemory(host, port, user, privKey, pubKey, "");
globalSSHConfig.setHostKeyVerification(
    "fingerprint_obtained_step_2",
    "ssh-ed25519", 
    true
);
```

## Complete Example

```cpp
#include "ESP-Reverse_Tunneling_Libssh2.h"

// Full secure configuration
void setupSecureSSHTunnel() {
    // SSH keys in PKCS#8 format (recommended)
    String privateKey = R"(-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIBxK5c3j7kJ9QZ8fG3mVlM2fk8WdlMJq5018faI4C4eA
-----END PRIVATE KEY-----)";
    
    String publicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAebBChSTfMPbiXfphT6KUzZ+TxZ2UwmrnTXx9ojgLh4 esp32-tunnel";
    
    // SSH configuration with key authentication
    globalSSHConfig.setSSHKeyAuthFromMemory(
        "tunnel.example.com",   // SSH server
        22,                       // SSH port
        "tunnel-user",           // Username
        privateKey,               // Private key
        publicKey,                // Public key
        ""                       // No passphrase
    );
    
    // Reverse tunnel configuration
    globalSSHConfig.setTunnelConfig(
        "127.0.0.1",              // Bind on localhost (server loopback interface)
        8080,                    // Remote port (server)
        "192.168.1.100",        // Local IP (ESP32)
        80                       // Local port (ESP32 web server)
    );
    
    // Secure configuration with host key verification
    globalSSHConfig.setHostKeyVerification(
        "a1b2c3d4e5f67890123456789012345678901234567890abcdef1234567890ab",  // SHA256 fingerprint
        "ssh-ed25519",                                                      // Key type
        true                                                                 // Enable
    );
    
    // Connection parameters configuration
    globalSSHConfig.setConnectionConfig(
    30,    // Keep-alive: 30 seconds
    5000,  // Reconnect delay: 5 seconds
    10,    // Max reconnect attempts
    30     // Connection timeout: 30 seconds
    );
}

void setup() {
    Serial.begin(115200);
    
    // WiFi configuration
    WiFi.begin("SSID", "PASSWORD");
    while (WiFi.status() != WL_CONNECTED) {
        delay(1000);
        Serial.println("Connecting to WiFi...");
    }
    
    // Secure tunnel configuration
    setupSecureSSHTunnel();
    
    // Tunnel initialization
    if (!tunnel.init()) {
        Serial.println("Failed to initialize SSH tunnel");
        return;
    }
    
    Serial.println("SSH tunnel initialized with host key verification enabled");
}

void loop() {
    tunnel.loop();
    delay(10);
}
```

This documentation covers all aspects of host key verification in your ESP-Reverse_Tunneling_Libssh2 library.
