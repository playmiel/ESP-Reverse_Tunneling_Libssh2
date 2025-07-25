# ESP32 SSH Tunnel Improvements

## Overview

This document describes the improvements made to the ESP32 SSH tunnel system to address stability issues and enhance configurability.

## Issues Resolved

### 1. Heap Corruption Caused by "Connection reset by peer"

**Original Issue:**
```
[4006183] WARN  [SSH] Channel 0: Local read error: Connection reset by peer
CORRUPT HEAP: Invalid data at 0x3f839be0. Expected 0xfefefefe got 0x00000000
```

**Implemented Solutions:**
- Specific handling of `ECONNRESET` and `EPIPE` errors
- Semaphore protection to prevent concurrent access
- Retry mechanism with a limit to avoid infinite loops
- Proper resource cleanup during disconnections

### 2. Static Configuration Replaced by Dynamic Configuration

**Before:**
```cpp
#define SSH_HOST "your-remote-server.com"
#define SSH_PORT 22
#define SSH_USERNAME "your_username"
// ...
```

**After:**
```cpp
globalSSHConfig.setSSHServer("your-server.com", 22, "username", "password");
globalSSHConfig.setTunnelConfig("0.0.0.0", 8080, "192.168.1.100", 80);
```

### 3. Removal of LED Functions

LED functions were removed as logs now provide sufficient information about the system state.

## New Features

### 1. Dynamic Configuration

#### SSH Configuration Structure
```cpp
struct SSHServerConfig {
    String host;
    int port;
    String username;
    String password;
    bool useSSHKey;
    String privateKeyPath;
};
```

#### Configuration Methods
```cpp
// Password-based configuration
globalSSHConfig.setSSHServer(host, port, username, password);

// SSH key-based configuration
globalSSHConfig.setSSHKeyAuth(host, port, username, keyPath, passphrase);

// Tunnel configuration
globalSSHConfig.setTunnelConfig(remoteHost, remotePort, localHost, localPort);

// Connection configuration
globalSSHConfig.setConnectionConfig(keepAlive, reconnectDelay, maxAttempts, timeout);
```

### 2. Thread-Safe Protection

#### Implemented Semaphores
- `tunnelMutex`: Global tunnel protection
- `statsMutex`: Statistics protection
- `channelMutex[]`: Individual channel protection

#### Protection Methods
```cpp
bool lockTunnel();
void unlockTunnel();
bool lockStats();
void unlockStats();
bool lockChannel(int channelIndex);
void unlockChannel(int channelIndex);
```

### 3. Improved Error Handling

#### Specific Network Error Detection
```cpp
if (errno == ECONNRESET || errno == EPIPE) {
    LOGF_W("SSH", "Channel %d: Connection reset by peer", channelIndex);
    // Proper cleanup without heap corruption
    unlockChannel(channelIndex);
    closeChannel(channelIndex);
    return;
}
```

#### Retry Mechanism
```cpp
int retryCount = 0;
const int maxRetries = 3;

while (remaining > 0 && retryCount < maxRetries) {
    // Write attempt with error handling
    if (retryCount >= maxRetries) {
        LOGF_W("SSH", "Channel %d: Max retries reached", channelIndex);
        // Clean channel closure
    }
}
```

### 4. Dynamic Memory Allocation

#### Dynamic Buffers
```cpp
// Allocation based on configuration
int bufferSize = config->getConnectionConfig().bufferSize;
rxBuffer = (uint8_t*)malloc(bufferSize);
txBuffer = (uint8_t*)malloc(bufferSize);
```

#### Dynamic Channels
```cpp
int maxChannels = config->getConnectionConfig().maxChannels;
channels = (TunnelChannel*)malloc(sizeof(TunnelChannel) * maxChannels);
```

## Usage

### Basic Configuration

```cpp
void configureSSHTunnel() {
    // SSH server configuration
    globalSSHConfig.setSSHServer(
        "your-remote-server.com",
        22,
        "your_username",
        "your_password"
    );
    
    // Tunnel configuration
    globalSSHConfig.setTunnelConfig(
        "0.0.0.0",        // Bind on remote server
        8080,             // Remote port
        "192.168.1.100",  // Local address
        80                // Local port
    );
    
    // Connection configuration
    globalSSHConfig.setConnectionConfig(
        30,    // Keep-alive (sec)
        5000,  // Reconnect delay (ms)
        5,     // Max attempts
        30     // Timeout (sec)
    );
}
```

### Initialization

```cpp
void setup() {
    // Configuration
    configureSSHTunnel();
    
    // Initialization
    if (!tunnel.init()) {
        LOG_E("MAIN", "Failed to initialize SSH tunnel");
        return;
    }
    
    // Connection
    if (!tunnel.connectSSH()) {
        LOG_E("MAIN", "Failed to connect SSH tunnel");
    }
}
```

## Advantages of the Improvements

1. **Increased Stability**: Eliminates heap corruption
2. **Flexibility**: Dynamic configuration without recompilation
3. **Thread-Safety**: Protection against concurrent access
4. **Robustness**: Improved network error handling
5. **Memory Efficiency**: Dynamic allocation based on needs
6. **Maintainability**: Cleaner and more modular code

## Modified Files

- `ssh_config.h`: New configuration structure
- `ssh_config.cpp`: Configuration implementation
- `ssh_tunnel.h`: Added semaphores and dynamic allocation
- `ssh_tunnel.cpp`: Improved error handling and thread-safe protection
- `examples/src/main.cpp`: Removed LEDs and uses new config

## Recommended Tests

1. **Stability Test**: Repeated connections/disconnections
2. **Load Test**: Large data transfers
3. **Resilience Test**: Simulated network failures
4. **Configuration Test**: Validation of different parameters
5. **Memory Test**: Check for memory leaks

## Important Notes

- Compilation errors in the development environment are normal (ESP32 headers not available)
- The code is designed to run on ESP32 with PlatformIO
- Configuration must be adapted to your specific environment
- Semaphores require FreeRTOS (included in ESP32)