#ifndef SSH_CONFIG_VALIDATORS_H
#define SSH_CONFIG_VALIDATORS_H

#include <cstddef>
#include <string_view>

// Pure boolean validators for SSH/tunnel/connection config values.
// Behavior must remain in lock-step with what SSHConfiguration::validateXxx()
// historically enforced — these are extracted rules, not stricter ones.
// See `src/ssh_config.cpp` validate* methods for the call sites.
namespace ssh_validators {

// Port must be in the TCP/UDP range, never 0 (sentinel for "unused").
inline bool isValidPort(int port) {
    return port >= 1 && port <= 65535;
}

// A hostname or IP literal: non-empty string. We do NOT validate DNS syntax
// or IDN — historically only emptiness was rejected.
inline bool isValidHostname(std::string_view host) {
    return !host.empty();
}

// Mirrors `keepAliveIntervalSec <= 0` rejection in validateConnectionConfig.
inline bool isValidKeepAlive(int seconds) {
    return seconds > 0;
}

// Mirrors `bufferSize <= 0` rejection. No power-of-two requirement.
inline bool isValidBufferSize(int bytes) {
    return bytes > 0;
}

// Mirrors `reconnectDelayMs <= 0` rejection.
inline bool isValidReconnectDelay(int ms) {
    return ms > 0;
}

// Mirrors `maxChannels <= 0` rejection.
inline bool isValidMaxChannels(int n) {
    return n > 0;
}

// Mirrors `connectionTimeoutSec <= 0` rejection.
inline bool isValidConnectionTimeout(int seconds) {
    return seconds > 0;
}

// Mirrors `maxReconnectAttempts <= 0` rejection.
inline bool isValidMaxReconnectAttempts(int n) {
    return n > 0;
}

} // namespace ssh_validators

#endif // SSH_CONFIG_VALIDATORS_H
