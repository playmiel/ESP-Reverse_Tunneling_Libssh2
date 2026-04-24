#ifndef CIRCUIT_BREAKER_H
#define CIRCUIT_BREAKER_H

#include <cstddef>
#include <cstdint>

// Per-mapping circuit breaker. Tracks consecutive local-endpoint connect
// failures keyed by remoteBindPort, applies exponential back-off above a
// threshold. Pure C++; no Arduino, FreeRTOS, or logging dependency.
class CircuitBreaker {
public:
    static constexpr int MAX_MAPPING_HEALTH = 8;
    static constexpr uint16_t FAIL_THRESHOLD = 3;
    static constexpr unsigned long BACKOFF_BASE_MS = 1000;
    static constexpr unsigned long BACKOFF_CAP_MS = 60000;

    struct MappingHealth {
        int remoteBindPort = 0;        // 0 = entry unused
        uint16_t consecutiveFails = 0;
        unsigned long backoffUntilMs = 0;
    };

    bool isBackedOff(int port, unsigned long now) const;

    // Returns true iff this call newly engaged the back-off
    // (CLOSED -> OPEN transition). Caller is responsible for logging.
    bool recordFailure(int port, unsigned long now);

    void recordSuccess(int port);

    // Test-only introspection.
    const MappingHealth* peek(int port) const;

    // Total number of CLOSED -> OPEN transitions since construction.
    unsigned long totalTrips() const { return totalTrips_; }

private:
    MappingHealth health_[MAX_MAPPING_HEALTH] = {};
    unsigned long totalTrips_ = 0;

    MappingHealth* findOrAlloc(int port);
    const MappingHealth* find(int port) const;
};

inline bool CircuitBreaker::isBackedOff(int port, unsigned long now) const {
    const MappingHealth* h = find(port);
    if (!h || h->backoffUntilMs == 0) {
        return false;
    }
    // Unsigned subtraction handles millis() wrap correctly: if now has
    // passed backoffUntilMs, the difference stays small (positive).
    return (long)(now - h->backoffUntilMs) < 0;
}

inline bool CircuitBreaker::recordFailure(int port, unsigned long now) {
    if (port == 0) {
        return false;
    }
    MappingHealth* h = findOrAlloc(port);
    if (!h) {
        return false; // table full — silently skip
    }
    bool wasOpen = h->backoffUntilMs != 0 && (long)(now - h->backoffUntilMs) < 0;
    if (h->consecutiveFails < 100) {
        h->consecutiveFails++;
    }
    if (h->consecutiveFails >= FAIL_THRESHOLD) {
        int exp = h->consecutiveFails - FAIL_THRESHOLD;
        if (exp > 16) {
            exp = 16;
        }
        unsigned long delay = BACKOFF_BASE_MS << exp;
        if (delay > BACKOFF_CAP_MS) {
            delay = BACKOFF_CAP_MS;
        }
        h->backoffUntilMs = now + delay;
        if (!wasOpen) {
            totalTrips_++;
            return true;
        }
    }
    return false;
}

inline void CircuitBreaker::recordSuccess(int port) {
    if (port == 0) {
        return;
    }
    MappingHealth* h = findOrAlloc(port);
    if (!h) {
        return;
    }
    h->consecutiveFails = 0;
    h->backoffUntilMs = 0;
}

inline const CircuitBreaker::MappingHealth* CircuitBreaker::peek(int port) const {
    return find(port);
}

inline CircuitBreaker::MappingHealth* CircuitBreaker::findOrAlloc(int port) {
    for (int i = 0; i < MAX_MAPPING_HEALTH; ++i) {
        if (health_[i].remoteBindPort == port) {
            return &health_[i];
        }
    }
    for (int i = 0; i < MAX_MAPPING_HEALTH; ++i) {
        if (health_[i].remoteBindPort == 0) {
            health_[i].remoteBindPort = port;
            health_[i].consecutiveFails = 0;
            health_[i].backoffUntilMs = 0;
            return &health_[i];
        }
    }
    return nullptr;
}

inline const CircuitBreaker::MappingHealth* CircuitBreaker::find(int port) const {
    if (port == 0) {
        return nullptr;  // 0 is the "unused slot" sentinel, never a real port
    }
    for (int i = 0; i < MAX_MAPPING_HEALTH; ++i) {
        if (health_[i].remoteBindPort == port) {
            return &health_[i];
        }
    }
    return nullptr;
}

#endif // CIRCUIT_BREAKER_H
