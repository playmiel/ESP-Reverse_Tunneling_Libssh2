#ifndef CHANNEL_LIFECYCLE_H
#define CHANNEL_LIFECYCLE_H

#include <stdint.h>

namespace channel_lifecycle {

// Negotiating and Resolving are intentionally part of the core lifecycle even
// though fixed reverse tunnels enter at Resolving. SOCKS5 channels will enter
// at Negotiating and select their destination before resolution starts.
enum class State : uint8_t {
  Negotiating,
  Resolving,
  Connecting,
  Open,
  Draining,
  Closed
};

enum class ConnectProgress : uint8_t { None, Pending, Opened, Failed };

inline bool isPreOpen(State state) {
  return state == State::Negotiating || state == State::Resolving ||
         state == State::Connecting;
}

inline bool canUseLocalSocket(State state) {
  return state == State::Open || state == State::Draining;
}

// Propagate the remote half-close only after all bytes received from SSH have
// reached the local socket. Closing its write side while sshToLocalEmpty is
// false truncates the request still waiting in the transport FIFO.
inline bool shouldShutdownLocalWrite(bool remoteEof, bool localEof,
                                     bool localShutdownSent,
                                     bool hasLocalSocket,
                                     bool sshToLocalEmpty) {
  return remoteEof && !localEof && !localShutdownSent && hasLocalSocket &&
         sshToLocalEmpty;
}

inline bool connectTimedOut(uint32_t nowMs, uint32_t startedMs,
                            uint32_t timeoutMs) {
  return timeoutMs > 0 && (nowMs - startedMs) >= timeoutMs;
}

} // namespace channel_lifecycle

#endif // CHANNEL_LIFECYCLE_H
