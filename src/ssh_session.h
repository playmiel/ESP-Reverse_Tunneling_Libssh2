#ifndef SSH_SESSION_H
#define SSH_SESSION_H

#include "logger.h"
#ifdef TUNNEL_DIAG_LOG_ONLY
#include "forward_accept_diag.h"
#endif
#include "ssh_config.h"
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <libssh2_esp.h>
#include <vector>

// Forward declaration
struct TunnelConfig;

struct ListenerEntry {
  LIBSSH2_LISTENER *listener = nullptr;
  TunnelConfig mapping;
  int boundPort = 0;
};

// SSHSession: manages the SSH connection lifecycle.
// Handles TCP connect, handshake, authentication, host key verification,
// keepalive, and reverse-tunnel listener management.
// All libssh2 calls are serialized through lock()/unlock().
class SSHSession {
public:
  SSHSession();
  ~SSHSession();

  // Initialize the session mutex. Call once before use.
  bool init();

  // Full connection sequence: TCP connect + handshake + auth + listeners.
  // Returns true if connected and at least one listener is active.
  bool connect(SSHConfiguration *config);

  // Disconnect and free all resources.
  void disconnect();

  // True if session is live and socket is valid.
  bool isConnected() const;

  // Number of consecutive keepalive failures seen since the last success.
  int getKeepAliveFailures() const { return keepAliveFailures_; }

  // Send SSH keepalive. Returns false if the connection should be considered
  // dead.
  bool sendKeepalive();

  // Check socket health via SO_ERROR.
  bool checkConnection() const;

  // Accept a pending channel from any active listener.
  // Returns the LIBSSH2_CHANNEL* and fills outMapping with the corresponding
  // config. Returns nullptr if no channel is pending.
  LIBSSH2_CHANNEL *acceptChannel(TunnelConfig &outMapping);
  bool hasFatalAcceptFailure() const;
  int getLastAcceptError() const { return lastAcceptError_; }
  int getConsecutiveFatalAcceptErrors() const {
    return consecutiveFatalAcceptErrors_;
  }

  // Default threshold above which a listener is considered "stuck" and is
  // cancelled+recreated. Picked well below typical reverse-proxy timeouts
  // (e.g. nginx 30s) so we react before clients see a 504.
  static constexpr unsigned long kForwardListenerStuckIdleMsDefault = 15000UL;

  // If accept has been idle longer than thresholdMs while at least one prior
  // accept has succeeded, cancel each remote-forward listener and recreate it
  // with the same mapping. Active channels are untouched. Returns true if at
  // least one listener was recreated. thresholdMs == 0 disables the watchdog.
  bool relistenStuckListeners(
      unsigned long nowMs,
      unsigned long thresholdMs = kForwardListenerStuckIdleMsDefault);

  // Lock/unlock the session mutex for external libssh2 calls (e.g.,
  // channel_read/write).
  bool lock(TickType_t ticks = portMAX_DELAY);
  void unlock();

  // Direct access for TransportPump (avoid double-lock overhead).
  LIBSSH2_SESSION *getSession() const { return session_; }
  int getSocketFd() const { return socketfd_; }

  // Listener access
  int getBoundPort() const { return boundPort_; }
  const std::vector<ListenerEntry> &getListeners() const { return listeners_; }

  // Number of listeners that are currently bound on the remote side.
  // Test/diagnostic only; cheap to call.
  int getActiveListenerCount() const {
    int n = 0;
    for (const auto &e : listeners_) {
      if (e.listener != nullptr) ++n;
    }
    return n;
  }

private:
  // Connection steps
  bool tcpConnect(const SSHServerConfig &sshConfig);
  bool handshake();
  bool configureKeepalive(const ConnectionConfig &connConfig);
  bool verifyHostKey(const SSHServerConfig &sshConfig);
  bool authenticate(const SSHServerConfig &sshConfig);
  bool createListeners(SSHConfiguration *config);

  // Listener helpers
  bool createListenerForMapping(const TunnelConfig &mapping,
                                ListenerEntry &entry);
  void cancelListener(ListenerEntry &entry);
  void cancelAllListeners();

  // Cleanup
  void cleanupSession();
  void resetAcceptState();
  void recordAcceptSuccess();
  void recordAcceptNoChannel(int err);
  bool isFatalAcceptError(int err) const;

  // Members
  LIBSSH2_SESSION *session_ = nullptr;
  int socketfd_ = -1;
  SemaphoreHandle_t sessionMutex_ = nullptr;
  SSHConfiguration *config_ = nullptr;
  std::vector<ListenerEntry> listeners_;
  int boundPort_ = -1;
  int keepAliveFailures_ = 0;
  int lastAcceptError_ = 0;
  int consecutiveFatalAcceptErrors_ = 0;
  unsigned long lastAcceptMs_ = 0;
  unsigned long totalAccepts_ = 0;
  bool libssh2Initialized_ = false;
#ifdef TUNNEL_DIAG_LOG_ONLY
  forward_accept_diag::Tracker acceptDiag_;
#endif
};

// Fingerprint encoding helpers (used by verifyHostKey)
String encodeFingerprintHex(const unsigned char *data, size_t len);
String encodeFingerprintBase64(const unsigned char *data, size_t len);

#endif // SSH_SESSION_H
