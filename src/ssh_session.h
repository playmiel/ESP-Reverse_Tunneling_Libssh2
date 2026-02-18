#ifndef SSH_SESSION_H
#define SSH_SESSION_H

#include "logger.h"
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

  // Send SSH keepalive. Returns false if the connection should be considered
  // dead.
  bool sendKeepalive();

  // Check socket health via SO_ERROR.
  bool checkConnection() const;

  // Accept a pending channel from any active listener.
  // Returns the LIBSSH2_CHANNEL* and fills outMapping with the corresponding
  // config. Returns nullptr if no channel is pending.
  LIBSSH2_CHANNEL *acceptChannel(TunnelConfig &outMapping);

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

  // Members
  LIBSSH2_SESSION *session_ = nullptr;
  int socketfd_ = -1;
  SemaphoreHandle_t sessionMutex_ = nullptr;
  SSHConfiguration *config_ = nullptr;
  std::vector<ListenerEntry> listeners_;
  int boundPort_ = -1;
  int keepAliveFailures_ = 0;
  bool libssh2Initialized_ = false;
};

// Fingerprint encoding helpers (used by verifyHostKey)
String encodeFingerprintHex(const unsigned char *data, size_t len);
String encodeFingerprintBase64(const unsigned char *data, size_t len);

#endif // SSH_SESSION_H
