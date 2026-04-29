#ifndef SSH_TUNNEL_H
#define SSH_TUNNEL_H

#include "ssh_channel.h"
#include "ssh_config.h"
#include "ssh_session.h"
#include "ssh_transport.h"
#include <Arduino.h>

// TunnelState and event types - kept identical for API compatibility
enum TunnelState {
  TUNNEL_DISCONNECTED = 0,
  TUNNEL_CONNECTING = 1,
  TUNNEL_CONNECTED = 2,
  TUNNEL_ERROR = 3
};

// ChannelCloseReason is defined in ssh_channel.h

struct SSHTunnelEvents {
  void (*onSessionConnected)() = nullptr;
  void (*onSessionDisconnected)() = nullptr;
  void (*onChannelOpened)(int) = nullptr;
  void (*onChannelClosed)(int, ChannelCloseReason) = nullptr;
  void (*onError)(int, const char *) = nullptr;
};

// A forwarded channel waiting for a free slot.
struct PendingChannel {
  enum class Action { Bind, Close };

  LIBSSH2_CHANNEL *channel = nullptr;
  TunnelConfig mapping;
  unsigned long queuedAtMs = 0;
  Action action = Action::Bind;
};

// SSHTunnel: public facade with the same API as before.
// Internally delegates to SSHSession, ChannelManager, and TransportPump.
class SSHTunnel {
public:
  SSHTunnel();
  ~SSHTunnel();

  // Initialize subsystems. Call once before connectSSH().
  bool init();

  // Connect to SSH server, authenticate, create listeners.
  bool connectSSH();

  // Disconnect everything (channels, session, socket).
  void disconnect();

  // True if SSH session is live.
  bool isConnected();

  // Main loop: accept connections, pump data, handle keepalive.
  // Call repeatedly from your FreeRTOS task.
  void loop();

  // State accessors
  TunnelState getState();
  String getStateString();
  int getBoundPort() const;

  // Statistics
  unsigned long getBytesReceived();
  unsigned long getBytesSent();
  unsigned long getBytesDropped();
  int getActiveChannels();
  // Number of reverse-tunnel listeners currently bound on the remote side.
  // Test/diagnostic helper; surfaces SSHSession::getActiveListenerCount().
  int getActiveListenerCount() const {
    return session_.getActiveListenerCount();
  }
  // Total CLOSED -> OPEN transitions of any per-mapping circuit breaker
  // since boot. Surfaced so integration tests can structurally detect
  // breaker engagement without parsing log text.
  unsigned long getBreakerTrips();
  int getKeepAliveFailures() const { return session_.getKeepAliveFailures(); }
  int getSocketHealthFailures() const { return socketHealthFailures_; }

  // Event handlers
  void setEventHandlers(const SSHTunnelEvents &handlers);

  // Dynamic tunnel management (add/remove listeners at runtime)
  bool addReverseTunnel(const TunnelConfig &mapping);
  bool removeReverseTunnel(const String &remoteHost, int remotePort);

  // Backpressure query for adaptive delay in caller loop
  bool hasAnyBackpressure() const;

private:
  // Accept pending SSH channel and bind to a local socket
  bool handleNewConnection();

  // Drain queued connections into newly freed slots
  void drainPendingQueue();

  // Retry closing channels that could not be freed immediately because the
  // session lock was unavailable.
  void drainDeferredCloseQueue();

  // Close and free channels that exceeded PENDING_TIMEOUT_MS
  void cleanExpiredPending();

  // Close and free all pending channels (used on disconnect/error)
  bool clearPendingQueue();

  // Track accepted channels that must be closed later once the session lock is
  // available again.
  bool enqueueDeferredClose(LIBSSH2_CHANNEL *channel,
                            const TunnelConfig &mapping, const char *reason);
  bool clearDeferredCloseQueue();

  // Error handling: clean orphan channels + sockets, then set TUNNEL_ERROR
  void enterErrorState(const char *reason);

  // Reconnection logic (with exponential backoff + auto-reset)
  void handleReconnection();

  // Event emission helpers
  void emitSessionConnected();
  void emitSessionDisconnected();
  void emitChannelOpened(int channelIndex);
  void emitChannelClosed(int channelIndex, ChannelCloseReason reason);
  void emitErrorEvent(int code, const char *detail);

  // Core modules
  SSHSession session_;
  ChannelManager channels_;
  TransportPump transport_;

  // State
  TunnelState state_ = TUNNEL_DISCONNECTED;
  unsigned long lastKeepAlive_ = 0;
  unsigned long lastConnectionAttempt_ = 0;
  int reconnectAttempts_ = 0;
  int socketHealthFailures_ = 0;

  // Statistics
  SemaphoreHandle_t statsMutex_ = nullptr;
  unsigned long bytesReceived_ = 0;
  unsigned long bytesSent_ = 0;

  // Configuration
  SSHConfiguration *config_ = nullptr;

  // Pending connection queue
  static constexpr int MAX_PENDING = 8;
  static constexpr int MAX_DEFERRED_CLOSE = 4;
  static constexpr unsigned long PENDING_TIMEOUT_MS = 5000;
  static constexpr unsigned long CLOSE_RETRY_TIMEOUT_MS = 5000;
  PendingChannel pendingQueue_[MAX_PENDING];
  int pendingCount_ = 0;
  PendingChannel deferredCloseQueue_[MAX_DEFERRED_CLOSE];
  int deferredCloseCount_ = 0;

  // Events
  SSHTunnelEvents eventHandlers_ = {};
};

#endif // SSH_TUNNEL_H
