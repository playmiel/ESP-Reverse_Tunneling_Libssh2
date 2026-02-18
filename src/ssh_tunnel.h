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

// ChannelCloseReason and TunnelErrorCode are defined in ssh_channel.h

struct SSHTunnelEvents {
  void (*onSessionConnected)() = nullptr;
  void (*onSessionDisconnected)() = nullptr;
  void (*onChannelOpened)(int) = nullptr;
  void (*onChannelClosed)(int, ChannelCloseReason) = nullptr;
  void (*onError)(int, const char *) = nullptr;
  void (*onChannelWriteBroken)(int, TunnelErrorCode, int,
                               const char *) = nullptr;
  void (*onLargeTransferStart)(int) = nullptr;
  void (*onLargeTransferEnd)(int) = nullptr;
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

  // Reconnection logic
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

  // Statistics
  SemaphoreHandle_t statsMutex_ = nullptr;
  unsigned long bytesReceived_ = 0;
  unsigned long bytesSent_ = 0;

  // Configuration
  SSHConfiguration *config_ = nullptr;

  // Events
  SSHTunnelEvents eventHandlers_ = {};
};

#endif // SSH_TUNNEL_H
