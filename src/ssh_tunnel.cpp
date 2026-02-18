#include "ssh_tunnel.h"

// ---------------------------------------------------------------------------
// SSHTunnel - Facade
// ---------------------------------------------------------------------------

SSHTunnel::SSHTunnel() {}

SSHTunnel::~SSHTunnel() {
  disconnect();
  if (statsMutex_) {
    vSemaphoreDelete(statsMutex_);
    statsMutex_ = nullptr;
  }
}

bool SSHTunnel::init() {
  config_ = &globalSSHConfig;

  // Create stats mutex
  if (!statsMutex_) {
    statsMutex_ = xSemaphoreCreateMutex();
    if (!statsMutex_) {
      LOG_E("SSH", "Failed to create stats mutex");
      return false;
    }
  }

  // Initialize SSH session module
  if (!session_.init()) {
    LOG_E("SSH", "Failed to initialize SSH session");
    return false;
  }

  // Initialize channel manager
  const ConnectionConfig &connConfig = config_->getConnectionConfig();
  size_t perDirectionSize = connConfig.tunnelRingBufferSize;
  if (perDirectionSize < 8192) {
    perDirectionSize = 8192; // Minimum 8KB per direction
  }

  if (!channels_.init(connConfig.maxChannels, perDirectionSize)) {
    LOG_E("SSH", "Failed to initialize channel manager");
    return false;
  }

  // Initialize transport pump
  size_t bufSize = connConfig.bufferSize > 0 ? connConfig.bufferSize : 4096;
  if (!transport_.init(bufSize)) {
    LOG_E("SSH", "Failed to initialize transport pump");
    return false;
  }
  transport_.attach(&session_, &channels_);

  state_ = TUNNEL_DISCONNECTED;
  LOG_I("SSH", "SSHTunnel initialized (v2 modular architecture)");
  return true;
}

bool SSHTunnel::connectSSH() {
  if (state_ == TUNNEL_CONNECTED) {
    return true;
  }

  state_ = TUNNEL_CONNECTING;
  lastConnectionAttempt_ = millis();

  if (!session_.connect(config_)) {
    state_ = TUNNEL_ERROR;
    emitErrorEvent(-1, "SSH connection failed");
    return false;
  }

  state_ = TUNNEL_CONNECTED;
  reconnectAttempts_ = 0;
  lastKeepAlive_ = millis();
  emitSessionConnected();

  LOGF_I("SSH", "Tunnel connected, bound port %d", session_.getBoundPort());
  return true;
}

void SSHTunnel::disconnect() {
  // Close all active channels
  if (session_.isConnected()) {
    if (session_.lock(pdMS_TO_TICKS(2000))) {
      for (int i = 0; i < channels_.getMaxSlots(); ++i) {
        if (channels_.getSlot(i).active) {
          channels_.finalizeClose(i);
          emitChannelClosed(i, ChannelCloseReason::Manual);
        }
      }
      session_.unlock();
    }
  }

  session_.disconnect();

  if (state_ == TUNNEL_CONNECTED) {
    emitSessionDisconnected();
  }
  state_ = TUNNEL_DISCONNECTED;
}

bool SSHTunnel::isConnected() {
  return state_ == TUNNEL_CONNECTED && session_.isConnected();
}

void SSHTunnel::loop() {
  if (state_ == TUNNEL_ERROR) {
    handleReconnection();
    return;
  }
  if (state_ == TUNNEL_DISCONNECTED) {
    return;
  }

  if (!session_.isConnected()) {
    state_ = TUNNEL_ERROR;
    emitSessionDisconnected();
    return;
  }

  // Check socket health
  if (!session_.checkConnection()) {
    LOG_W("SSH", "Socket health check failed");
    state_ = TUNNEL_ERROR;
    return;
  }

  // Send keepalive if needed
  unsigned long now = millis();
  int keepAliveInterval =
      config_->getConnectionConfig().keepAliveIntervalSec * 1000;
  if (keepAliveInterval > 0 &&
      (now - lastKeepAlive_) >= (unsigned long)keepAliveInterval) {
    if (!session_.sendKeepalive()) {
      state_ = TUNNEL_ERROR;
      return;
    }
    lastKeepAlive_ = now;
  }

  // Accept new connections
  handleNewConnection();

  // Pump all data (the core of the new architecture)
  transport_.pumpAll();

  // Update aggregate stats
  if (statsMutex_ && xSemaphoreTake(statsMutex_, pdMS_TO_TICKS(5)) == pdTRUE) {
    bytesReceived_ = channels_.getTotalBytesReceived();
    bytesSent_ = channels_.getTotalBytesSent();
    xSemaphoreGive(statsMutex_);
  }
}

TunnelState SSHTunnel::getState() { return state_; }

String SSHTunnel::getStateString() {
  switch (state_) {
  case TUNNEL_DISCONNECTED:
    return "Disconnected";
  case TUNNEL_CONNECTING:
    return "Connecting";
  case TUNNEL_CONNECTED:
    return "Connected";
  case TUNNEL_ERROR:
    return "Error";
  default:
    return "Unknown";
  }
}

int SSHTunnel::getBoundPort() const { return session_.getBoundPort(); }

unsigned long SSHTunnel::getBytesReceived() { return bytesReceived_; }

unsigned long SSHTunnel::getBytesSent() { return bytesSent_; }

unsigned long SSHTunnel::getBytesDropped() {
  return 0; // No deferred/drop mechanism in v2
}

int SSHTunnel::getActiveChannels() { return channels_.getActiveCount(); }

void SSHTunnel::setEventHandlers(const SSHTunnelEvents &handlers) {
  eventHandlers_ = handlers;
}

bool SSHTunnel::addReverseTunnel(const TunnelConfig &mapping) {
  config_->addTunnelMapping(mapping);
  return true;
}

bool SSHTunnel::removeReverseTunnel(const String &remoteHost, int remotePort) {
  const auto &mappings = config_->getTunnelMappings();
  for (size_t i = 0; i < mappings.size(); ++i) {
    if (mappings[i].remoteBindHost == remoteHost &&
        mappings[i].remoteBindPort == remotePort) {
      config_->removeTunnelMapping(i);
      return true;
    }
  }
  return false;
}

bool SSHTunnel::hasAnyBackpressure() const {
  return transport_.hasAnyBackpressure();
}

// ---------------------------------------------------------------------------
// Private
// ---------------------------------------------------------------------------

bool SSHTunnel::handleNewConnection() {
  if (!channels_.shouldAcceptNew()) {
    return false;
  }

  TunnelConfig mapping;
  LIBSSH2_CHANNEL *ch = session_.acceptChannel(mapping);
  if (!ch) {
    return false;
  }

  int slot = channels_.allocateSlot();
  if (slot < 0) {
    LOG_W("SSH", "No channel slots available, rejecting connection");
    if (session_.lock(pdMS_TO_TICKS(200))) {
      libssh2_channel_close(ch);
      libssh2_channel_free(ch);
      session_.unlock();
    }
    return false;
  }

  if (!channels_.bindChannel(slot, ch, mapping)) {
    LOGF_E("SSH", "Failed to bind channel to slot %d", slot);
    if (session_.lock(pdMS_TO_TICKS(200))) {
      libssh2_channel_close(ch);
      libssh2_channel_free(ch);
      session_.unlock();
    }
    return false;
  }

  emitChannelOpened(slot);
  return true;
}

void SSHTunnel::handleReconnection() {
  int maxReconnectAttempts =
      config_->getConnectionConfig().maxReconnectAttempts;
  if (reconnectAttempts_ >= maxReconnectAttempts) {
    LOG_E("SSH", "Max reconnection attempts reached");
    state_ = TUNNEL_ERROR;
    return;
  }

  unsigned long now = millis();
  int reconnectDelay = config_->getConnectionConfig().reconnectDelayMs;
  if (now - lastConnectionAttempt_ < (unsigned long)reconnectDelay) {
    return;
  }

  LOG_I("SSH", "Attempting reconnection...");
  disconnect();
  reconnectAttempts_++;

  if (connectSSH()) {
    LOG_I("SSH", "Reconnection successful");
    reconnectAttempts_ = 0;
  } else {
    LOG_E("SSH", "Reconnection failed");
  }
}

// ---------------------------------------------------------------------------
// Event emission
// ---------------------------------------------------------------------------

void SSHTunnel::emitSessionConnected() {
  if (eventHandlers_.onSessionConnected) {
    eventHandlers_.onSessionConnected();
  }
}

void SSHTunnel::emitSessionDisconnected() {
  if (eventHandlers_.onSessionDisconnected) {
    eventHandlers_.onSessionDisconnected();
  }
}

void SSHTunnel::emitChannelOpened(int channelIndex) {
  if (eventHandlers_.onChannelOpened) {
    eventHandlers_.onChannelOpened(channelIndex);
  }
}

void SSHTunnel::emitChannelClosed(int channelIndex, ChannelCloseReason reason) {
  if (eventHandlers_.onChannelClosed) {
    eventHandlers_.onChannelClosed(channelIndex, reason);
  }
}

void SSHTunnel::emitErrorEvent(int code, const char *detail) {
  if (eventHandlers_.onError) {
    eventHandlers_.onError(code, detail);
  }
}
