#include "ssh_tunnel.h"
#include <unistd.h>

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
  // Close all pending queued channels first
  clearPendingQueue();

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
    enterErrorState("session lost");
    return;
  }

  // Check socket health
  if (!session_.checkConnection()) {
    enterErrorState("socket health check failed");
    return;
  }

  // Send keepalive if needed
  unsigned long now = millis();
  int keepAliveInterval =
      config_->getConnectionConfig().keepAliveIntervalSec * 1000;
  if (keepAliveInterval > 0 &&
      (now - lastKeepAlive_) >= (unsigned long)keepAliveInterval) {
    if (!session_.sendKeepalive()) {
      enterErrorState("keepalive failed");
      return;
    }
    lastKeepAlive_ = now;
  }

  // Accept new connections
  handleNewConnection();

  // Pump all data (the core of the new architecture)
  transport_.pumpAll();

  // Emit close events recorded during pumpAll (outside session lock)
  TransportPump::CloseEvent closeEvents[TransportPump::MAX_CLOSE_EVENTS];
  int closeCount = transport_.consumeCloseEvents(
      closeEvents, TransportPump::MAX_CLOSE_EVENTS);
  for (int i = 0; i < closeCount; ++i) {
    emitChannelClosed(closeEvents[i].slot, closeEvents[i].reason);
  }

  // Drain pending queue into freshly freed slots
  if (pendingCount_ > 0) {
    drainPendingQueue();
    cleanExpiredPending();
  }

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
  // Always try to accept from libssh2, even if slots are full.
  // This prevents the SSH server from timing out the forwarded channel.
  TunnelConfig mapping;
  LIBSSH2_CHANNEL *ch = session_.acceptChannel(mapping);
  if (!ch) {
    return false;
  }

  // Try to bind directly if a slot is available
  int slot = channels_.allocateSlot();
  if (slot >= 0 && channels_.bindChannel(slot, ch, mapping)) {
    emitChannelOpened(slot);
    return true;
  }

  // No slot available (or bind failed) — queue the channel
  if (pendingCount_ < MAX_PENDING) {
    PendingChannel &pending = pendingQueue_[pendingCount_];
    pending.channel = ch;
    pending.mapping = mapping;
    pending.queuedAtMs = millis();
    pendingCount_++;
    LOGF_I("SSH", "Channel queued for later binding (pending: %d/%d)",
           pendingCount_, MAX_PENDING);
    return false;
  }

  // Queue is also full — reject the connection
  LOG_W("SSH", "Pending queue full, rejecting connection");
  if (session_.lock(pdMS_TO_TICKS(200))) {
    libssh2_channel_close(ch);
    libssh2_channel_free(ch);
    session_.unlock();
  }
  return false;
}

void SSHTunnel::drainPendingQueue() {
  int writeIdx = 0;
  for (int i = 0; i < pendingCount_; ++i) {
    PendingChannel &pending = pendingQueue_[i];

    int slot = channels_.allocateSlot();
    if (slot >= 0 && channels_.bindChannel(slot, pending.channel, pending.mapping)) {
      LOGF_I("SSH", "Queued channel bound to slot %d (waited %lums)", slot,
             millis() - pending.queuedAtMs);
      emitChannelOpened(slot);
      pending.channel = nullptr; // consumed
    } else {
      // Keep in queue — compact in place
      if (writeIdx != i) {
        pendingQueue_[writeIdx] = pending;
      }
      writeIdx++;
    }
  }
  pendingCount_ = writeIdx;
}

void SSHTunnel::cleanExpiredPending() {
  unsigned long now = millis();
  int writeIdx = 0;
  for (int i = 0; i < pendingCount_; ++i) {
    PendingChannel &pending = pendingQueue_[i];
    if ((now - pending.queuedAtMs) > PENDING_TIMEOUT_MS) {
      LOGF_W("SSH", "Pending channel expired after %lums, dropping",
             now - pending.queuedAtMs);
      if (session_.lock(pdMS_TO_TICKS(200))) {
        libssh2_channel_close(pending.channel);
        libssh2_channel_free(pending.channel);
        session_.unlock();
      }
      pending.channel = nullptr;
    } else {
      if (writeIdx != i) {
        pendingQueue_[writeIdx] = pending;
      }
      writeIdx++;
    }
  }
  pendingCount_ = writeIdx;
}

void SSHTunnel::clearPendingQueue() {
  if (pendingCount_ == 0) {
    return;
  }
  LOGF_I("SSH", "Clearing %d pending queued channels", pendingCount_);
  bool locked = session_.lock(pdMS_TO_TICKS(500));
  for (int i = 0; i < pendingCount_; ++i) {
    if (pendingQueue_[i].channel) {
      if (locked) {
        libssh2_channel_close(pendingQueue_[i].channel);
        libssh2_channel_free(pendingQueue_[i].channel);
      }
      pendingQueue_[i].channel = nullptr;
    }
  }
  if (locked) {
    session_.unlock();
  }
  pendingCount_ = 0;
}

void SSHTunnel::enterErrorState(const char *reason) {
  LOGF_W("SSH", "Entering error state: %s", reason);

  // Close all pending queued channels
  clearPendingQueue();

  // Close all orphan channels and their local sockets to prevent leaks
  if (session_.lock(pdMS_TO_TICKS(500))) {
    for (int i = 0; i < channels_.getMaxSlots(); ++i) {
      if (channels_.getSlot(i).active) {
        ChannelCloseReason cr = channels_.getSlot(i).closeReason;
        if (cr == ChannelCloseReason::Unknown) {
          cr = ChannelCloseReason::Error;
        }
        channels_.finalizeClose(i);
        emitChannelClosed(i, cr);
      }
    }
    session_.unlock();
  } else {
    // Lock failed — at minimum close local sockets to avoid fd leak
    for (int i = 0; i < channels_.getMaxSlots(); ++i) {
      ChannelSlot &ch = channels_.getSlot(i);
      if (ch.active && ch.localSocket >= 0) {
        close(ch.localSocket);
        ch.localSocket = -1;
      }
    }
  }

  state_ = TUNNEL_ERROR;
  lastConnectionAttempt_ = millis();
  emitSessionDisconnected();
}

void SSHTunnel::handleReconnection() {
  int maxReconnectAttempts =
      config_->getConnectionConfig().maxReconnectAttempts;

  if (reconnectAttempts_ >= maxReconnectAttempts) {
    // All attempts exhausted — wait a long cooldown then reset the counter
    // so reconnection resumes automatically (essential for 24/7 devices).
    unsigned long now = millis();
    unsigned long cooldown = 60000UL; // 60s cooldown after exhausting attempts
    if (now - lastConnectionAttempt_ < cooldown) {
      return;
    }
    LOGF_I("SSH", "Reconnect cooldown elapsed, resetting attempts (was %d/%d)",
           reconnectAttempts_, maxReconnectAttempts);
    reconnectAttempts_ = 0;
  }

  // Exponential backoff: baseDelay * 2^attempt, capped at 60s
  unsigned long now = millis();
  int baseDelay = config_->getConnectionConfig().reconnectDelayMs;
  unsigned long delay = baseDelay;
  for (int i = 0; i < reconnectAttempts_ && delay < 60000UL; ++i) {
    delay *= 2;
  }
  if (delay > 60000UL) {
    delay = 60000UL;
  }

  if (now - lastConnectionAttempt_ < delay) {
    return;
  }

  LOGF_I("SSH", "Attempting reconnection %d/%d (delay was %lums)...",
         reconnectAttempts_ + 1, maxReconnectAttempts, delay);
  disconnect();
  reconnectAttempts_++;

  if (connectSSH()) {
    LOG_I("SSH", "Reconnection successful");
    reconnectAttempts_ = 0;
  } else {
    LOGF_E("SSH", "Reconnection failed (%d/%d)", reconnectAttempts_,
           maxReconnectAttempts);
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
