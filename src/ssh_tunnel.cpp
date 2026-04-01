#include "ssh_tunnel.h"
#include <unistd.h>

namespace {

enum class BindResult { Bound, Failed, LockUnavailable };

bool closeAcceptedChannel(SSHSession &session, LIBSSH2_CHANNEL *channel,
                          TickType_t lockTicks, const char *logDetail) {
  if (!channel) {
    return true;
  }

  if (logDetail) {
    LOG_W("SSH", logDetail);
  }

  if (session.lock(lockTicks)) {
    libssh2_channel_close(channel);
    libssh2_channel_free(channel);
    session.unlock();
    return true;
  }

  return false;
}

BindResult bindAcceptedChannel(SSHSession &session, ChannelManager &channels,
                               int slot, LIBSSH2_CHANNEL *channel,
                               const TunnelConfig &mapping,
                               TickType_t lockTicks) {
  if (!session.lock(lockTicks)) {
    return BindResult::LockUnavailable;
  }

  bool bound = channels.bindChannel(slot, channel, mapping);
  session.unlock();
  return bound ? BindResult::Bound : BindResult::Failed;
}

} // namespace

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
  socketHealthFailures_ = 0;
  lastKeepAlive_ = millis();
  emitSessionConnected();

  LOGF_I("SSH", "Tunnel connected, bound port %d", session_.getBoundPort());
  return true;
}

void SSHTunnel::disconnect() {
  // Close all pending queued channels first
  clearPendingQueue();
  clearDeferredCloseQueue();

  // Close all active channels
  bool locked = false;
  if (session_.isConnected()) {
    locked = session_.lock(pdMS_TO_TICKS(2000));
  }
  for (int i = 0; i < channels_.getMaxSlots(); ++i) {
    if (!channels_.getSlot(i).active) {
      continue;
    }
    if (locked) {
      channels_.finalizeClose(i);
    } else {
      channels_.abandonSlot(i, ChannelCloseReason::Manual);
    }
    emitChannelClosed(i, ChannelCloseReason::Manual);
  }
  if (locked) {
    session_.unlock();
  }

  session_.disconnect();

  // If session teardown invalidated libssh2 state before the slots were
  // finalized, make sure no stale active slots remain blocked forever.
  for (int i = 0; i < channels_.getMaxSlots(); ++i) {
    channels_.abandonSlot(i, ChannelCloseReason::Manual);
  }
  for (int i = 0; i < pendingCount_; ++i) {
    pendingQueue_[i].channel = nullptr;
  }
  pendingCount_ = 0;
  for (int i = 0; i < deferredCloseCount_; ++i) {
    deferredCloseQueue_[i].channel = nullptr;
  }
  deferredCloseCount_ = 0;

  if (state_ == TUNNEL_CONNECTED) {
    emitSessionDisconnected();
  }
  socketHealthFailures_ = 0;
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
    socketHealthFailures_++;
    if (socketHealthFailures_ >= 3) {
      enterErrorState("socket health check failed");
      return;
    }
    LOGF_W("SSH", "Socket health check failed (%d/3), waiting for confirmation",
           socketHealthFailures_);
  } else {
    socketHealthFailures_ = 0;
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

  if (deferredCloseCount_ > 0) {
    drainDeferredCloseQueue();
  }

  // Accept new connections (one per loop to avoid PSRAM heap fragmentation
  // from rapid ring buffer allocation cycles)
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
    cleanExpiredPending();
    drainPendingQueue();
  }
  if (deferredCloseCount_ > 0) {
    drainDeferredCloseQueue();
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
  if (slot >= 0) {
    BindResult bindResult = bindAcceptedChannel(session_, channels_, slot, ch,
                                                mapping, pdMS_TO_TICKS(200));
    if (bindResult == BindResult::Bound) {
      emitChannelOpened(slot);
      return true;
    }
    if (bindResult == BindResult::LockUnavailable) {
      LOG_W("SSH", "Session lock unavailable while binding accepted channel");
      if (pendingCount_ < MAX_PENDING) {
        PendingChannel &pending = pendingQueue_[pendingCount_];
        pending.channel = ch;
        pending.mapping = mapping;
        pending.queuedAtMs = millis();
        pending.action = PendingChannel::Action::Bind;
        pendingCount_++;
        LOGF_I("SSH",
               "Channel queued for later binding after lock contention "
               "(pending: %d/%d)",
               pendingCount_, MAX_PENDING);
        return false;
      }
      // Pending queue full + lock unavailable: queue as Close, don't destroy
      // the tunnel for transient contention
      if (!enqueueDeferredClose(ch, mapping,
                                "Deferring close: lock unavailable and "
                                "pending queue full")) {
        LOG_W("SSH", "All queues full, dropping channel (transient)");
      }
      return false;
    }

    // Bind failure means the local endpoint or channel resources are not
    // usable right now — close the channel, don't keep it hanging.
    if (!enqueueDeferredClose(ch, mapping,
                              "Rejecting accepted channel after bind "
                              "failure")) {
      LOG_W("SSH", "Deferred close queue full, dropping channel");
    }
    return false;
  }

  // No slot available — queue the channel
  if (pendingCount_ < MAX_PENDING) {
    PendingChannel &pending = pendingQueue_[pendingCount_];
    pending.channel = ch;
    pending.mapping = mapping;
    pending.queuedAtMs = millis();
    pending.action = PendingChannel::Action::Bind;
    pendingCount_++;
    LOGF_I("SSH", "Channel queued for later binding (pending: %d/%d)",
           pendingCount_, MAX_PENDING);
    return false;
  }

  // Queue is also full — reject the connection, but don't destroy the tunnel
  LOG_W("SSH", "Pending queue full, rejecting connection");
  if (!closeAcceptedChannel(session_, ch, pdMS_TO_TICKS(500), nullptr) &&
      !enqueueDeferredClose(ch, mapping,
                            "Pending queue full and close deferred")) {
    // All queues saturated — last resort: leak the channel rather than
    // tearing down the entire tunnel for a transient overload.
    LOG_E("SSH", "All queues full, channel leaked (will be freed on session "
                 "disconnect)");
  }
  return false;
}

void SSHTunnel::drainPendingQueue() {
  unsigned long now = millis();
  int writeIdx = 0;
  for (int i = 0; i < pendingCount_; ++i) {
    PendingChannel &pending = pendingQueue_[i];

    if (!pending.channel) {
      continue;
    }

    if (pending.action == PendingChannel::Action::Close) {
      unsigned long age = now - pending.queuedAtMs;
      if (age > CLOSE_RETRY_TIMEOUT_MS) {
        // Close retry timed out — force-free with session lock or abandon
        LOGF_W("SSH",
               "Pending close entry expired after %lums, force-freeing", age);
        if (session_.lock(pdMS_TO_TICKS(100))) {
          libssh2_channel_free(pending.channel);
          session_.unlock();
        }
        pending.channel = nullptr;
        continue;
      }
      if (!closeAcceptedChannel(session_, pending.channel, pdMS_TO_TICKS(200),
                                "Retrying deferred close of queued channel")) {
        if (writeIdx != i) {
          pendingQueue_[writeIdx] = pending;
        }
        writeIdx++;
      } else {
        pending.channel = nullptr;
      }
      continue;
    }

    if ((now - pending.queuedAtMs) > PENDING_TIMEOUT_MS) {
      LOGF_W("SSH", "Pending channel expired after %lums, dropping",
             now - pending.queuedAtMs);
      if (!closeAcceptedChannel(session_, pending.channel, pdMS_TO_TICKS(200),
                                nullptr)) {
        pending.action = PendingChannel::Action::Close;
        if (writeIdx != i) {
          pendingQueue_[writeIdx] = pending;
        }
        writeIdx++;
      } else {
        pending.channel = nullptr;
      }
      continue;
    }

    int slot = channels_.allocateSlot();
    if (slot >= 0) {
      BindResult bindResult =
          bindAcceptedChannel(session_, channels_, slot, pending.channel,
                              pending.mapping, pdMS_TO_TICKS(200));
      if (bindResult == BindResult::Bound) {
        LOGF_I("SSH", "Queued channel bound to slot %d (waited %lums)", slot,
               millis() - pending.queuedAtMs);
        emitChannelOpened(slot);
        pending.channel = nullptr; // consumed
      } else {
        if (bindResult == BindResult::LockUnavailable) {
          if (writeIdx != i) {
            pendingQueue_[writeIdx] = pending;
          }
          writeIdx++;
          continue;
        }

        LOGF_W("SSH",
               "Dropping queued channel for %s:%d -> %s:%d after bind "
               "failure",
               pending.mapping.remoteBindHost.c_str(),
               pending.mapping.remoteBindPort,
               pending.mapping.localHost.c_str(), pending.mapping.localPort);
        if (!closeAcceptedChannel(session_, pending.channel, pdMS_TO_TICKS(200),
                                  nullptr)) {
          pending.action = PendingChannel::Action::Close;
          if (writeIdx != i) {
            pendingQueue_[writeIdx] = pending;
          }
          writeIdx++;
        } else {
          pending.channel = nullptr; // dropped
        }
      }
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

void SSHTunnel::drainDeferredCloseQueue() {
  unsigned long now = millis();
  int writeIdx = 0;
  for (int i = 0; i < deferredCloseCount_; ++i) {
    PendingChannel &pending = deferredCloseQueue_[i];
    if (!pending.channel) {
      continue;
    }
    unsigned long age = now - pending.queuedAtMs;
    if (age > CLOSE_RETRY_TIMEOUT_MS) {
      LOGF_W("SSH",
             "Deferred close entry expired after %lums, force-freeing", age);
      if (session_.lock(pdMS_TO_TICKS(100))) {
        libssh2_channel_free(pending.channel);
        session_.unlock();
      }
      pending.channel = nullptr;
      continue;
    }
    if (!closeAcceptedChannel(session_, pending.channel, pdMS_TO_TICKS(200),
                              "Retrying deferred close of accepted channel")) {
      if (writeIdx != i) {
        deferredCloseQueue_[writeIdx] = pending;
      }
      writeIdx++;
    } else {
      pending.channel = nullptr;
    }
  }
  deferredCloseCount_ = writeIdx;
}

void SSHTunnel::cleanExpiredPending() {
  unsigned long now = millis();
  int writeIdx = 0;
  for (int i = 0; i < pendingCount_; ++i) {
    PendingChannel &pending = pendingQueue_[i];
    if (!pending.channel) {
      continue;
    }
    if (pending.action == PendingChannel::Action::Bind &&
        (now - pending.queuedAtMs) > PENDING_TIMEOUT_MS) {
      LOGF_W("SSH", "Pending channel expired after %lums, dropping",
             now - pending.queuedAtMs);
      if (!closeAcceptedChannel(session_, pending.channel, pdMS_TO_TICKS(200),
                                nullptr)) {
        pending.action = PendingChannel::Action::Close;
        if (writeIdx != i) {
          pendingQueue_[writeIdx] = pending;
        }
        writeIdx++;
      } else {
        pending.channel = nullptr;
      }
    } else {
      if (writeIdx != i) {
        pendingQueue_[writeIdx] = pending;
      }
      writeIdx++;
    }
  }
  pendingCount_ = writeIdx;
}

bool SSHTunnel::clearPendingQueue() {
  if (pendingCount_ == 0) {
    return true;
  }
  LOGF_I("SSH", "Clearing %d pending queued channels", pendingCount_);
  bool locked = session_.lock(pdMS_TO_TICKS(500));
  if (!locked) {
    LOG_W("SSH", "Could not lock session to clear pending queue");
    return false;
  }
  for (int i = 0; i < pendingCount_; ++i) {
    if (pendingQueue_[i].channel) {
      libssh2_channel_close(pendingQueue_[i].channel);
      libssh2_channel_free(pendingQueue_[i].channel);
      pendingQueue_[i].channel = nullptr;
    }
  }
  session_.unlock();
  pendingCount_ = 0;
  return true;
}

bool SSHTunnel::enqueueDeferredClose(LIBSSH2_CHANNEL *channel,
                                     const TunnelConfig &mapping,
                                     const char *reason) {
  if (!channel) {
    return true;
  }
  if (closeAcceptedChannel(session_, channel, pdMS_TO_TICKS(200), reason)) {
    return true;
  }
  if (deferredCloseCount_ >= MAX_DEFERRED_CLOSE) {
    LOG_W("SSH", "Deferred close queue full");
    return false;
  }

  PendingChannel &pending = deferredCloseQueue_[deferredCloseCount_++];
  pending.channel = channel;
  pending.mapping = mapping;
  pending.queuedAtMs = millis();
  pending.action = PendingChannel::Action::Close;
  LOGF_W("SSH", "Channel queued for deferred close (pending close: %d/%d)",
         deferredCloseCount_, MAX_DEFERRED_CLOSE);
  return true;
}

bool SSHTunnel::clearDeferredCloseQueue() {
  if (deferredCloseCount_ == 0) {
    return true;
  }
  bool locked = session_.lock(pdMS_TO_TICKS(500));
  if (!locked) {
    LOG_W("SSH", "Could not lock session to clear deferred close queue");
    return false;
  }
  for (int i = 0; i < deferredCloseCount_; ++i) {
    if (deferredCloseQueue_[i].channel) {
      libssh2_channel_close(deferredCloseQueue_[i].channel);
      libssh2_channel_free(deferredCloseQueue_[i].channel);
      deferredCloseQueue_[i].channel = nullptr;
    }
  }
  session_.unlock();
  deferredCloseCount_ = 0;
  return true;
}

void SSHTunnel::enterErrorState(const char *reason) {
  LOGF_W("SSH", "Entering error state: %s", reason);

  // Close all pending queued channels
  clearPendingQueue();
  clearDeferredCloseQueue();

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
    // Lock failed — the SSH session is already unhealthy, so release the
    // local resources and free the slots without touching libssh2.
    for (int i = 0; i < channels_.getMaxSlots(); ++i) {
      ChannelSlot &ch = channels_.getSlot(i);
      if (ch.active) {
        ChannelCloseReason cr = ch.closeReason;
        if (cr == ChannelCloseReason::Unknown) {
          cr = ChannelCloseReason::Error;
        }
        channels_.abandonSlot(i, cr);
        emitChannelClosed(i, cr);
      }
    }
  }

  session_.disconnect();
  for (int i = 0; i < channels_.getMaxSlots(); ++i) {
    channels_.abandonSlot(i, ChannelCloseReason::Error);
  }
  for (int i = 0; i < pendingCount_; ++i) {
    pendingQueue_[i].channel = nullptr;
  }
  pendingCount_ = 0;
  for (int i = 0; i < deferredCloseCount_; ++i) {
    deferredCloseQueue_[i].channel = nullptr;
  }
  deferredCloseCount_ = 0;

  state_ = TUNNEL_ERROR;
  socketHealthFailures_ = 0;
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
  clearPendingQueue();
  clearDeferredCloseQueue();
  session_.disconnect();
  for (int i = 0; i < channels_.getMaxSlots(); ++i) {
    channels_.abandonSlot(i, ChannelCloseReason::Error);
  }
  for (int i = 0; i < pendingCount_; ++i) {
    pendingQueue_[i].channel = nullptr;
  }
  pendingCount_ = 0;
  for (int i = 0; i < deferredCloseCount_; ++i) {
    deferredCloseQueue_[i].channel = nullptr;
  }
  deferredCloseCount_ = 0;
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
