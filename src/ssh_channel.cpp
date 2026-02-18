#include "ssh_channel.h"
#include "memory_fixes.h"
#include "network_optimizations.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

// ---------------------------------------------------------------------------
// ChannelManager
// ---------------------------------------------------------------------------

ChannelManager::ChannelManager() {}

ChannelManager::~ChannelManager() { destroy(); }

bool ChannelManager::init(int maxChannels, size_t ringBufferSize) {
  if (slots_) {
    destroy();
  }

  maxSlots_ = maxChannels;
  ringBufferSize_ = ringBufferSize;
  activeCount_ = 0;

  slots_ = static_cast<ChannelSlot *>(
      safeMalloc(sizeof(ChannelSlot) * maxSlots_, "ChannelSlots"));
  if (!slots_) {
    LOG_E("SSH", "Failed to allocate channel slots");
    maxSlots_ = 0;
    return false;
  }

  // Placement-new to initialize each slot
  for (int i = 0; i < maxSlots_; ++i) {
    new (&slots_[i]) ChannelSlot();
  }

  LOGF_I("SSH", "ChannelManager initialized: %d slots, %zuKB ring buffers",
         maxSlots_, ringBufferSize_ / 1024);
  return true;
}

void ChannelManager::destroy() {
  if (!slots_) {
    return;
  }
  for (int i = 0; i < maxSlots_; ++i) {
    if (slots_[i].active) {
      // Close local socket
      if (slots_[i].localSocket >= 0) {
        close(slots_[i].localSocket);
        slots_[i].localSocket = -1;
      }
      // Free staging buffers
      SAFE_FREE(slots_[i].pendingSsh);
      SAFE_FREE(slots_[i].pendingLocal);
      // Free ring buffers
      delete slots_[i].toLocal;
      slots_[i].toLocal = nullptr;
      delete slots_[i].toRemote;
      slots_[i].toRemote = nullptr;
      // Note: SSH channel must be freed by caller with session lock
      slots_[i].active = false;
    }
    slots_[i].~ChannelSlot();
  }
  free(slots_);
  slots_ = nullptr;
  maxSlots_ = 0;
  activeCount_ = 0;
}

int ChannelManager::allocateSlot() {
  if (!slots_) {
    return -1;
  }

  // First pass: find inactive slot
  for (int i = 0; i < maxSlots_; ++i) {
    if (!slots_[i].active) {
      LOGF_D("SSH", "Channel slot %d selected (inactive)", i);
      return i;
    }
  }

  // Second pass: recycle stale slot (30s inactivity)
  unsigned long now = millis();
  for (int i = 0; i < maxSlots_; ++i) {
    if (slots_[i].active && (now - slots_[i].lastActivity) > 30000) {
      LOGF_I("SSH", "Recycling stale channel %d", i);
      beginClose(i, ChannelCloseReason::Timeout);
      return -1; // Don't reuse immediately; let drain complete first
    }
  }

  return -1;
}

bool ChannelManager::bindChannel(int slotIndex, LIBSSH2_CHANNEL *sshChannel,
                                 const TunnelConfig &mapping) {
  if (slotIndex < 0 || slotIndex >= maxSlots_) {
    return false;
  }

  ChannelSlot &slot = slots_[slotIndex];
  if (slot.active) {
    LOGF_W("SSH", "bindChannel: slot %d already active", slotIndex);
    return false;
  }

  // Connect to local endpoint
  int localSocket = connectToLocalEndpoint(mapping);
  if (localSocket < 0) {
    return false;
  }

  // Use static tag strings so the DataRingBuffer destructor can safely log.
  // DataRingBuffer stores a const char* — stack strings become dangling.
  static const char *const kTagsToLocal[] = {
      "ch0_toLocal", "ch1_toLocal", "ch2_toLocal", "ch3_toLocal",
      "ch4_toLocal", "ch5_toLocal", "ch6_toLocal", "ch7_toLocal"};
  static const char *const kTagsToRemote[] = {
      "ch0_toRemote", "ch1_toRemote", "ch2_toRemote", "ch3_toRemote",
      "ch4_toRemote", "ch5_toRemote", "ch6_toRemote", "ch7_toRemote"};
  const char *tagL = (slotIndex < 8) ? kTagsToLocal[slotIndex] : "chN_toLocal";
  const char *tagR = (slotIndex < 8) ? kTagsToRemote[slotIndex] : "chN_toRemote";

  DataRingBuffer *toLocal = new DataRingBuffer(ringBufferSize_, tagL);
  DataRingBuffer *toRemote = new DataRingBuffer(ringBufferSize_, tagR);

  if (!toLocal || !toRemote || toLocal->capacityBytes() == 0 ||
      toRemote->capacityBytes() == 0) {
    LOG_E("SSH", "Failed to allocate ring buffers for channel");
    delete toLocal;
    delete toRemote;
    close(localSocket);
    return false;
  }

  // Allocate staging buffers (prevent data reordering on partial writes)
  uint8_t *pendingSsh = static_cast<uint8_t *>(
      safeMalloc(ChannelSlot::PENDING_BUF_SIZE, "pendSsh"));
  uint8_t *pendingLocal = static_cast<uint8_t *>(
      safeMalloc(ChannelSlot::PENDING_BUF_SIZE, "pendLocal"));
  if (!pendingSsh || !pendingLocal) {
    LOG_E("SSH", "Failed to allocate staging buffers");
    delete toLocal;
    delete toRemote;
    SAFE_FREE(pendingSsh);
    SAFE_FREE(pendingLocal);
    close(localSocket);
    return false;
  }

  // Initialize slot
  resetSlot(slotIndex);
  slot.sshChannel = sshChannel;
  slot.localSocket = localSocket;
  slot.active = true;
  slot.state = ChannelSlot::State::Open;
  slot.toLocal = toLocal;
  slot.toRemote = toRemote;
  slot.pendingSsh = pendingSsh;
  slot.pendingLocal = pendingLocal;
  slot.lastActivity = millis();
  slot.lastSuccessfulWrite = slot.lastActivity;
  slot.lastSuccessfulRead = slot.lastActivity;
  snapshotEndpoint(slot, mapping);

  // Set SSH channel to non-blocking
  libssh2_channel_set_blocking(sshChannel, 0);

  activeCount_++;
  LOGF_I("SSH", "Channel %d bound: %s:%d -> %s:%d (active: %d/%d)",
         slotIndex, slot.endpoint.remoteHost, slot.endpoint.remotePort,
         slot.endpoint.localHost, slot.endpoint.localPort, activeCount_,
         maxSlots_);
  return true;
}

void ChannelManager::beginClose(int slotIndex, ChannelCloseReason reason) {
  if (slotIndex < 0 || slotIndex >= maxSlots_) {
    return;
  }
  ChannelSlot &slot = slots_[slotIndex];
  if (!slot.active || slot.state == ChannelSlot::State::Draining ||
      slot.state == ChannelSlot::State::Closed) {
    return;
  }

  slot.state = ChannelSlot::State::Draining;
  slot.closeStartMs = millis();
  slot.closeReason = reason;
  LOGF_I("SSH", "Channel %d: begin close (reason=%d, toLocal=%zu, toRemote=%zu)",
         slotIndex, static_cast<int>(reason),
         slot.toLocal ? slot.toLocal->size() : 0,
         slot.toRemote ? slot.toRemote->size() : 0);
}

void ChannelManager::finalizeClose(int slotIndex) {
  if (slotIndex < 0 || slotIndex >= maxSlots_) {
    return;
  }
  ChannelSlot &slot = slots_[slotIndex];
  if (!slot.active) {
    return;
  }

  LOGF_I("SSH",
         "Channel %d: finalize close (sent=%zu, recv=%zu, reason=%d)",
         slotIndex, slot.totalBytesSent, slot.totalBytesReceived,
         static_cast<int>(slot.closeReason));

  // Free SSH channel (caller must hold session lock)
  if (slot.sshChannel) {
    libssh2_channel_close(slot.sshChannel);
    libssh2_channel_free(slot.sshChannel);
    slot.sshChannel = nullptr;
  }

  // Close local socket
  if (slot.localSocket >= 0) {
    close(slot.localSocket);
    slot.localSocket = -1;
  }

  // Free staging buffers
  SAFE_FREE(slot.pendingSsh);
  SAFE_FREE(slot.pendingLocal);

  // Free ring buffers
  delete slot.toLocal;
  slot.toLocal = nullptr;
  delete slot.toRemote;
  slot.toRemote = nullptr;

  slot.active = false;
  slot.state = ChannelSlot::State::Closed;
  activeCount_--;

  LOGF_I("SSH", "Channel %d closed (active: %d/%d)", slotIndex, activeCount_,
         maxSlots_);
}

bool ChannelManager::shouldAcceptNew() const {
  if (activeCount_ >= maxSlots_) {
    return false;
  }
  // 2+ free slots: always accept
  if (activeCount_ <= maxSlots_ - 2) {
    return true;
  }
  // Last slot: accept unless a channel is in error state
  for (int i = 0; i < maxSlots_; ++i) {
    if (slots_[i].active && slots_[i].consecutiveErrors > 5) {
      return false;
    }
  }
  return true;
}

size_t ChannelManager::getTotalBytesReceived() const {
  size_t total = 0;
  for (int i = 0; i < maxSlots_; ++i) {
    total += slots_[i].totalBytesReceived;
  }
  return total;
}

size_t ChannelManager::getTotalBytesSent() const {
  size_t total = 0;
  for (int i = 0; i < maxSlots_; ++i) {
    total += slots_[i].totalBytesSent;
  }
  return total;
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

int ChannelManager::connectToLocalEndpoint(const TunnelConfig &mapping) {
  int localSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (localSocket < 0) {
    LOG_E("SSH", "Failed to create local socket");
    return -1;
  }

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(mapping.localPort);
  if (inet_pton(AF_INET, mapping.localHost.c_str(), &addr.sin_addr) != 1) {
    LOGF_E("SSH", "Invalid local host address %s", mapping.localHost.c_str());
    close(localSocket);
    return -1;
  }

  if (::connect(localSocket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    LOGF_E("SSH", "Failed to connect to local endpoint %s:%d",
           mapping.localHost.c_str(), mapping.localPort);
    close(localSocket);
    return -1;
  }

  if (!NetworkOptimizer::optimizeSocket(localSocket)) {
    LOG_W("SSH", "Failed to optimize local socket");
  }

  // Set non-blocking
  int flags = fcntl(localSocket, F_GETFL, 0);
  fcntl(localSocket, F_SETFL, flags | O_NONBLOCK);

  return localSocket;
}

void ChannelManager::snapshotEndpoint(ChannelSlot &slot,
                                      const TunnelConfig &mapping) {
  snprintf(slot.endpoint.localHost, SSH_TUNNEL_ENDPOINT_HOST_MAX, "%s",
           mapping.localHost.c_str());
  slot.endpoint.localPort = mapping.localPort;
  snprintf(slot.endpoint.remoteHost, SSH_TUNNEL_ENDPOINT_HOST_MAX, "%s",
           mapping.remoteBindHost.c_str());
  slot.endpoint.remotePort = mapping.remoteBindPort;
}

void ChannelManager::resetSlot(int index) {
  if (index < 0 || index >= maxSlots_) {
    return;
  }
  ChannelSlot &slot = slots_[index];
  slot.sshChannel = nullptr;
  slot.localSocket = -1;
  slot.active = false;
  slot.state = ChannelSlot::State::Closed;
  slot.localEof = false;
  slot.remoteEof = false;
  slot.closeStartMs = 0;
  slot.eofSentMs = 0;
  slot.closeReason = ChannelCloseReason::Unknown;
  slot.localReadPaused = false;
  slot.sshReadPaused = false;
  slot.totalBytesReceived = 0;
  slot.totalBytesSent = 0;
  slot.lastActivity = 0;
  slot.lastSuccessfulWrite = 0;
  slot.lastSuccessfulRead = 0;
  slot.consecutiveErrors = 0;
  slot.eagainCount = 0;
  slot.firstEagainMs = 0;
  slot.toLocal = nullptr;
  slot.toRemote = nullptr;
  slot.pendingSsh = nullptr;
  slot.pendingLocal = nullptr;
  slot.pendingSshLen = 0;
  slot.pendingSshOff = 0;
  slot.pendingLocalLen = 0;
  slot.pendingLocalOff = 0;
  memset(&slot.endpoint, 0, sizeof(slot.endpoint));
}
