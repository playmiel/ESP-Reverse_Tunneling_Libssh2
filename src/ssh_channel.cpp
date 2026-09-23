#include "ssh_channel.h"
#include "channel_inactivity.h"
#include "channel_slot_alloc.h"
#include "memory_fixes.h"
#include "network_optimizations.h"
#include <arpa/inet.h>
#include <errno.h>
#include <esp_heap_caps.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {
constexpr long LOCAL_ENDPOINT_CONNECT_TIMEOUT_MS = 2000;
}

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

  LOGF_I("SSH", "ChannelManager initialized: %d slots, 2 x %zuKB per channel",
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

  unsigned long now = millis();

  // First pass: find inactive slot, skipping any slot that is still in
  // its post-finalize cooldown window (Bug #1 guard).
  int idx = channel_alloc::findFreeSlot(slots_, maxSlots_, now);
  if (idx >= 0) {
    LOGF_D("SSH", "Channel slot %d selected (inactive)", idx);
    return idx;
  }

  // Second pass: mark an inactive channel for recycling. The same configured
  // timeout is also enforced on every pump cycle by TransportPump.
  for (int i = 0; i < maxSlots_; ++i) {
    if (slots_[i].active &&
        channel_inactivity::hasExpired(now, slots_[i].lastActivity,
                                       channelTimeoutMs_)) {
      LOGF_I("SSH", "Recycling stale channel %d", i);
      beginClose(i, ChannelCloseReason::Timeout);
      return -1; // Don't reuse immediately; let drain complete first
    }
  }

  return -1;
}

bool ChannelManager::attachChannel(int slotIndex, LIBSSH2_CHANNEL *sshChannel,
                                   const TunnelConfig &mapping,
                                   bool deferDestination) {
  if (slotIndex < 0 || slotIndex >= maxSlots_) {
    return false;
  }

  ChannelSlot &slot = slots_[slotIndex];
  if (slot.active) {
    LOGF_W("SSH", "attachChannel: slot %d already active", slotIndex);
    return false;
  }

  // Use static tag strings so the DataRingBuffer destructor can safely log.
  // DataRingBuffer stores a const char* — stack strings become dangling.
  // Pre-built tags for channels 0-7; dynamically allocated for 8+.
  static const char *const kTagsToLocal[] = {
      "ch0_toLocal", "ch1_toLocal", "ch2_toLocal", "ch3_toLocal",
      "ch4_toLocal", "ch5_toLocal", "ch6_toLocal", "ch7_toLocal"};
  static const char *const kTagsToRemote[] = {
      "ch0_toRemote", "ch1_toRemote", "ch2_toRemote", "ch3_toRemote",
      "ch4_toRemote", "ch5_toRemote", "ch6_toRemote", "ch7_toRemote"};
  // For channels >= 8, allocate persistent tag strings (leaked intentionally
  // — they live for the process lifetime and are reused across bind cycles).
  static char extraTagsL[24][16]; // supports up to channel 31
  static char extraTagsR[24][16];
  const char *tagL;
  const char *tagR;
  if (slotIndex < 8) {
    tagL = kTagsToLocal[slotIndex];
    tagR = kTagsToRemote[slotIndex];
  } else {
    int idx = slotIndex - 8;
    if (idx >= 24)
      idx = 23; // cap at ch31
    snprintf(extraTagsL[idx], sizeof(extraTagsL[idx]), "ch%d_toLocal",
             slotIndex);
    snprintf(extraTagsR[idx], sizeof(extraTagsR[idx]), "ch%d_toRemote",
             slotIndex);
    tagL = extraTagsL[idx];
    tagR = extraTagsR[idx];
  }

  // Heap guard: verify enough memory before allocating ring buffers.
  // Check PSRAM if available, otherwise check internal heap.
  {
    size_t required =
        ringBufferSize_ * 2 + 32768; // 2 rings + structs + prepend
    size_t freePsram = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM);
    if (freePsram > 0) {
      // Board has PSRAM — check PSRAM availability
      if (freePsram < required) {
        LOGF_E("SSH",
               "Not enough PSRAM for channel %d: need %zu, largest free %zu",
               slotIndex, required, freePsram);
        return false;
      }
    } else {
      // No PSRAM — check internal heap (fallback path)
      size_t freeInternal = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
      if (freeInternal < required) {
        LOGF_E("SSH",
               "Not enough heap for channel %d: need %zu, largest free %zu",
               slotIndex, required, freeInternal);
        return false;
      }
    }
  }

  DataRingBuffer *toLocal = new DataRingBuffer(ringBufferSize_, tagL);
  DataRingBuffer *toRemote = new DataRingBuffer(ringBufferSize_, tagR);

  if (!toLocal || !toRemote || toLocal->capacityBytes() == 0 ||
      toRemote->capacityBytes() == 0) {
    LOG_E("SSH", "Failed to allocate ring buffers for channel");
    delete toLocal;
    delete toRemote;
    return false;
  }

  // Initialize slot
  resetSlot(slotIndex);
  slot.sshChannel = sshChannel;
  slot.active = true;
  slot.state = deferDestination ? ChannelSlot::State::Negotiating
                                : ChannelSlot::State::Resolving;
  slot.toLocal = toLocal;
  slot.toRemote = toRemote;
  slot.lastActivity = millis();
  slot.stateStartedMs = slot.lastActivity;
  slot.lastSuccessfulWrite = slot.lastActivity;
  slot.lastSuccessfulRead = slot.lastActivity;
  snapshotEndpoint(slot, mapping);
  slot.isSocks5 = mapping.isSocks5();
  if (deferDestination) {
    slot.endpoint.localHost[0] = '\0';
    slot.endpoint.localPort = 0;
  }

  activeCount_++;
  LOGF_I("SSH", "Channel %d attached: remote=%s:%d state=%d (active: %d/%d)",
         slotIndex, slot.endpoint.remoteHost, slot.endpoint.remotePort,
         static_cast<int>(slot.state), activeCount_, maxSlots_);
  return true;
}

bool ChannelManager::beginDestinationConnection(int slotIndex,
                                                const char *host, int port) {
  if (slotIndex < 0 || slotIndex >= maxSlots_ || !host || host[0] == '\0' ||
      port < 1 || port > 65535) {
    return false;
  }

  ChannelSlot &slot = slots_[slotIndex];
  if (!slot.active || slot.state != ChannelSlot::State::Negotiating ||
      slot.localSocket >= 0) {
    return false;
  }

  size_t hostLen = strnlen(host, SSH_TUNNEL_DESTINATION_HOST_MAX);
  if (hostLen == 0 || hostLen >= SSH_TUNNEL_DESTINATION_HOST_MAX) {
    return false;
  }
  memcpy(slot.endpoint.localHost, host, hostLen);
  slot.endpoint.localHost[hostLen] = '\0';
  slot.endpoint.localPort = port;
  slot.resolvedIpv4 = 0;
  slot.state = ChannelSlot::State::Resolving;
  slot.stateStartedMs = millis();
  slot.lastActivity = slot.stateStartedMs;
  return true;
}

channel_lifecycle::ConnectProgress
ChannelManager::failConnection(int slotIndex, const char *detail,
                               int errorCode, bool recordFailure,
                               bool dnsFailure) {
  ChannelSlot &slot = slots_[slotIndex];
  slot.destinationError = errorCode;
  slot.destinationDnsFailure = dnsFailure;
  if (slot.localSocket >= 0) {
    close(slot.localSocket);
    slot.localSocket = -1;
  }

  LOGF_E("SSH", "Channel %d: destination %s:%d failed during %s (err=%d)",
         slotIndex, slot.endpoint.localHost, slot.endpoint.localPort,
         detail ? detail : "connection", errorCode);

  if (recordFailure && !slot.isSocks5) {
    unsigned long now = millis();
    if (breaker_.recordFailure(slot.endpoint.remotePort, now)) {
      const auto *health = breaker_.peek(slot.endpoint.remotePort);
      if (health) {
        unsigned long delay = health->backoffUntilMs - now;
        LOGF_W("SSH",
               "Mapping port %d: %u consecutive destination failures, "
               "back-off %lums",
               slot.endpoint.remotePort, health->consecutiveFails, delay);
      }
    }
  }

  // No destination exists to drain these bytes into. Discard them so the
  // channel can complete its SSH close instead of waiting for drain timeout.
  if (slot.toLocal) {
    slot.toLocal->clear();
  }
  if (slot.toRemote && !slot.isSocks5) {
    slot.toRemote->clear();
  }
  beginClose(slotIndex, ChannelCloseReason::Error);
  return channel_lifecycle::ConnectProgress::Failed;
}

channel_lifecycle::ConnectProgress
ChannelManager::markConnectionOpen(int slotIndex) {
  ChannelSlot &slot = slots_[slotIndex];
  if (!NetworkOptimizer::optimizeSocket(slot.localSocket)) {
    LOG_W("SSH", "Failed to optimize destination socket");
  }

  if (!slot.isSocks5) {
    const auto *health = breaker_.peek(slot.endpoint.remotePort);
    if (health &&
        (health->consecutiveFails > 0 || health->backoffUntilMs > 0)) {
      LOGF_I("SSH", "Mapping port %d: recovered after %u failures",
             slot.endpoint.remotePort, health->consecutiveFails);
    }
    breaker_.recordSuccess(slot.endpoint.remotePort);
  }

  slot.state = ChannelSlot::State::Open;
  slot.reachedOpen = true;
  slot.stateStartedMs = millis();
  slot.lastActivity = slot.stateStartedMs;
  slot.lastSuccessfulWrite = slot.lastActivity;
  slot.lastSuccessfulRead = slot.lastActivity;
  LOGF_I("SSH", "Channel %d open: %s:%d -> %s:%d", slotIndex,
         slot.endpoint.remoteHost, slot.endpoint.remotePort,
         slot.endpoint.localHost, slot.endpoint.localPort);
#ifdef TUNNEL_DIAG_LOG_ONLY
  slot.diagBoundMs = slot.lastActivity;
  LOGF_I("SSH", "HTTPDIAG ch=%d bound remote=%s:%d local=%s:%d active=%d/%d",
         slotIndex, slot.endpoint.remoteHost, slot.endpoint.remotePort,
         slot.endpoint.localHost, slot.endpoint.localPort, activeCount_,
         maxSlots_);
#endif
  return channel_lifecycle::ConnectProgress::Opened;
}

channel_lifecycle::ConnectProgress
ChannelManager::progressConnection(int slotIndex) {
  if (slotIndex < 0 || slotIndex >= maxSlots_) {
    return channel_lifecycle::ConnectProgress::None;
  }
  ChannelSlot &slot = slots_[slotIndex];
  if (!slot.active || (slot.state != ChannelSlot::State::Resolving &&
                       slot.state != ChannelSlot::State::Connecting)) {
    return channel_lifecycle::ConnectProgress::None;
  }
  if (slot.state == ChannelSlot::State::Resolving) {
    struct in_addr ipv4;
    memset(&ipv4, 0, sizeof(ipv4));
    if (inet_pton(AF_INET, slot.endpoint.localHost, &ipv4) != 1) {
      // getaddrinfo may block while DNS is in flight, but it deliberately runs
      // outside the libssh2 session lock. A later SOCKS5 resolver can replace
      // this step with an asynchronous worker without changing channel states.
      struct addrinfo hints;
      memset(&hints, 0, sizeof(hints));
      hints.ai_family = AF_INET;
      hints.ai_socktype = SOCK_STREAM;
      struct addrinfo *result = nullptr;
      int dnsResult = getaddrinfo(slot.endpoint.localHost, nullptr, &hints,
                                  &result);
      if (dnsResult != 0 || !result || !result->ai_addr) {
        if (result) {
          freeaddrinfo(result);
        }
        return failConnection(slotIndex, "DNS resolution", dnsResult, true,
                              true);
      }
      ipv4 = reinterpret_cast<struct sockaddr_in *>(result->ai_addr)->sin_addr;
      freeaddrinfo(result);
    }
    slot.resolvedIpv4 = ipv4.s_addr;
    slot.state = ChannelSlot::State::Connecting;
    slot.stateStartedMs = millis();
  }

  if (slot.localSocket < 0) {
    slot.localSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (slot.localSocket < 0) {
      return failConnection(slotIndex, "socket creation", errno);
    }
    int flags = fcntl(slot.localSocket, F_GETFL, 0);
    if (flags < 0 ||
        fcntl(slot.localSocket, F_SETFL, flags | O_NONBLOCK) < 0) {
      return failConnection(slotIndex, "non-blocking setup", errno);
    }

    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(slot.endpoint.localPort);
    address.sin_addr.s_addr = slot.resolvedIpv4;
    int rc = ::connect(slot.localSocket,
                       reinterpret_cast<struct sockaddr *>(&address),
                       sizeof(address));
    if (rc == 0 || (rc < 0 && errno == EISCONN)) {
      return markConnectionOpen(slotIndex);
    }
    if (errno != EINPROGRESS && errno != EALREADY && errno != EWOULDBLOCK) {
      return failConnection(slotIndex, "connect", errno);
    }
  }

  fd_set writeFds;
  fd_set errorFds;
  FD_ZERO(&writeFds);
  FD_ZERO(&errorFds);
  FD_SET(slot.localSocket, &writeFds);
  FD_SET(slot.localSocket, &errorFds);
  struct timeval noWait = {0, 0};
  int selected = select(slot.localSocket + 1, nullptr, &writeFds, &errorFds,
                        &noWait);
  if (selected < 0) {
    return failConnection(slotIndex, "connect poll", errno);
  }
  if (selected > 0 && (FD_ISSET(slot.localSocket, &writeFds) ||
                       FD_ISSET(slot.localSocket, &errorFds))) {
    int socketError = 0;
    socklen_t errorLength = sizeof(socketError);
    if (getsockopt(slot.localSocket, SOL_SOCKET, SO_ERROR, &socketError,
                   &errorLength) != 0) {
      return failConnection(slotIndex, "connect status", errno);
    }
    if (socketError != 0) {
      return failConnection(slotIndex, "connect", socketError);
    }
    return markConnectionOpen(slotIndex);
  }

  unsigned long now = millis();
  if (channel_lifecycle::connectTimedOut(
          now, slot.stateStartedMs, LOCAL_ENDPOINT_CONNECT_TIMEOUT_MS)) {
    return failConnection(slotIndex, "connect timeout", ETIMEDOUT);
  }
  return channel_lifecycle::ConnectProgress::Pending;
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
  LOGF_I("SSH",
         "Channel %d: begin close (reason=%d, toLocal=%zu, toRemote=%zu)",
         slotIndex, static_cast<int>(reason),
         slot.toLocal ? slot.toLocal->size() : 0,
         slot.toRemote ? slot.toRemote->size() : 0);
}

bool ChannelManager::finalizeClose(int slotIndex) {
  if (slotIndex < 0 || slotIndex >= maxSlots_) {
    return true;
  }
  ChannelSlot &slot = slots_[slotIndex];
  if (!slot.active) {
    return true;
  }

  LOGF_I("SSH", "Channel %d: finalize close (sent=%zu, recv=%zu, reason=%d)",
         slotIndex, slot.totalBytesSent, slot.totalBytesReceived,
         static_cast<int>(slot.closeReason));

  // Free SSH channel (caller must hold session lock)
  if (slot.sshChannel) {
    if (!slot.sshCloseProgress.closeComplete) {
      int closeRc = libssh2_channel_close(slot.sshChannel);
      if (!channel_close_progress::recordCloseResult(
              slot.sshCloseProgress, closeRc, LIBSSH2_ERROR_EAGAIN)) {
        LOGF_D("SSH", "Channel %d: SSH close EAGAIN, retrying", slotIndex);
        return false;
      }
      if (closeRc != 0) {
        LOGF_W("SSH", "Channel %d: SSH close returned %d, continuing cleanup",
               slotIndex, closeRc);
      }
    }

    if (channel_close_progress::readyForFree(slot.sshCloseProgress)) {
      int freeRc = libssh2_channel_free(slot.sshChannel);
      if (!channel_close_progress::recordFreeResult(
              slot.sshCloseProgress, freeRc, LIBSSH2_ERROR_EAGAIN)) {
        LOGF_D("SSH", "Channel %d: SSH free EAGAIN, retrying", slotIndex);
        return false;
      }
      if (freeRc != 0) {
        LOGF_W("SSH", "Channel %d: SSH free returned %d, dropping local slot",
               slotIndex, freeRc);
      }
    }

    if (!channel_close_progress::readyForFinalize(slot.sshCloseProgress)) {
      return false;
    }
    slot.sshChannel = nullptr;
  }

  // Close local socket
  if (slot.localSocket >= 0) {
    close(slot.localSocket);
    slot.localSocket = -1;
  }

  // Free ring buffers
  delete slot.toLocal;
  slot.toLocal = nullptr;
  delete slot.toRemote;
  slot.toRemote = nullptr;

  slot.active = false;
  slot.state = ChannelSlot::State::Closed;
  // Stamp the finalize time so allocateSlot's cooldown can guard against
  // immediate re-bind racing libssh2's channel teardown.
  slot.lastFinalizeMs = millis();
  activeCount_--;

  LOGF_I("SSH", "Channel %d closed (active: %d/%d)", slotIndex, activeCount_,
         maxSlots_);
  return true;
}

void ChannelManager::abandonSlot(int slotIndex, ChannelCloseReason reason) {
  if (slotIndex < 0 || slotIndex >= maxSlots_) {
    return;
  }
  ChannelSlot &slot = slots_[slotIndex];
  if (!slot.active) {
    return;
  }

  LOGF_W("SSH",
         "Channel %d: abandoning slot without libssh2 cleanup (reason=%d)",
         slotIndex, static_cast<int>(reason));

  if (slot.localSocket >= 0) {
    close(slot.localSocket);
    slot.localSocket = -1;
  }

  delete slot.toLocal;
  slot.toLocal = nullptr;
  delete slot.toRemote;
  slot.toRemote = nullptr;

  slot.sshChannel = nullptr;
  if (activeCount_ > 0) {
    activeCount_--;
  }
  resetSlot(slotIndex);
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

void ChannelManager::snapshotEndpoint(ChannelSlot &slot,
                                      const TunnelConfig &mapping) {
  snprintf(slot.endpoint.localHost, SSH_TUNNEL_DESTINATION_HOST_MAX, "%s",
           mapping.localHost.c_str());
  slot.endpoint.localPort = mapping.localPort;
  snprintf(slot.endpoint.remoteHost, SSH_TUNNEL_REMOTE_HOST_MAX, "%s",
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
  slot.stateStartedMs = 0;
  slot.resolvedIpv4 = 0;
  slot.isSocks5 = false;
  slot.socks5Negotiator.reset();
  slot.destinationError = 0;
  slot.destinationDnsFailure = false;
  slot.reachedOpen = false;
  slot.localEof = false;
  slot.remoteEof = false;
  slot.localShutdownSent = false;
  slot.closeStartMs = 0;
  slot.eofSentMs = 0;
  slot.closeReason = ChannelCloseReason::Unknown;
  slot.sshCloseProgress = channel_close_progress::Progress();
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
  slot.firstLocalSendEagainMs = 0;
  slot.toLocal = nullptr;
  slot.toRemote = nullptr;
  memset(&slot.endpoint, 0, sizeof(slot.endpoint));
#ifdef TUNNEL_DIAG_LOG_ONLY
  slot.diagRequestParsed = false;
  slot.diagLocalWriteLogged = false;
  slot.diagResponseLogged = false;
  slot.diagNoRequestLogged = false;
  slot.diagNoLocalWriteLogged = false;
  slot.diagNoResponseLogged = false;
  slot.diagBoundMs = 0;
  slot.diagRequestMs = 0;
  slot.diagLocalWriteMs = 0;
  slot.diagRequestBufferLen = 0;
  memset(slot.diagMethod, 0, sizeof(slot.diagMethod));
  memset(slot.diagUrl, 0, sizeof(slot.diagUrl));
  memset(slot.diagRequestId, 0, sizeof(slot.diagRequestId));
  memset(slot.diagRequestBuffer, 0, sizeof(slot.diagRequestBuffer));
#endif
}

// Circuit breaker logic now lives in src/circuit_breaker.h and is composed
// as the breaker_ member. Public isMappingBackedOff()/getBreakerTrips()
// forwarders are inline in the header.
