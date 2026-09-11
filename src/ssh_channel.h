#ifndef SSH_CHANNEL_H
#define SSH_CHANNEL_H

#include "channel_close_progress.h"
#include "channel_lifecycle.h"
#include "circuit_breaker.h"
#include "ring_buffer.h"
#include "ssh_config.h"
#include <libssh2_esp.h>

// Reuse existing enums from the public API
enum class ChannelCloseReason {
  Unknown = 0,
  RemoteClosed,
  LocalClosed,
  Error,
  Timeout,
  Manual
};

static constexpr size_t SSH_TUNNEL_REMOTE_HOST_MAX = 64;
// SOCKS5 domain names are length-prefixed with one byte, so reserve the full
// 255-byte payload plus the terminator now rather than changing slots later.
static constexpr size_t SSH_TUNNEL_DESTINATION_HOST_MAX = 256;

struct ChannelEndpointInfo {
  char remoteHost[SSH_TUNNEL_REMOTE_HOST_MAX];
  int remotePort;
  char localHost[SSH_TUNNEL_DESTINATION_HOST_MAX];
  int localPort;
};

// Simplified channel slot (25 fields instead of 50+).
// No deferred buffers. Backpressure is handled by pausing reads when
// ring buffers are full.
struct ChannelSlot {
  LIBSSH2_CHANNEL *sshChannel = nullptr;
  int localSocket = -1;
  bool active = false;
  ChannelEndpointInfo endpoint = {};

  // Ring buffers (one per direction, allocated by ChannelManager)
  DataRingBuffer *toLocal = nullptr;  // SSH -> Local
  DataRingBuffer *toRemote = nullptr; // Local -> SSH

  // Channel state machine. Fixed tunnels start at Resolving; future SOCKS5
  // tunnels start at Negotiating and choose a destination later.
  using State = channel_lifecycle::State;
  State state = State::Closed;
  unsigned long stateStartedMs = 0;
  uint32_t resolvedIpv4 = 0; // network byte order, populated by Resolving
  bool reachedOpen = false; // preserves callback pairing on pre-open failures
  bool localEof = false;  // Local socket sent EOF / closed
  bool remoteEof = false; // SSH channel sent EOF
  bool localShutdownSent =
      false; // shutdown(SHUT_WR) issued on local socket after remote EOF
  unsigned long closeStartMs = 0;
  unsigned long eofSentMs = 0; // When SSH EOF was sent (0 = not yet sent)
  ChannelCloseReason closeReason = ChannelCloseReason::Unknown;
  channel_close_progress::Progress sshCloseProgress;

  // Backpressure flags
  bool localReadPaused =
      false;                  // Stop reading from local socket (toRemote full)
  bool sshReadPaused = false; // Stop reading from SSH channel (toLocal full)

  // Statistics
  size_t totalBytesReceived = 0;
  size_t totalBytesSent = 0;
  unsigned long lastActivity = 0;
  unsigned long lastSuccessfulWrite = 0; // Last SSH write success
  unsigned long lastSuccessfulRead = 0;  // Last SSH read success

  // Error tracking
  int consecutiveErrors = 0;
  int eagainCount = 0;
  unsigned long firstEagainMs = 0;          // SSH write EAGAIN stall start
  unsigned long firstLocalSendEagainMs = 0; // local send EAGAIN stall start

#ifdef TUNNEL_DIAG_LOG_ONLY
  bool diagRequestParsed = false;
  bool diagLocalWriteLogged = false;
  bool diagResponseLogged = false;
  bool diagNoRequestLogged = false;
  bool diagNoLocalWriteLogged = false;
  bool diagNoResponseLogged = false;
  unsigned long diagBoundMs = 0;
  unsigned long diagRequestMs = 0;
  unsigned long diagLocalWriteMs = 0;
  char diagMethod[8] = {};
  char diagUrl[160] = {};
  char diagRequestId[40] = {};
  char diagRequestBuffer[2048] = {};
  size_t diagRequestBufferLen = 0;
#endif

  // millis() at the most recent finalizeClose; 0 if never finalized.
  // Used by allocateSlot (channel_alloc::findFreeSlot) to enforce a short
  // cooldown after teardown so libssh2's channel free can settle before
  // the slot is re-bound (Bug #1 in 2026-04-28 baseline report).
  // Intentionally NOT reset by resetSlot — the cooldown must survive
  // a slot's transient lifecycle.
  unsigned long lastFinalizeMs = 0;
};

// Manages a fixed-size array of ChannelSlots.
// Handles attachment, destination resolution/connection, close state
// transitions, and iteration.
class ChannelManager {
public:
  ChannelManager();
  ~ChannelManager();

  // Allocate slot array. Call once after configuration is known.
  bool init(int maxChannels, size_t ringBufferSize);

  // Set the maximum inactivity period for open channels. Configuration
  // validation guarantees a positive value before normal use.
  void setChannelTimeout(unsigned long timeoutMs) {
    channelTimeoutMs_ = timeoutMs;
  }

  // Release all slots and free memory.
  void destroy();

  // Find a free slot. Returns index or -1 if none available.
  int allocateSlot();

  // Attach an accepted SSH channel and allocate its buffers without resolving
  // or connecting to the destination. Fixed tunnels enter Resolving; a future
  // SOCKS5 listener can defer destination selection and enter Negotiating.
  bool attachChannel(int slotIndex, LIBSSH2_CHANNEL *sshChannel,
                     const TunnelConfig &mapping,
                     bool deferDestination = false);

  // Supply the destination selected during negotiation, then start the
  // Resolving -> Connecting -> Open sequence on subsequent loop iterations.
  bool beginDestinationConnection(int slotIndex, const char *host, int port);

  // Advance one pre-open channel without taking the libssh2 session lock.
  channel_lifecycle::ConnectProgress progressConnection(int slotIndex);

  // Begin graceful close: state -> Draining.
  void beginClose(int slotIndex, ChannelCloseReason reason);

  // Finalize close: free SSH channel, close local socket, reset slot.
  // The caller must hold the session lock when calling this (for
  // libssh2_channel_free).
  // Returns false if non-blocking libssh2 close/free needs another retry.
  bool finalizeClose(int slotIndex);

  // Force-reset a slot when the SSH session is already unusable and the
  // caller cannot safely run libssh2 channel cleanup.
  void abandonSlot(int slotIndex, ChannelCloseReason reason);

  // Should we accept a new connection?
  bool shouldAcceptNew() const;

  // Accessors
  int getMaxSlots() const { return maxSlots_; }
  int getActiveCount() const { return activeCount_; }
  ChannelSlot &getSlot(int index) { return slots_[index]; }
  const ChannelSlot &getSlot(int index) const { return slots_[index]; }

  // Iterate over active slots. Callback receives slot index.
  template <typename Func> void iterateActive(Func fn) {
    for (int i = 0; i < maxSlots_; ++i) {
      if (slots_[i].active) {
        fn(i);
      }
    }
  }

  // Total stats across all channels
  size_t getTotalBytesReceived() const;
  size_t getTotalBytesSent() const;

  // Circuit breaker: returns true if the mapping identified by remoteBindPort
  // is currently in back-off due to recent local-endpoint failures.
  bool isMappingBackedOff(int remoteBindPort, unsigned long now) const {
    return breaker_.isBackedOff(remoteBindPort, now);
  }
  // Total number of CLOSED -> OPEN transitions since construction.
  unsigned long getBreakerTrips() const { return breaker_.totalTrips(); }

private:
  channel_lifecycle::ConnectProgress failConnection(int slotIndex,
                                                     const char *detail,
                                                     int errorCode,
                                                     bool recordFailure = true);
  channel_lifecycle::ConnectProgress markConnectionOpen(int slotIndex);
  void snapshotEndpoint(ChannelSlot &slot, const TunnelConfig &mapping);
  void resetSlot(int index);

  ChannelSlot *slots_ = nullptr;
  int maxSlots_ = 0;
  int activeCount_ = 0;
  size_t ringBufferSize_ = 32 * 1024; // Per ring buffer (default 32KB)
  unsigned long channelTimeoutMs_ = 1800000UL;

  CircuitBreaker breaker_;
};

#endif // SSH_CHANNEL_H
