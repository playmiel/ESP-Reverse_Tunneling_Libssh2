#ifndef SSH_CHANNEL_H
#define SSH_CHANNEL_H

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

enum class TunnelErrorCode : int {
  Unknown = 0,
  SshEagain = 1,
  SshSocketRecv = 2,
  SshSocketSend = 3,
  SshChannelClosed = 4,
  SshDecrypt = 5,
  SshReadFailure = 6,
  SshWriteFailure = 7,
  LocalSocketError = 8,
  DropLocalToSsh = 9,
  DropSshToLocal = 10,
  AllocFailure = 11
};

static constexpr size_t SSH_TUNNEL_ENDPOINT_HOST_MAX = 64;

struct ChannelEndpointInfo {
  char remoteHost[SSH_TUNNEL_ENDPOINT_HOST_MAX];
  int remotePort;
  char localHost[SSH_TUNNEL_ENDPOINT_HOST_MAX];
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

  // Channel state machine
  enum class State { Open, Draining, Closed } state = State::Closed;
  bool localEof = false;  // Local socket sent EOF / closed
  bool remoteEof = false; // SSH channel sent EOF
  unsigned long closeStartMs = 0;
  unsigned long eofSentMs = 0; // When SSH EOF was sent (0 = not yet sent)
  ChannelCloseReason closeReason = ChannelCloseReason::Unknown;

  // Backpressure flags
  bool localReadPaused = false; // Stop reading from local socket (toRemote full)
  bool sshReadPaused = false;   // Stop reading from SSH channel (toLocal full)

  // Statistics
  size_t totalBytesReceived = 0;
  size_t totalBytesSent = 0;
  unsigned long lastActivity = 0;
  unsigned long lastSuccessfulWrite = 0; // Last SSH write success
  unsigned long lastSuccessfulRead = 0;  // Last SSH read success

  // Error tracking
  int consecutiveErrors = 0;
  int eagainCount = 0;
  unsigned long firstEagainMs = 0;

  // Staging buffers: data read from ring goes here before being
  // written to SSH / local socket. Prevents data reordering when
  // writes are partial or return EAGAIN. Data is NEVER written
  // back to the ring buffer (which would put it at the wrong end).
  static constexpr size_t PENDING_BUF_SIZE = 4096;
  uint8_t *pendingSsh = nullptr;
  size_t pendingSshLen = 0;
  size_t pendingSshOff = 0;
  uint8_t *pendingLocal = nullptr;
  size_t pendingLocalLen = 0;
  size_t pendingLocalOff = 0;

  bool hasPendingSsh() const { return pendingSshLen > 0 && pendingSshOff < pendingSshLen; }
  bool hasPendingLocal() const { return pendingLocalLen > 0 && pendingLocalOff < pendingLocalLen; }
  void clearPendingSsh() { pendingSshLen = 0; pendingSshOff = 0; }
  void clearPendingLocal() { pendingLocalLen = 0; pendingLocalOff = 0; }
};

// Manages a fixed-size array of ChannelSlots.
// Handles allocation, binding (connect local socket + init ring buffers),
// close state transitions, and iteration.
class ChannelManager {
public:
  ChannelManager();
  ~ChannelManager();

  // Allocate slot array. Call once after configuration is known.
  bool init(int maxChannels, size_t ringBufferSize);

  // Release all slots and free memory.
  void destroy();

  // Find a free slot. Returns index or -1 if none available.
  int allocateSlot();

  // Bind an accepted SSH channel to a slot: connect to local endpoint,
  // create ring buffers, mark active.
  // Returns true on success.
  bool bindChannel(int slotIndex, LIBSSH2_CHANNEL *sshChannel,
                   const TunnelConfig &mapping);

  // Begin graceful close: state -> Draining.
  void beginClose(int slotIndex, ChannelCloseReason reason);

  // Finalize close: free SSH channel, close local socket, reset slot.
  // The caller must hold the session lock when calling this (for libssh2_channel_free).
  void finalizeClose(int slotIndex);

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

private:
  int connectToLocalEndpoint(const TunnelConfig &mapping);
  void snapshotEndpoint(ChannelSlot &slot, const TunnelConfig &mapping);
  void resetSlot(int index);

  ChannelSlot *slots_ = nullptr;
  int maxSlots_ = 0;
  int activeCount_ = 0;
  size_t ringBufferSize_ = 32 * 1024; // Per ring buffer (default 32KB)
};

#endif // SSH_CHANNEL_H
