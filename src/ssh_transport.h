#ifndef SSH_TRANSPORT_H
#define SSH_TRANSPORT_H

#include "ssh_channel.h"
#include "ssh_session.h"
#include <stddef.h>
#include <stdint.h>

// TransportPump: the single data movement engine.
// Called once per loop() iteration. Handles all SSH <-> Local data flow
// using round-robin fair scheduling across channels.
//
// 4-phase pump cycle:
//   Phase 1: pumpSshTransport()  - Read SSH data into toLocal rings (processes
//   WINDOW_ADJUST) Phase 2: drainSshToLocal()   - Send toLocal ring data to
//   local sockets Phase 3: drainLocalToSsh()   - Read local sockets + write
//   toRemote rings to SSH Phase 4: checkCloses()       - Finalize channels
//   whose rings are empty or timed out
class TransportPump {
public:
  TransportPump();
  ~TransportPump();

  // Allocate working buffers. Call once.
  bool init(size_t bufferSize = 4096);

  // Set references to session and channel manager.
  void attach(SSHSession *session, ChannelManager *channels);

  // Execute one full pump cycle. Returns true if any data was moved.
  bool pumpAll();

  // Returns true if any channel has backpressure active.
  bool hasAnyBackpressure() const;

  // Per-pump stats (reset each pumpAll call)
  size_t lastBytesMoved() const { return lastBytesMoved_; }

  // Close events recorded during pumpAll() for the caller to emit callbacks.
  // Filled by checkCloses(), consumed by the caller after pumpAll() returns.
  struct CloseEvent {
    int slot;
    ChannelCloseReason reason;
  };
  static constexpr int MAX_CLOSE_EVENTS = 32;
  int consumeCloseEvents(CloseEvent *out, int maxEvents);

private:
  // Phase 1: Read from SSH channels into toLocal ring buffers.
  // Also implicitly processes WINDOW_ADJUST packets inside libssh2.
  void pumpSshTransport();

  // Phase 2: Drain toLocal rings -> local sockets (round-robin).
  void drainSshToLocal();

  // Phase 3: Read local sockets -> toRemote rings, then drain toRemote -> SSH
  // (round-robin).
  void drainLocalToSsh();

  // Phase 4: Check channels in Draining state for completion.
  void checkCloses();

  // Backpressure thresholds (fraction of ring buffer capacity)
  static constexpr int BACKPRESSURE_HIGH_PCT = 75; // Pause reads above 75%
  static constexpr int BACKPRESSURE_LOW_PCT = 25;  // Resume reads below 25%
  static constexpr size_t MAX_WRITE_PER_CHANNEL =
      4096; // Max SSH write per channel per round
  static constexpr unsigned long DRAIN_TIMEOUT_MS =
      15000; // Max time in Draining state
  static constexpr unsigned long HALF_CLOSE_TIMEOUT_MS =
      10000; // Close after remote EOF + 10s idle
  static constexpr int EAGAIN_STALL_TIMEOUT_MS =
      30000; // Max EAGAIN duration before close
  static constexpr unsigned long EOF_GRACE_MS =
      200; // Wait after SSH EOF sent before closing

  SSHSession *session_ = nullptr;
  ChannelManager *channels_ = nullptr;

  uint8_t *rxBuf_ = nullptr; // Shared read buffer
  uint8_t *txBuf_ = nullptr; // Shared write buffer
  size_t bufSize_ = 0;

  unsigned int roundRobinOffset_ = 0;
  size_t lastBytesMoved_ = 0;

  // Pending close events (filled by checkCloses, drained by consumeCloseEvents)
  CloseEvent pendingCloseEvents_[MAX_CLOSE_EVENTS];
  int pendingCloseCount_ = 0;
};

#endif // SSH_TRANSPORT_H
