#ifndef SSH_TRANSPORT_H
#define SSH_TRANSPORT_H

#include "ssh_channel.h"
#include "ssh_session.h"
#include <stddef.h>
#include <stdint.h>

#ifdef TUNNEL_INSTRUMENT
#include <libssh2.h>
// Per-channel cumulative timings around libssh2 syscalls. Microseconds.
struct InstrChannel {
  uint64_t read_us = 0;
  uint32_t read_calls = 0;
  uint32_t read_eagain = 0;
  uint32_t read_zero = 0; // EOF detections
  uint64_t read_bytes = 0;
  uint64_t write_us = 0;
  uint32_t write_calls = 0;
  uint32_t write_eagain = 0;
  uint64_t write_bytes = 0;
};
struct InstrSession {
  uint64_t lock_wait_us = 0;
  uint32_t lock_calls = 0;   // successful acquisitions
  uint32_t lock_failed = 0;  // timed-out acquisitions
  uint64_t phase1_us = 0;    // total time in pumpSshTransport
  uint32_t phase1_cycles = 0;
  uint64_t phase3_us = 0;    // total time in drainLocalToSsh
  uint32_t phase3_cycles = 0;
};
#endif

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

#ifdef TUNNEL_INSTRUMENT
  static constexpr int INSTR_MAX_CHANNELS = 8;
  // Format current cumulative instrumentation into a single line. Returns
  // bytes written (excluding NUL). Test-firmware only.
  size_t formatInstrumentation(char *out, size_t outSize) const;
#endif

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
      16384; // Max SSH write per channel per round
  static constexpr unsigned long DRAIN_TIMEOUT_MS =
      15000; // Max time in Draining state
  static constexpr unsigned long HALF_CLOSE_TIMEOUT_MS =
      5000; // Close after remote EOF + 5s idle (tolerates slow backends: DB
            // queries, external APIs). Active streams update lastActivity so
            // this only fires on truly silent channels.
  static constexpr int EAGAIN_STALL_TIMEOUT_MS =
      3000; // Max SSH-write EAGAIN duration before close (detect dead channels)
  static constexpr int LOCAL_SEND_STALL_TIMEOUT_MS =
      8000; // Max local-socket send EAGAIN duration before close (symmetric
            // stall detection for the SSH->local direction)
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

#ifdef TUNNEL_INSTRUMENT
  // Wrap libssh2_channel_read with timing + counters. slotIdx may be -1 if
  // unknown (won't be recorded).
  int instrRead(int slotIdx, LIBSSH2_CHANNEL *ch, char *buf, size_t sz);
  int instrWrite(int slotIdx, LIBSSH2_CHANNEL *ch, const char *buf, size_t sz);

  InstrChannel instrCh_[INSTR_MAX_CHANNELS];
  InstrSession instrSess_;
#endif
};

#endif // SSH_TRANSPORT_H
