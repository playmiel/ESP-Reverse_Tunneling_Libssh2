#include "ssh_transport.h"
#include "memory_fixes.h"
#include <errno.h>
#include <sys/socket.h>

// ---------------------------------------------------------------------------
// TransportPump
// ---------------------------------------------------------------------------

TransportPump::TransportPump() {}

TransportPump::~TransportPump() {
  SAFE_FREE(rxBuf_);
  SAFE_FREE(txBuf_);
}

bool TransportPump::init(size_t bufferSize) {
  bufSize_ = bufferSize;
  rxBuf_ = static_cast<uint8_t *>(safeMalloc(bufSize_, "tp_rxBuf"));
  txBuf_ = static_cast<uint8_t *>(safeMalloc(bufSize_, "tp_txBuf"));
  if (!rxBuf_ || !txBuf_) {
    LOG_E("SSH", "TransportPump: failed to allocate buffers");
    SAFE_FREE(rxBuf_);
    SAFE_FREE(txBuf_);
    return false;
  }
  LOGF_I("SSH", "TransportPump initialized: %zuB buffers", bufSize_);
  return true;
}

void TransportPump::attach(SSHSession *session, ChannelManager *channels) {
  session_ = session;
  channels_ = channels;
}

bool TransportPump::pumpAll() {
  if (!session_ || !channels_ || !rxBuf_ || !txBuf_) {
    return false;
  }
  lastBytesMoved_ = 0;

  // Phase 1: Read SSH -> toLocal rings (processes WINDOW_ADJUST implicitly)
  pumpSshTransport();

  // Phase 2: toLocal rings -> local sockets
  drainSshToLocal();

  // Phase 3: local sockets -> toRemote rings -> SSH
  drainLocalToSsh();

  // Phase 4: transition Open channels to Draining when both EOFs set,
  //          then finalize Draining channels whose rings are empty.
  checkCloses();

  return lastBytesMoved_ > 0;
}

bool TransportPump::hasAnyBackpressure() const {
  if (!channels_) {
    return false;
  }
  int max = channels_->getMaxSlots();
  for (int i = 0; i < max; ++i) {
    const ChannelSlot &ch = channels_->getSlot(i);
    if (ch.active && (ch.localReadPaused || ch.sshReadPaused)) {
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Phase 1: Pump SSH transport
// Read from each SSH channel into toLocal ring. This implicitly triggers
// libssh2 to process incoming SSH packets including WINDOW_ADJUST.
// MUST run before any writes to ensure channels have fresh window credit.
//
// IMPORTANT: remote EOF does NOT trigger close. It just sets the flag.
// The channel stays open to let the local side finish sending its response.
// ---------------------------------------------------------------------------
void TransportPump::pumpSshTransport() {
  if (!session_->lock(pdMS_TO_TICKS(50))) {
    return;
  }

  int maxSlots = channels_->getMaxSlots();
  bool anyReadDone = false;

  for (int i = 0; i < maxSlots; ++i) {
    ChannelSlot &ch = channels_->getSlot(i);
    if (!ch.active || !ch.sshChannel) {
      continue;
    }

    // Channels with remoteEof: still need ONE read to pump SSH transport
    // (processes WINDOW_ADJUST for OTHER channels' writes).
    // But don't try to store data — just pump and move on.
    if (ch.remoteEof) {
      char pumpBuf[64];
      libssh2_channel_read(ch.sshChannel, pumpBuf, sizeof(pumpBuf));
      anyReadDone = true;
      continue;
    }

    // Skip if toLocal ring is paused (too full)
    if (ch.sshReadPaused) {
      if (ch.toLocal && ch.toLocal->size() <
              ch.toLocal->capacityBytes() * BACKPRESSURE_LOW_PCT / 100) {
        ch.sshReadPaused = false;
        LOGF_D("SSH", "Channel %d: SSH read resumed (toLocal=%zu)", i,
               ch.toLocal->size());
      } else {
        // Still do a transport pump read even when paused
        char pumpBuf[64];
        libssh2_channel_read(ch.sshChannel, pumpBuf, sizeof(pumpBuf));
        anyReadDone = true;
        continue;
      }
    }

    if (!ch.toLocal) {
      continue;
    }

    // Read up to 4 chunks from SSH channel
    for (int attempt = 0; attempt < 4; attempt++) {
      size_t freeSpace = ch.toLocal->available();
      if (freeSpace == 0) {
        ch.sshReadPaused = true;
        break;
      }
      size_t readSize = freeSpace < bufSize_ ? freeSpace : bufSize_;
      int rc = libssh2_channel_read(ch.sshChannel, (char *)rxBuf_, readSize);
      anyReadDone = true;

      if (rc > 0) {
        size_t written = ch.toLocal->write(rxBuf_, rc);
        ch.totalBytesReceived += written;
        lastBytesMoved_ += written;
        ch.lastSuccessfulRead = millis();
        ch.lastActivity = ch.lastSuccessfulRead;
        ch.eagainCount = 0;
        ch.firstEagainMs = 0;
        ch.consecutiveErrors = 0;

        // Check backpressure
        if (ch.toLocal->size() >
            ch.toLocal->capacityBytes() * BACKPRESSURE_HIGH_PCT / 100) {
          ch.sshReadPaused = true;
          break;
        }
      } else if (rc == LIBSSH2_ERROR_EAGAIN) {
        break;
      } else if (rc == 0) {
        // EOF from remote — just set the flag, do NOT close
        ch.remoteEof = true;
        LOGF_I("SSH", "Channel %d: remote EOF", i);
        break;
      } else {
        // Error
        ch.consecutiveErrors++;
        LOGF_W("SSH", "Channel %d: SSH read error %d (errors=%d)", i, rc,
               ch.consecutiveErrors);
        if (ch.consecutiveErrors > 3 &&
            ch.state == ChannelSlot::State::Open) {
          channels_->beginClose(i, ChannelCloseReason::Error);
        }
        break;
      }
    }

    // Check for SSH channel EOF flag (in case libssh2 sets it without returning 0)
    if (!ch.remoteEof && ch.sshChannel &&
        libssh2_channel_eof(ch.sshChannel)) {
      ch.remoteEof = true;
      LOGF_I("SSH", "Channel %d: remote EOF (eof flag)", i);
    }
  }

  session_->unlock();
}

// ---------------------------------------------------------------------------
// Phase 2: Drain toLocal rings -> local sockets (round-robin)
// Uses DataRingBuffer::writeToFront() to preserve FIFO order on partial sends.
// Data goes: ring.read() -> send(). Unsent remainder -> ring.writeToFront().
// ---------------------------------------------------------------------------
void TransportPump::drainSshToLocal() {
  int maxSlots = channels_->getMaxSlots();
  if (maxSlots == 0) {
    return;
  }

  for (int n = 0; n < maxSlots; ++n) {
    int i = (n + roundRobinOffset_) % maxSlots;
    ChannelSlot &ch = channels_->getSlot(i);
    if (!ch.active || ch.localSocket < 0 || !ch.toLocal) {
      continue;
    }

    if (ch.toLocal->empty()) {
      continue;
    }

    size_t available = ch.toLocal->size();
    size_t toDrain = available < bufSize_ ? available : bufSize_;

    size_t got = ch.toLocal->read(txBuf_, toDrain);
    if (got == 0) {
      continue;
    }

    ssize_t sent = send(ch.localSocket, txBuf_, got, MSG_DONTWAIT);
    if (sent > 0) {
      lastBytesMoved_ += sent;
      ch.lastActivity = millis();
      if (static_cast<size_t>(sent) < got) {
        // Partial send: put unsent data back at the front of the ring
        ch.toLocal->writeToFront(txBuf_ + sent, got - sent);
      }
    } else if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
      ch.localEof = true;
      LOGF_W("SSH", "Channel %d: local send error %d (%s)", i, errno,
             strerror(errno));
    } else {
      // EAGAIN/EWOULDBLOCK: put ALL data back at the front
      ch.toLocal->writeToFront(txBuf_, got);
    }
  }
}

// ---------------------------------------------------------------------------
// Phase 3: Local sockets -> toRemote rings -> SSH channel (round-robin)
// Single session lock for all channels, budget per channel.
//
// IMPORTANT: We keep reading from local socket even when remoteEof is set
// (Draining or not), because in HTTP reverse tunnel the remote sends EOF
// after the request, but the local web server is still sending the response.
// ---------------------------------------------------------------------------
void TransportPump::drainLocalToSsh() {
  int maxSlots = channels_->getMaxSlots();
  if (maxSlots == 0) {
    return;
  }

  if (!session_->lock(pdMS_TO_TICKS(50))) {
    return;
  }

  for (int n = 0; n < maxSlots; ++n) {
    int i = (n + roundRobinOffset_) % maxSlots;
    ChannelSlot &ch = channels_->getSlot(i);
    if (!ch.active || !ch.sshChannel) {
      continue;
    }

    // --- Step A: Drain toRemote -> SSH using writeToFront() for partial writes ---
    // Data goes: ring.read() -> SSH write. Unsent remainder -> ring.writeToFront().
    if (ch.toRemote) {
      size_t budget = MAX_WRITE_PER_CHANNEL;
      bool hitEagain = false;

      while (budget > 0 && !ch.toRemote->empty() && !hitEagain) {
        size_t chunkSize = budget < bufSize_ ? budget : bufSize_;
        size_t got = ch.toRemote->read(txBuf_, chunkSize);
        if (got == 0) break;

        ssize_t written = libssh2_channel_write(ch.sshChannel,
                                                 (char *)txBuf_, got);
        if (written > 0) {
          ch.totalBytesSent += written;
          lastBytesMoved_ += written;
          budget -= written;
          ch.lastSuccessfulWrite = millis();
          ch.lastActivity = ch.lastSuccessfulWrite;
          ch.eagainCount = 0;
          ch.firstEagainMs = 0;
          ch.consecutiveErrors = 0;
          if (static_cast<size_t>(written) < got) {
            // Partial write: put unsent data back at the front
            ch.toRemote->writeToFront(txBuf_ + written, got - written);
            break;
          }
        } else if (written == LIBSSH2_ERROR_EAGAIN) {
          // Put ALL data back at the front of the ring
          ch.toRemote->writeToFront(txBuf_, got);
          ch.eagainCount++;
          if (ch.firstEagainMs == 0) ch.firstEagainMs = millis();
          hitEagain = true;
        } else {
          ch.consecutiveErrors++;
          LOGF_W("SSH", "Channel %d: SSH write error %ld (errors=%d)", i,
                 (long)written, ch.consecutiveErrors);
          break;
        }
      }

      // Check EAGAIN stall timeout
      if (ch.firstEagainMs > 0 &&
          (millis() - ch.firstEagainMs) >
              static_cast<unsigned long>(EAGAIN_STALL_TIMEOUT_MS)) {
        LOGF_W("SSH", "Channel %d: EAGAIN stall timeout (%dms, toRemote=%zu)",
               i, EAGAIN_STALL_TIMEOUT_MS, ch.toRemote->size());
        if (ch.state == ChannelSlot::State::Open) {
          channels_->beginClose(i, ChannelCloseReason::Error);
        }
        ch.firstEagainMs = millis();
      }
    }

    // Check backpressure on toRemote
    if (ch.toRemote) {
      size_t used = ch.toRemote->size();
      size_t cap = ch.toRemote->capacityBytes();
      if (ch.localReadPaused) {
        if (used < cap * BACKPRESSURE_LOW_PCT / 100) {
          ch.localReadPaused = false;
          LOGF_D("SSH", "Channel %d: local read resumed (toRemote=%zu)", i,
                 used);
        }
      } else if (used > cap * BACKPRESSURE_HIGH_PCT / 100) {
        ch.localReadPaused = true;
        LOGF_D("SSH", "Channel %d: local read paused (toRemote=%zu)", i,
               used);
      }
    }

    // --- Step B: Read from local socket -> toRemote ring ---
    // Continue reading even when remoteEof is set or state is Draining.
    // The local web server may still be sending the HTTP response.
    if (!ch.localEof && !ch.localReadPaused && ch.localSocket >= 0 &&
        ch.toRemote) {
      size_t freeSpace = ch.toRemote->available();
      if (freeSpace > 0) {
        size_t readSize = freeSpace < bufSize_ ? freeSpace : bufSize_;
        ssize_t recvd = recv(ch.localSocket, rxBuf_, readSize, MSG_DONTWAIT);
        if (recvd > 0) {
          ch.toRemote->write(rxBuf_, recvd);
          ch.lastActivity = millis();
          lastBytesMoved_ += recvd;
        } else if (recvd == 0) {
          // Local socket closed — the response is fully sent
          ch.localEof = true;
          LOGF_I("SSH", "Channel %d: local EOF", i);
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
          ch.localEof = true;
          LOGF_W("SSH", "Channel %d: local recv error %d (%s)", i, errno,
                 strerror(errno));
        }
      }
    }
  }

  session_->unlock();
  roundRobinOffset_++;
}

// ---------------------------------------------------------------------------
// Phase 4: Check channel close transitions
//
// State machine:
//   Open -> Draining: when BOTH remoteEof AND localEof are set,
//                     or on consecutive errors, or on inactivity timeout.
//   Draining (rings not empty): keep draining, wait for empty.
//   Draining (rings empty, EOF not sent): send SSH EOF + pump transport.
//   Draining (rings empty, EOF sent, 200ms passed): finalize close.
//
// The 200ms grace period after EOF lets libssh2 flush any internal buffers
// to the TCP socket, preventing truncated HTTP responses.
// ---------------------------------------------------------------------------
void TransportPump::checkCloses() {
  int maxSlots = channels_->getMaxSlots();
  unsigned long now = millis();

  // --- Step 1: Transition Open channels to Draining when appropriate ---
  for (int i = 0; i < maxSlots; ++i) {
    ChannelSlot &ch = channels_->getSlot(i);
    if (!ch.active || ch.state != ChannelSlot::State::Open) {
      continue;
    }

    // Both sides done → begin graceful drain
    if (ch.remoteEof && ch.localEof) {
      channels_->beginClose(i, ChannelCloseReason::RemoteClosed);
      continue;
    }

    // Consecutive errors on an open channel
    if (ch.consecutiveErrors > 5) {
      channels_->beginClose(i, ChannelCloseReason::Error);
      continue;
    }

    // Half-closed timeout: remote EOF received but local hasn't closed.
    // For HTTP: the request is done, and if the local web server hasn't
    // sent any data for 3 seconds, the response is likely complete
    // (keep-alive connection staying open). Close proactively.
    if (ch.remoteEof && !ch.localEof && ch.lastActivity > 0 &&
        (now - ch.lastActivity) > HALF_CLOSE_TIMEOUT_MS) {
      bool toRemoteEmpty = !ch.toRemote || ch.toRemote->empty();
      if (toRemoteEmpty) {
        LOGF_I("SSH",
               "Channel %d: half-close timeout (remote EOF, no local data for "
               "%lums)",
               i, now - ch.lastActivity);
        channels_->beginClose(i, ChannelCloseReason::RemoteClosed);
        continue;
      }
    }

    // Full inactivity timeout (30 seconds with no data movement)
    if (ch.lastActivity > 0 && (now - ch.lastActivity) > 30000) {
      LOGF_W("SSH", "Channel %d: inactivity timeout (%lums)", i,
             now - ch.lastActivity);
      channels_->beginClose(i, ChannelCloseReason::Timeout);
      continue;
    }
  }

  // --- Step 2: Handle Draining channels ---
  // Two sub-phases:
  //   a) Rings empty but EOF not sent → send EOF + pump transport
  //   b) EOF sent and grace period elapsed → finalize
  // Recapture now — Step 1 may have called beginClose() which sets
  // closeStartMs = millis(). Using the old `now` would cause unsigned
  // underflow (now - closeStartMs wraps to UINT_MAX → instant timeout).
  now = millis();
  int toSendEof[16];
  int eofCount = 0;
  int toClose[16];
  int closeCount = 0;

  for (int i = 0; i < maxSlots; ++i) {
    ChannelSlot &ch = channels_->getSlot(i);
    if (!ch.active || ch.state != ChannelSlot::State::Draining) {
      continue;
    }

    bool ringsEmpty = (!ch.toLocal || ch.toLocal->empty()) &&
                      (!ch.toRemote || ch.toRemote->empty());
    bool timedOut = (now - ch.closeStartMs) > DRAIN_TIMEOUT_MS;
    bool tooManyErrors = ch.consecutiveErrors > 3;

    if (timedOut) {
      LOGF_W("SSH",
             "Channel %d: drain timeout (%lums, toLocal=%zu, toRemote=%zu)", i,
             now - ch.closeStartMs, ch.toLocal ? ch.toLocal->size() : 0,
             ch.toRemote ? ch.toRemote->size() : 0);
      if (closeCount < 16) toClose[closeCount++] = i;
    } else if (tooManyErrors) {
      LOGF_W("SSH", "Channel %d: closing due to errors (%d)", i,
             ch.consecutiveErrors);
      if (closeCount < 16) toClose[closeCount++] = i;
    } else if (ringsEmpty) {
      if (ch.eofSentMs == 0) {
        // Rings drained — send SSH EOF first (next sub-step)
        if (eofCount < 16) toSendEof[eofCount++] = i;
      } else if ((now - ch.eofSentMs) >= EOF_GRACE_MS) {
        // Grace period elapsed — safe to finalize
        LOGF_I("SSH", "Channel %d: drain complete (sent=%zu, recv=%zu)", i,
               ch.totalBytesSent, ch.totalBytesReceived);
        if (closeCount < 16) toClose[closeCount++] = i;
      }
      // else: grace period still running, wait
    }
  }

  // --- Step 2a: Send EOF + pump transport for channels whose rings are empty ---
  if (eofCount > 0 && session_->lock(pdMS_TO_TICKS(100))) {
    for (int c = 0; c < eofCount; ++c) {
      int i = toSendEof[c];
      ChannelSlot &ch = channels_->getSlot(i);
      if (!ch.sshChannel) {
        continue;
      }

      // Send SSH EOF to signal "no more data from us"
      int rc = libssh2_channel_send_eof(ch.sshChannel);
      if (rc == 0 || rc == LIBSSH2_ERROR_EAGAIN) {
        // Retry EAGAIN a few times
        for (int retry = 0; rc == LIBSSH2_ERROR_EAGAIN && retry < 10;
             retry++) {
          rc = libssh2_channel_send_eof(ch.sshChannel);
        }
      }

      // Pump SSH transport to flush any pending outgoing data.
      // libssh2_channel_read() as a side effect processes the outgoing queue.
      uint8_t pumpBuf[512];
      for (int p = 0; p < 8; p++) {
        int pr =
            libssh2_channel_read(ch.sshChannel, (char *)pumpBuf, sizeof(pumpBuf));
        if (pr > 0 && ch.toLocal) {
          // Got some data — put it in the ring (will be drained next cycle)
          ch.toLocal->write(reinterpret_cast<uint8_t *>(pumpBuf), pr);
        }
        if (pr == LIBSSH2_ERROR_EAGAIN || pr <= 0) {
          break;
        }
      }

      ch.eofSentMs = millis();
      LOGF_D("SSH", "Channel %d: SSH EOF sent, grace period started", i);
    }
    session_->unlock();
  }

  // --- Step 2b: Finalize channels that have completed grace period ---
  if (closeCount > 0 && session_->lock(pdMS_TO_TICKS(200))) {
    for (int c = 0; c < closeCount; ++c) {
      channels_->finalizeClose(toClose[c]);
    }
    session_->unlock();
  }
}
