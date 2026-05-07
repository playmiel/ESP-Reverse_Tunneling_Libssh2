#ifndef FORWARD_ACCEPT_DIAG_H
#define FORWARD_ACCEPT_DIAG_H

#include <stdint.h>

namespace forward_accept_diag {

struct Snapshot {
  uint32_t pollsSinceAccept = 0;
  uint32_t eagainSinceAccept = 0;
  uint32_t errorsSinceAccept = 0;
  uint32_t lockMissesSinceAccept = 0;
  uint32_t totalPolls = 0;
  uint32_t totalAccepts = 0;
  uint32_t idleMs = 0;
  int lastErr = 0;
};

class Tracker {
public:
  void reset() {
    totalPolls_ = 0;
    totalAccepts_ = 0;
    pollsSinceAccept_ = 0;
    eagainSinceAccept_ = 0;
    errorsSinceAccept_ = 0;
    lockMissesSinceAccept_ = 0;
    idleStartMs_ = 0;
    lastSummaryMs_ = 0;
    lastErr_ = 0;
  }

  void recordPoll(uint32_t nowMs) {
    if (idleStartMs_ == 0) {
      idleStartMs_ = nowMs;
    }
    ++totalPolls_;
    ++pollsSinceAccept_;
  }

  void recordNoChannel(uint32_t, int err, bool isEagain) {
    lastErr_ = err;
    if (isEagain) {
      ++eagainSinceAccept_;
    } else if (err != 0) {
      ++errorsSinceAccept_;
    }
  }

  void recordLockUnavailable(uint32_t nowMs) {
    if (idleStartMs_ == 0) {
      idleStartMs_ = nowMs;
    }
    ++lockMissesSinceAccept_;
  }

  bool idleSummaryDue(uint32_t nowMs, uint32_t intervalMs) const {
    if (pollsSinceAccept_ == 0 && lockMissesSinceAccept_ == 0) {
      return false;
    }
    uint32_t last = lastSummaryMs_ != 0 ? lastSummaryMs_ : idleStartMs_;
    return last != 0 && elapsed(nowMs, last) >= intervalMs;
  }

  void markIdleSummary(uint32_t nowMs) { lastSummaryMs_ = nowMs; }

  Snapshot snapshot(uint32_t nowMs) const {
    Snapshot out;
    out.pollsSinceAccept = pollsSinceAccept_;
    out.eagainSinceAccept = eagainSinceAccept_;
    out.errorsSinceAccept = errorsSinceAccept_;
    out.lockMissesSinceAccept = lockMissesSinceAccept_;
    out.totalPolls = totalPolls_;
    out.totalAccepts = totalAccepts_;
    out.idleMs = idleStartMs_ != 0 ? elapsed(nowMs, idleStartMs_) : 0;
    out.lastErr = lastErr_;
    return out;
  }

  Snapshot recordAccept(uint32_t nowMs) {
    Snapshot out = snapshot(nowMs);
    ++totalAccepts_;
    out.totalAccepts = totalAccepts_;
    pollsSinceAccept_ = 0;
    eagainSinceAccept_ = 0;
    errorsSinceAccept_ = 0;
    lockMissesSinceAccept_ = 0;
    idleStartMs_ = 0;
    lastSummaryMs_ = 0;
    lastErr_ = 0;
    return out;
  }

private:
  static uint32_t elapsed(uint32_t nowMs, uint32_t thenMs) {
    return nowMs - thenMs;
  }

  uint32_t totalPolls_ = 0;
  uint32_t totalAccepts_ = 0;
  uint32_t pollsSinceAccept_ = 0;
  uint32_t eagainSinceAccept_ = 0;
  uint32_t errorsSinceAccept_ = 0;
  uint32_t lockMissesSinceAccept_ = 0;
  uint32_t idleStartMs_ = 0;
  uint32_t lastSummaryMs_ = 0;
  int lastErr_ = 0;
};

} // namespace forward_accept_diag

#endif // FORWARD_ACCEPT_DIAG_H
