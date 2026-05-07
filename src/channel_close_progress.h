#ifndef CHANNEL_CLOSE_PROGRESS_H
#define CHANNEL_CLOSE_PROGRESS_H

namespace channel_close_progress {

struct Progress {
  bool closeComplete = false;
  bool freeComplete = false;
};

inline bool recordCloseResult(Progress &progress, int rc, int eagainCode) {
  if (rc == eagainCode) {
    return false;
  }
  progress.closeComplete = true;
  return true;
}

inline bool readyForFree(const Progress &progress) {
  return progress.closeComplete;
}

inline bool recordFreeResult(Progress &progress, int rc, int eagainCode) {
  if (rc == eagainCode) {
    return false;
  }
  progress.freeComplete = true;
  return true;
}

inline bool readyForFinalize(const Progress &progress) {
  return progress.closeComplete && progress.freeComplete;
}

} // namespace channel_close_progress

#endif // CHANNEL_CLOSE_PROGRESS_H
