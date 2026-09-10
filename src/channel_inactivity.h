#ifndef CHANNEL_INACTIVITY_H
#define CHANNEL_INACTIVITY_H

namespace channel_inactivity {

// Unsigned subtraction keeps the elapsed-time calculation correct when
// millis() wraps. A zero timestamp means the channel has not been initialized;
// a zero timeout disables this guard defensively (normal config rejects it).
inline bool hasExpired(unsigned long nowMs, unsigned long lastActivityMs,
                       unsigned long timeoutMs) {
  return lastActivityMs > 0 && timeoutMs > 0 &&
         (nowMs - lastActivityMs) > timeoutMs;
}

} // namespace channel_inactivity

#endif // CHANNEL_INACTIVITY_H
