#ifndef FORWARD_ACCEPT_ERROR_H
#define FORWARD_ACCEPT_ERROR_H

namespace forward_accept_error {

inline bool isBenignNoChannel(int err, int eagainCode) {
  return err == 0 || err == eagainCode;
}

inline bool isFatal(int err, int eagainCode, int channelUnknownCode,
                    int channelClosedCode, int socketSendCode,
                    int socketDisconnectCode) {
  if (isBenignNoChannel(err, eagainCode)) {
    return false;
  }
  return err == channelUnknownCode || err == channelClosedCode ||
         err == socketSendCode || err == socketDisconnectCode;
}

inline bool shouldReconnectAfterConsecutiveErrors(
    int consecutiveFatalErrors, int err, int eagainCode,
    int channelUnknownCode, int channelClosedCode, int socketSendCode,
    int socketDisconnectCode) {
  return consecutiveFatalErrors >= 3 &&
         isFatal(err, eagainCode, channelUnknownCode, channelClosedCode,
                 socketSendCode, socketDisconnectCode);
}

} // namespace forward_accept_error

#endif // FORWARD_ACCEPT_ERROR_H
