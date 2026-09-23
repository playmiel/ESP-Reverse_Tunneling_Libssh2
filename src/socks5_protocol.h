#ifndef SOCKS5_PROTOCOL_H
#define SOCKS5_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

namespace socks5 {

static constexpr uint8_t VERSION = 0x05;
static constexpr uint8_t METHOD_NO_AUTH = 0x00;
static constexpr uint8_t METHOD_NOT_ACCEPTABLE = 0xff;
static constexpr uint8_t COMMAND_CONNECT = 0x01;
static constexpr uint8_t ADDRESS_IPV4 = 0x01;
static constexpr uint8_t ADDRESS_DOMAIN = 0x03;

enum class Reply : uint8_t {
  Succeeded = 0x00,
  GeneralFailure = 0x01,
  NetworkUnreachable = 0x03,
  HostUnreachable = 0x04,
  ConnectionRefused = 0x05,
  TtlExpired = 0x06,
  CommandNotSupported = 0x07,
  AddressTypeNotSupported = 0x08
};

enum class Event : uint8_t {
  NeedMore,
  MethodAccepted,
  MethodRejected,
  ConnectRequest,
  GeneralFailure,
  CommandNotSupported,
  AddressTypeNotSupported
};

// Incremental, allocation-free parser for the SOCKS5 subset supported by the
// tunnel: NO AUTH, CONNECT, IPv4 and domain-name destinations. The caller
// should never pass more than bytesNeeded(), which prevents pipelined
// application data from being consumed as part of the handshake.
class Negotiator {
public:
  Negotiator() { reset(); }

  void reset() {
    stage_ = Stage::GreetingHeader;
    headerUsed_ = 0;
    remainingMethods_ = 0;
    sawNoAuth_ = false;
    methodAccepted_ = false;
    addressType_ = 0;
    domainLength_ = 0;
    targetUsed_ = 0;
    targetNeeded_ = 0;
    targetHost_[0] = '\0';
    targetPort_ = 0;
    memset(header_, 0, sizeof(header_));
    memset(targetBytes_, 0, sizeof(targetBytes_));
  }

  size_t bytesNeeded() const {
    switch (stage_) {
    case Stage::GreetingHeader:
      return 2 - headerUsed_;
    case Stage::RequestHeader:
      return sizeof(header_) - headerUsed_;
    case Stage::GreetingMethods:
      return remainingMethods_;
    case Stage::DomainLength:
      return 1;
    case Stage::Target:
      return targetNeeded_ - targetUsed_;
    case Stage::Complete:
    case Stage::Failed:
      return 0;
    }
    return 0;
  }

  Event consume(const uint8_t *data, size_t length) {
    const size_t needed = bytesNeeded();
    if (!data || length == 0 || needed == 0 || length > needed) {
      return Event::GeneralFailure;
    }

    switch (stage_) {
    case Stage::GreetingHeader:
      memcpy(header_ + headerUsed_, data, length);
      headerUsed_ += length;
      if (headerUsed_ < 2) {
        return Event::NeedMore;
      }
      if (header_[0] != VERSION || header_[1] == 0) {
        stage_ = Stage::Failed;
        return Event::MethodRejected;
      }
      remainingMethods_ = header_[1];
      headerUsed_ = 0;
      stage_ = Stage::GreetingMethods;
      return Event::NeedMore;

    case Stage::GreetingMethods:
      for (size_t i = 0; i < length; ++i) {
        if (data[i] == METHOD_NO_AUTH) {
          sawNoAuth_ = true;
        }
      }
      remainingMethods_ -= length;
      if (remainingMethods_ > 0) {
        return Event::NeedMore;
      }
      if (!sawNoAuth_) {
        stage_ = Stage::Failed;
        return Event::MethodRejected;
      }
      methodAccepted_ = true;
      headerUsed_ = 0;
      stage_ = Stage::RequestHeader;
      return Event::MethodAccepted;

    case Stage::RequestHeader:
      memcpy(header_ + headerUsed_, data, length);
      headerUsed_ += length;
      if (headerUsed_ < sizeof(header_)) {
        return Event::NeedMore;
      }
      if (header_[0] != VERSION || header_[2] != 0) {
        stage_ = Stage::Failed;
        return Event::GeneralFailure;
      }
      if (header_[1] != COMMAND_CONNECT) {
        stage_ = Stage::Failed;
        return Event::CommandNotSupported;
      }
      addressType_ = header_[3];
      targetUsed_ = 0;
      if (addressType_ == ADDRESS_IPV4) {
        targetNeeded_ = 6; // four address octets + two port octets
        stage_ = Stage::Target;
        return Event::NeedMore;
      }
      if (addressType_ == ADDRESS_DOMAIN) {
        stage_ = Stage::DomainLength;
        return Event::NeedMore;
      }
      stage_ = Stage::Failed;
      return Event::AddressTypeNotSupported;

    case Stage::DomainLength:
      domainLength_ = data[0];
      if (domainLength_ == 0) {
        stage_ = Stage::Failed;
        return Event::AddressTypeNotSupported;
      }
      targetUsed_ = 0;
      targetNeeded_ = static_cast<size_t>(domainLength_) + 2;
      stage_ = Stage::Target;
      return Event::NeedMore;

    case Stage::Target:
      memcpy(targetBytes_ + targetUsed_, data, length);
      targetUsed_ += length;
      if (targetUsed_ < targetNeeded_) {
        return Event::NeedMore;
      }
      if (!finishTarget()) {
        stage_ = Stage::Failed;
        return Event::GeneralFailure;
      }
      stage_ = Stage::Complete;
      return Event::ConnectRequest;

    case Stage::Complete:
    case Stage::Failed:
      return Event::GeneralFailure;
    }
    return Event::GeneralFailure;
  }

  bool methodAccepted() const { return methodAccepted_; }
  bool complete() const { return stage_ == Stage::Complete; }
  const char *targetHost() const { return targetHost_; }
  uint16_t targetPort() const { return targetPort_; }

private:
  enum class Stage : uint8_t {
    GreetingHeader,
    GreetingMethods,
    RequestHeader,
    DomainLength,
    Target,
    Complete,
    Failed
  };

  bool finishTarget() {
    size_t portOffset = 0;
    if (addressType_ == ADDRESS_IPV4) {
      if (targetNeeded_ != 6) {
        return false;
      }
      snprintf(targetHost_, sizeof(targetHost_), "%u.%u.%u.%u",
               static_cast<unsigned>(targetBytes_[0]),
               static_cast<unsigned>(targetBytes_[1]),
               static_cast<unsigned>(targetBytes_[2]),
               static_cast<unsigned>(targetBytes_[3]));
      portOffset = 4;
    } else if (addressType_ == ADDRESS_DOMAIN) {
      if (domainLength_ == 0 ||
          targetNeeded_ != static_cast<size_t>(domainLength_) + 2) {
        return false;
      }
      memcpy(targetHost_, targetBytes_, domainLength_);
      targetHost_[domainLength_] = '\0';
      portOffset = domainLength_;
    } else {
      return false;
    }

    targetPort_ = static_cast<uint16_t>(
        (static_cast<uint16_t>(targetBytes_[portOffset]) << 8) |
        targetBytes_[portOffset + 1]);
    return targetPort_ != 0;
  }

  Stage stage_ = Stage::GreetingHeader;
  uint8_t header_[4] = {};
  size_t headerUsed_ = 0;
  size_t remainingMethods_ = 0;
  bool sawNoAuth_ = false;
  bool methodAccepted_ = false;
  uint8_t addressType_ = 0;
  uint8_t domainLength_ = 0;
  uint8_t targetBytes_[257] = {};
  size_t targetUsed_ = 0;
  size_t targetNeeded_ = 0;
  char targetHost_[256] = {};
  uint16_t targetPort_ = 0;
};

inline size_t writeMethodSelection(bool accepted, uint8_t *out,
                                   size_t capacity) {
  if (!out || capacity < 2) {
    return 0;
  }
  out[0] = VERSION;
  out[1] = accepted ? METHOD_NO_AUTH : METHOD_NOT_ACCEPTABLE;
  return 2;
}

// The bound address is intentionally reported as 0.0.0.0:0. RFC 1928 allows
// the server to return the address associated with the connection, but clients
// do not require it for CONNECT and querying it is unnecessary for this MVP.
inline size_t writeConnectReply(Reply reply, uint8_t *out, size_t capacity) {
  if (!out || capacity < 10) {
    return 0;
  }
  out[0] = VERSION;
  out[1] = static_cast<uint8_t>(reply);
  out[2] = 0;
  out[3] = ADDRESS_IPV4;
  memset(out + 4, 0, 6);
  return 10;
}

} // namespace socks5

#endif // SOCKS5_PROTOCOL_H
