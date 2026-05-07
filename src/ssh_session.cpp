#include "ssh_session.h"
#include "forward_accept_error.h"
#include "network_optimizations.h"
#include <arpa/inet.h>
#include <lwip/netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

// ---------------------------------------------------------------------------
// Fingerprint helpers
// ---------------------------------------------------------------------------

String encodeFingerprintHex(const unsigned char *data, size_t len) {
  static const char kHexDigits[] = "0123456789abcdef";
  String out;
  out.reserve(len * 2);
  for (size_t i = 0; i < len; ++i) {
    unsigned char value = data[i];
    out += kHexDigits[(value >> 4) & 0x0F];
    out += kHexDigits[value & 0x0F];
  }
  return out;
}

String encodeFingerprintBase64(const unsigned char *data, size_t len) {
  static const char kBase64Table[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  String out;
  out.reserve(((len + 2) / 3) * 4);

  size_t index = 0;
  while (index < len) {
    uint32_t octet_a = data[index++];
    uint32_t octet_b = 0;
    uint32_t octet_c = 0;
    bool have_b = false;
    bool have_c = false;

    if (index < len) {
      octet_b = data[index++];
      have_b = true;
    }
    if (index < len) {
      octet_c = data[index++];
      have_c = true;
    }

    uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

    out += kBase64Table[(triple >> 18) & 0x3F];
    out += kBase64Table[(triple >> 12) & 0x3F];
    out += have_b ? kBase64Table[(triple >> 6) & 0x3F] : '=';
    out += have_c ? kBase64Table[triple & 0x3F] : '=';
  }

  // Strip trailing '=' (OpenSSH format)
  while (out.length() > 0 && out.charAt(out.length() - 1) == '=') {
    out.remove(out.length() - 1);
  }
  return out;
}

static bool isValidHexFingerprint(const String &value) {
  if (value.length() != 64) {
    return false;
  }
  for (size_t i = 0; i < value.length(); ++i) {
    char c = value.charAt(i);
    if (!isxdigit(static_cast<unsigned char>(c))) {
      return false;
    }
  }
  return true;
}

static constexpr int kAcceptFatalReconnectThreshold = 3;

// ---------------------------------------------------------------------------
// SSHSession
// ---------------------------------------------------------------------------

SSHSession::SSHSession() {}

SSHSession::~SSHSession() {
  disconnect();
  if (sessionMutex_) {
    vSemaphoreDelete(sessionMutex_);
    sessionMutex_ = nullptr;
  }
}

bool SSHSession::init() {
  if (!sessionMutex_) {
    sessionMutex_ = xSemaphoreCreateMutex();
    if (!sessionMutex_) {
      LOG_E("SSH", "Failed to create session mutex");
      return false;
    }
  }
  if (!libssh2Initialized_) {
    if (libssh2_init(0) != 0) {
      LOG_E("SSH", "libssh2_init failed");
      return false;
    }
    libssh2Initialized_ = true;
  }
  return true;
}

bool SSHSession::connect(SSHConfiguration *config) {
  config_ = config;
  resetAcceptState();

  if (session_) {
    LOG_W("SSH", "connect: leftover session, cleaning up");
    cleanupSession();
  }

  const SSHServerConfig &sshConfig = config_->getSSHConfig();
  const ConnectionConfig &connConfig = config_->getConnectionConfig();

  if (!tcpConnect(sshConfig)) {
    return false;
  }
  if (!handshake()) {
    cleanupSession();
    return false;
  }
  if (!configureKeepalive(connConfig)) {
    // Non-fatal, just log
  }
  if (!verifyHostKey(sshConfig)) {
    LOG_E("SSH", "Host key verification failed");
    cleanupSession();
    return false;
  }
  if (!authenticate(sshConfig)) {
    LOG_E("SSH", "Authentication failed");
    cleanupSession();
    return false;
  }
  if (!createListeners(config_)) {
    LOG_E("SSH", "Failed to create reverse listeners");
    cleanupSession();
    return false;
  }

  // Switch to non-blocking mode NOW (after all blocking setup is done).
  // TransportPump needs non-blocking for channel_read/write.
  libssh2_session_set_blocking(session_, 0);

  LOG_I("SSH", "SSH session fully connected (non-blocking mode active)");
  return true;
}

void SSHSession::disconnect() {
  cancelAllListeners();
  cleanupSession();
}

bool SSHSession::isConnected() const {
  return session_ != nullptr && socketfd_ >= 0;
}

bool SSHSession::sendKeepalive() {
  if (!session_) {
    return false;
  }

  int seconds = 0;
  int rc = LIBSSH2_ERROR_EAGAIN;
  if (lock(pdMS_TO_TICKS(200))) {
    rc = libssh2_keepalive_send(session_, &seconds);
    unlock();
  } else {
    LOG_W("SSH", "Keep-alive skipped (session lock timeout)");
    return true; // Not fatal
  }

  if (rc == 0) {
    keepAliveFailures_ = 0;
    LOGF_D("SSH", "Keep-alive sent, next in %d seconds", seconds);
    return true;
  }
  if (rc == LIBSSH2_ERROR_SOCKET_SEND) {
    keepAliveFailures_++;
    LOGF_W("SSH", "Keep-alive failed: %d (%d/3)", rc, keepAliveFailures_);
    if (keepAliveFailures_ >= 3) {
      LOG_W("SSH", "Keep-alive socket send failed 3 times");
      keepAliveFailures_ = 0;
      return false; // Signal dead connection
    }
    return true;
  }
  if (rc != LIBSSH2_ERROR_EAGAIN) {
    keepAliveFailures_ = 0;
    LOGF_W("SSH", "Keep-alive failed: %d", rc);
  }
  return true;
}

bool SSHSession::checkConnection() const {
  if (!session_ || socketfd_ < 0) {
    return false;
  }
  int error = 0;
  socklen_t len = sizeof(error);
  int retval = getsockopt(socketfd_, SOL_SOCKET, SO_ERROR, &error, &len);
  if (retval != 0 || error != 0) {
    LOGF_W("SSH", "checkConnection: retval=%d so_error=%d (%s)", retval, error,
           strerror(error));
    return false;
  }
  return true;
}

void SSHSession::resetAcceptState() {
  lastAcceptError_ = 0;
  consecutiveFatalAcceptErrors_ = 0;
  lastAcceptMs_ = 0;
  totalAccepts_ = 0;
#ifdef TUNNEL_DIAG_LOG_ONLY
  acceptDiag_.reset();
#endif
}

void SSHSession::recordAcceptSuccess() {
  lastAcceptError_ = 0;
  consecutiveFatalAcceptErrors_ = 0;
  lastAcceptMs_ = millis();
  ++totalAccepts_;
}

void SSHSession::recordAcceptNoChannel(int err) {
  lastAcceptError_ = err;
  if (isFatalAcceptError(err)) {
    ++consecutiveFatalAcceptErrors_;
    return;
  }
  consecutiveFatalAcceptErrors_ = 0;
}

bool SSHSession::isFatalAcceptError(int err) const {
  return forward_accept_error::isFatal(
      err, LIBSSH2_ERROR_EAGAIN, LIBSSH2_ERROR_CHANNEL_UNKNOWN,
      LIBSSH2_ERROR_CHANNEL_CLOSED, LIBSSH2_ERROR_SOCKET_SEND,
      LIBSSH2_ERROR_SOCKET_DISCONNECT);
}

bool SSHSession::hasFatalAcceptFailure() const {
  return forward_accept_error::shouldReconnectAfterConsecutiveErrors(
      consecutiveFatalAcceptErrors_, lastAcceptError_, LIBSSH2_ERROR_EAGAIN,
      LIBSSH2_ERROR_CHANNEL_UNKNOWN, LIBSSH2_ERROR_CHANNEL_CLOSED,
      LIBSSH2_ERROR_SOCKET_SEND, LIBSSH2_ERROR_SOCKET_DISCONNECT);
}

LIBSSH2_CHANNEL *SSHSession::acceptChannel(TunnelConfig &outMapping) {
  if (!session_ || listeners_.empty()) {
    return nullptr;
  }

#ifdef TUNNEL_DIAG_LOG_ONLY
  static constexpr unsigned long ACCEPT_IDLE_LOG_INTERVAL_MS = 1000;
#endif

  for (auto &entry : listeners_) {
    if (!entry.listener) {
      continue;
    }
#ifdef TUNNEL_DIAG_LOG_ONLY
    unsigned long pollNow = millis();
    acceptDiag_.recordPoll(pollNow);
#endif
    if (!lock(pdMS_TO_TICKS(50))) {
#ifdef TUNNEL_DIAG_LOG_ONLY
      acceptDiag_.recordLockUnavailable(millis());
      LOGF_W("SSH", "SERVERDIAG forward_accept_lock_unavailable remote=%s:%d "
                    "local=%s:%d",
             entry.mapping.remoteBindHost.c_str(), entry.mapping.remoteBindPort,
             entry.mapping.localHost.c_str(), entry.mapping.localPort);
#endif
      continue;
    }
    LIBSSH2_CHANNEL *ch = libssh2_channel_forward_accept(entry.listener);
    int acceptErr = ch ? 0 : libssh2_session_last_errno(session_);
    unlock();
    if (ch) {
      outMapping = entry.mapping;
      recordAcceptSuccess();
#ifdef TUNNEL_DIAG_LOG_ONLY
      forward_accept_diag::Snapshot diag = acceptDiag_.recordAccept(millis());
      LOGF_I("SSH", "SERVERDIAG forward_accept channel=%p remote=%s:%d "
                    "local=%s:%d bound=%d idle_ms=%lu polls=%lu eagain=%lu "
                    "errors=%lu lock_miss=%lu total_polls=%lu "
                    "total_accepts=%lu last_err=%d",
             ch, entry.mapping.remoteBindHost.c_str(),
             entry.mapping.remoteBindPort, entry.mapping.localHost.c_str(),
             entry.mapping.localPort, entry.boundPort,
             static_cast<unsigned long>(diag.idleMs),
             static_cast<unsigned long>(diag.pollsSinceAccept),
             static_cast<unsigned long>(diag.eagainSinceAccept),
             static_cast<unsigned long>(diag.errorsSinceAccept),
             static_cast<unsigned long>(diag.lockMissesSinceAccept),
             static_cast<unsigned long>(diag.totalPolls),
             static_cast<unsigned long>(diag.totalAccepts), diag.lastErr);
#endif
      return ch;
    }
    recordAcceptNoChannel(acceptErr);
#ifdef TUNNEL_DIAG_LOG_ONLY
    acceptDiag_.recordNoChannel(millis(), acceptErr,
                                acceptErr == LIBSSH2_ERROR_EAGAIN);
    if (acceptErr != 0 && acceptErr != LIBSSH2_ERROR_EAGAIN) {
      const bool fatal = isFatalAcceptError(acceptErr);
      const bool logNow =
          !fatal || consecutiveFatalAcceptErrors_ == 1 ||
          consecutiveFatalAcceptErrors_ == kAcceptFatalReconnectThreshold ||
          (consecutiveFatalAcceptErrors_ % 100) == 0;
      if (logNow) {
        LOGF_W("SSH", "SERVERDIAG forward_accept_error err=%d fatal=%d "
                      "fatal_count=%d remote=%s:%d local=%s:%d bound=%d",
               acceptErr, fatal ? 1 : 0, consecutiveFatalAcceptErrors_,
               entry.mapping.remoteBindHost.c_str(),
               entry.mapping.remoteBindPort, entry.mapping.localHost.c_str(),
               entry.mapping.localPort, entry.boundPort);
      }
    }
    unsigned long now = millis();
    if (acceptDiag_.idleSummaryDue(now, ACCEPT_IDLE_LOG_INTERVAL_MS)) {
      forward_accept_diag::Snapshot diag = acceptDiag_.snapshot(now);
      LOGF_W("SSH", "SERVERDIAG forward_accept_idle idle_ms=%lu polls=%lu "
                    "eagain=%lu errors=%lu lock_miss=%lu total_polls=%lu "
                    "total_accepts=%lu last_err=%d listeners=%d",
             static_cast<unsigned long>(diag.idleMs),
             static_cast<unsigned long>(diag.pollsSinceAccept),
             static_cast<unsigned long>(diag.eagainSinceAccept),
             static_cast<unsigned long>(diag.errorsSinceAccept),
             static_cast<unsigned long>(diag.lockMissesSinceAccept),
             static_cast<unsigned long>(diag.totalPolls),
             static_cast<unsigned long>(diag.totalAccepts), diag.lastErr,
             getActiveListenerCount());
      acceptDiag_.markIdleSummary(now);
    }
#endif
  }
  return nullptr;
}

bool SSHSession::lock(TickType_t ticks) {
  if (!sessionMutex_) {
    return false;
  }
  TickType_t waitTicks = ticks;
  if (waitTicks == 0) {
    waitTicks = 1;
  }
  return xSemaphoreTake(sessionMutex_, waitTicks) == pdTRUE;
}

void SSHSession::unlock() {
  if (sessionMutex_) {
    xSemaphoreGive(sessionMutex_);
  }
}

// ---------------------------------------------------------------------------
// Private: connection steps
// ---------------------------------------------------------------------------

bool SSHSession::tcpConnect(const SSHServerConfig &sshConfig) {
  socketfd_ = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (socketfd_ == -1) {
    LOG_E("SSH", "Error opening socket");
    return false;
  }

  if (!NetworkOptimizer::optimizeSSHSocket(socketfd_)) {
    LOG_W("SSH", "Warning: Could not apply all socket optimizations");
  }

  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  struct hostent *he = gethostbyname(sshConfig.host.c_str());
  if (he == nullptr) {
    LOGF_E("SSH", "Invalid remote hostname: %s", sshConfig.host.c_str());
    close(socketfd_);
    socketfd_ = -1;
    return false;
  }
  memcpy(&sin.sin_addr, he->h_addr_list[0], he->h_length);
  sin.sin_port = htons(sshConfig.port);

  if (::connect(socketfd_, (struct sockaddr *)(&sin),
                sizeof(struct sockaddr_in)) != 0) {
    LOGF_E("SSH", "Failed to connect to %s:%d", sshConfig.host.c_str(),
           sshConfig.port);
    close(socketfd_);
    socketfd_ = -1;
    return false;
  }

  LOGF_I("SSH", "TCP connected to %s:%d", sshConfig.host.c_str(),
         sshConfig.port);
  return true;
}

#ifdef TUNNEL_LIBSSH2_TRACE
static void libssh2TraceToLogger(LIBSSH2_SESSION * /*session*/,
                                 void * /*context*/, const char *data,
                                 size_t length) {
  if (!data || length == 0) {
    return;
  }
  // libssh2 trace strings aren't NUL-terminated and may contain a trailing
  // newline; copy into a small static buffer (single-threaded under session
  // lock) and trim before forwarding.
  static char buf[256];
  size_t n = length < sizeof(buf) - 1 ? length : sizeof(buf) - 1;
  memcpy(buf, data, n);
  while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) {
    --n;
  }
  buf[n] = '\0';
  LOGF_D("LIBSSH2", "%s", buf);
}
#endif

bool SSHSession::handshake() {
  session_ = libssh2_session_init();
  if (!session_) {
    LOG_E("SSH", "Could not initialize the SSH session");
    return false;
  }

#ifdef TUNNEL_LIBSSH2_TRACE
  // Wire libssh2 internal trace to the logger so we can see CHANNEL_OPEN
  // routing and listener queueing. Requires the libssh2 library itself to
  // be compiled with -DLIBSSH2DEBUG (otherwise libssh2_trace*() are no-ops).
  // CONN gives us the events relevant to forward-accept diagnosis:
  // "Remote received connection from..." and "Connection queued: ...".
  // Add LIBSSH2_TRACE_TRANS if you also need per-packet visibility (very
  // chatty — thousands of lines/sec on a busy session).
  libssh2_trace_sethandler(session_, this, libssh2TraceToLogger);
  libssh2_trace(session_, LIBSSH2_TRACE_CONN);
#endif

  // Session stays BLOCKING during setup (handshake, auth, listeners).
  // Non-blocking mode is enabled after connect() completes successfully.

  if (!lock(pdMS_TO_TICKS(5000))) {
    LOG_E("SSH", "Session lock timeout during handshake");
    libssh2_session_free(session_);
    session_ = nullptr;
    return false;
  }

  int rc = libssh2_session_handshake(session_, socketfd_);
  if (rc) {
    LOGF_E("SSH", "Error when starting up SSH session: %d", rc);
    libssh2_session_free(session_);
    session_ = nullptr;
    unlock();
    return false;
  }
  unlock();

  LOG_I("SSH", "SSH handshake completed");
  return true;
}

bool SSHSession::configureKeepalive(const ConnectionConfig &connConfig) {
  if (!connConfig.libssh2KeepAliveEnabled) {
    return true;
  }
  if (lock(pdMS_TO_TICKS(200))) {
    libssh2_keepalive_config(session_, 1,
                             connConfig.libssh2KeepAliveIntervalSec);
    unlock();
    LOGF_I("SSH", "libssh2 keepalive configured (interval=%ds)",
           connConfig.libssh2KeepAliveIntervalSec);
    return true;
  }
  LOG_W("SSH", "Session lock timeout while configuring libssh2 keepalive");
  return false;
}

bool SSHSession::verifyHostKey(const SSHServerConfig &sshConfig) {
  if (!sshConfig.verifyHostKey) {
    LOG_W("SSH", "Host key verification disabled - connection accepted");
    return true;
  }

  size_t host_key_len = 0;
  int host_key_type = 0;
  if (!lock(pdMS_TO_TICKS(200))) {
    LOG_E("SSH", "Session lock timeout while reading host key");
    return false;
  }
  const char *host_key =
      libssh2_session_hostkey(session_, &host_key_len, &host_key_type);
  const unsigned char *fingerprint_raw =
      reinterpret_cast<const unsigned char *>(
          libssh2_hostkey_hash(session_, LIBSSH2_HOSTKEY_HASH_SHA256));
  unlock();

  if (!host_key || host_key_len == 0) {
    LOG_E("SSH", "Failed to get host key from server");
    return false;
  }
  if (!fingerprint_raw) {
    LOG_E("SSH", "Failed to get host key fingerprint");
    return false;
  }

  String fingerprintHex = encodeFingerprintHex(fingerprint_raw, 32);
  String fingerprintBase64 = encodeFingerprintBase64(fingerprint_raw, 32);
  String fingerprintOpenSSH = String("SHA256:") + fingerprintBase64;

  String keyTypeStr;
  switch (host_key_type) {
  case LIBSSH2_HOSTKEY_TYPE_RSA:
    keyTypeStr = "ssh-rsa";
    break;
  case LIBSSH2_HOSTKEY_TYPE_DSS:
    keyTypeStr = "ssh-dss";
    break;
  case LIBSSH2_HOSTKEY_TYPE_ECDSA_256:
    keyTypeStr = "ecdsa-sha2-nistp256";
    break;
  case LIBSSH2_HOSTKEY_TYPE_ECDSA_384:
    keyTypeStr = "ecdsa-sha2-nistp384";
    break;
  case LIBSSH2_HOSTKEY_TYPE_ECDSA_521:
    keyTypeStr = "ecdsa-sha2-nistp521";
    break;
  case LIBSSH2_HOSTKEY_TYPE_ED25519:
    keyTypeStr = "ssh-ed25519";
    break;
  default:
    keyTypeStr = "unknown";
    break;
  }

  LOGF_I("SSH", "Server host key: %s", keyTypeStr.c_str());
  LOGF_I("SSH", "Server fingerprint (SHA256 hex): %s", fingerprintHex.c_str());
  LOGF_I("SSH", "Server fingerprint (OpenSSH): %s", fingerprintOpenSSH.c_str());

  if (sshConfig.hostKeyType.length() > 0 &&
      sshConfig.hostKeyType != keyTypeStr) {
    LOGF_E("SSH", "Host key type mismatch! Expected: %s, Got: %s",
           sshConfig.hostKeyType.c_str(), keyTypeStr.c_str());
    return false;
  }

  if (sshConfig.expectedHostKeyFingerprint.length() == 0) {
    LOG_W("SSH", "No expected fingerprint configured - accepting");
    LOGF_I("SSH", "Store this fingerprint (hex): %s", fingerprintHex.c_str());
    LOGF_I("SSH", "Store this fingerprint (OpenSSH): %s",
           fingerprintOpenSSH.c_str());
    return true;
  }

  String expectedRaw = sshConfig.expectedHostKeyFingerprint;
  expectedRaw.trim();
  expectedRaw.replace("\r", "");
  expectedRaw.replace("\n", "");

  bool expectedIsBase64 = false;
  String expectedComparable;

  String lowered = expectedRaw;
  lowered.toLowerCase();
  if (lowered.startsWith("sha256:")) {
    expectedIsBase64 = true;
    expectedComparable = expectedRaw.substring(expectedRaw.indexOf(':') + 1);
  } else {
    String candidate = expectedRaw;
    candidate.replace(" ", "");
    candidate.replace(":", "");
    String candidateLower = candidate;
    candidateLower.toLowerCase();
    if (isValidHexFingerprint(candidateLower)) {
      expectedComparable = candidateLower;
    } else {
      expectedIsBase64 = true;
      expectedComparable = expectedRaw;
    }
  }

  if (expectedIsBase64) {
    expectedComparable.trim();
    if (expectedComparable.startsWith("SHA256:")) {
      expectedComparable.remove(0, 7);
    } else if (expectedComparable.startsWith("sha256:")) {
      expectedComparable.remove(0, 7);
    }
    expectedComparable.replace(" ", "");
    expectedComparable.replace("\r", "");
    expectedComparable.replace("\n", "");
    expectedComparable.replace("=", "");
  } else {
    expectedComparable.toLowerCase();
    expectedComparable.replace(" ", "");
    expectedComparable.replace(":", "");
  }

  bool fingerprintsMatch = expectedIsBase64
                               ? (expectedComparable == fingerprintBase64)
                               : (expectedComparable == fingerprintHex);

  if (!fingerprintsMatch) {
    LOG_E("SSH", "HOST KEY VERIFICATION FAILED!");
    LOG_E("SSH", "This could indicate a Man-in-the-Middle attack!");
    if (expectedIsBase64) {
      LOGF_E("SSH", "Expected (OpenSSH): SHA256:%s",
             expectedComparable.c_str());
      LOGF_E("SSH", "Got      (OpenSSH): %s", fingerprintOpenSSH.c_str());
    } else {
      LOGF_E("SSH", "Expected (hex): %s", expectedComparable.c_str());
      LOGF_E("SSH", "Got      (hex): %s", fingerprintHex.c_str());
    }
    LOGF_E("SSH", "Key type: %s", keyTypeStr.c_str());

    if (sshConfig.onHostKeyMismatch) {
      const String actualForCallback =
          expectedIsBase64 ? fingerprintOpenSSH : fingerprintHex;
      sshConfig.onHostKeyMismatch(expectedRaw, actualForCallback, keyTypeStr,
                                  sshConfig.hostKeyMismatchContext);
    }
    return false;
  }

  LOG_I("SSH", "Host key verification successful");
  return true;
}

bool SSHSession::authenticate(const SSHServerConfig &sshConfig) {
  char *userauthlist = nullptr;
  if (lock(pdMS_TO_TICKS(500))) {
    userauthlist = libssh2_userauth_list(session_, sshConfig.username.c_str(),
                                         sshConfig.username.length());
    unlock();
  } else {
    LOG_E("SSH", "Session lock timeout while querying authentication methods");
    return false;
  }

  if (userauthlist == nullptr) {
    String detail = "";
    if (lock(pdMS_TO_TICKS(200))) {
      char *errmsg = nullptr;
      int errlen = 0;
      libssh2_session_last_error(session_, &errmsg, &errlen, 0);
      if (errmsg && errlen > 0) {
        detail = String(errmsg).substring(0, errlen);
      }
      unlock();
    }
    if (detail.length() > 0) {
      LOGF_E("SSH", "Failed to query authentication methods: %s",
             detail.c_str());
    } else {
      LOG_E("SSH", "Failed to query authentication methods (no data returned)");
    }
    return false;
  }
  LOGF_I("SSH", "Authentication methods: %s", userauthlist);

  // Determine auth method
  bool usePassword = !sshConfig.useSSHKey;

  if (usePassword) {
    int authRc = 0;
    if (lock(pdMS_TO_TICKS(1000))) {
      authRc = libssh2_userauth_password(session_, sshConfig.username.c_str(),
                                         sshConfig.password.c_str());
      unlock();
    } else {
      LOG_E("SSH", "Session lock timeout during password authentication");
      return false;
    }
    if (authRc) {
      LOG_E("SSH", "Authentication by password failed");
      return false;
    }
    LOG_I("SSH", "Authentication by password succeeded");
    return true;
  }

  // Public key authentication
  if (config_) {
    config_->diagnoseSSHKeys();
  }

  if (sshConfig.privateKeyData.length() > 0 &&
      sshConfig.publicKeyData.length() > 0) {
    // Validate keys
    if (config_ && !config_->validateSSHKeys()) {
      LOG_E("SSH", "SSH keys validation failed");
      return false;
    }

    LOGF_I("SSH",
           "Authenticating with keys from memory (private: %d bytes, public: "
           "%d bytes)",
           sshConfig.privateKeyData.length(), sshConfig.publicKeyData.length());

    // Try 3 passphrase variants: configured, empty string, NULL
    const char *passphrases[] = {
        sshConfig.password.length() > 0 ? sshConfig.password.c_str() : nullptr,
        "", nullptr};
    const char *passphraseNames[] = {"configured", "empty", "NULL"};

    for (int attempt = 0; attempt < 3; attempt++) {
      int auth_result = 0;
      String errorDetail = "";
      if (lock(pdMS_TO_TICKS(1000))) {
        auth_result = libssh2_userauth_publickey_frommemory(
            session_, sshConfig.username.c_str(), sshConfig.username.length(),
            sshConfig.publicKeyData.c_str(), sshConfig.publicKeyData.length(),
            sshConfig.privateKeyData.c_str(), sshConfig.privateKeyData.length(),
            passphrases[attempt]);
        if (auth_result) {
          char *errmsg = nullptr;
          int errlen = 0;
          libssh2_session_last_error(session_, &errmsg, &errlen, 0);
          if (errmsg && errlen > 0) {
            errorDetail = String(errmsg).substring(0, errlen);
          }
        }
        unlock();
      } else {
        LOG_E("SSH", "Session lock timeout during public key authentication");
        return false;
      }

      if (auth_result == 0) {
        LOGF_I("SSH", "Authentication succeeded with %s passphrase",
               passphraseNames[attempt]);
        return true;
      }

      const char *detail =
          errorDetail.length() ? errorDetail.c_str() : "Unknown";
      LOGF_E("SSH",
             "Auth attempt %d/%d (%s passphrase) failed: %d, Message: %s",
             attempt + 1, 3, passphraseNames[attempt], auth_result, detail);
    }

    LOG_W(
        "SSH",
        "Note: Your private key may be in OpenSSH format. "
        "Consider converting to PEM format: ssh-keygen -p -m PEM -f your_key");
    return false;

  } else {
    // Fallback to file-based method
    LOG_W("SSH",
          "SSH keys not available in memory, falling back to file-based auth");
    String keyfile1_str = sshConfig.privateKeyPath + ".pub";
    const char *keyfile1 = keyfile1_str.c_str();
    const char *keyfile2 = sshConfig.privateKeyPath.c_str();
    int fileAuth = 0;
    if (lock(pdMS_TO_TICKS(1000))) {
      fileAuth = libssh2_userauth_publickey_fromfile(
          session_, sshConfig.username.c_str(), keyfile1, keyfile2,
          sshConfig.password.c_str());
      if (fileAuth) {
        char *errmsg = nullptr;
        int errlen = 0;
        libssh2_session_last_error(session_, &errmsg, &errlen, 0);
        String detailStr = "";
        if (errmsg && errlen > 0) {
          detailStr = String(errmsg).substring(0, errlen);
        }
        unlock();
        const char *detail = detailStr.length() ? detailStr.c_str() : "Unknown";
        LOGF_E("SSH", "Auth by public key from file failed: %d, Message: %s",
               fileAuth, detail);
        return false;
      }
      unlock();
    } else {
      LOG_E("SSH", "Session lock timeout during file-based authentication");
      return false;
    }
    LOG_I("SSH", "Authentication by public key from file succeeded");
    return true;
  }
}

bool SSHSession::createListeners(SSHConfiguration *config) {
  cancelAllListeners();
  boundPort_ = -1;

  const std::vector<TunnelConfig> &mappings = config->getTunnelMappings();
  if (mappings.empty()) {
    LOG_E("SSH", "No tunnel mappings configured");
    return false;
  }

  int listenerLimit = config->getConnectionConfig().maxReverseListeners;
  int desired = std::min(listenerLimit, static_cast<int>(mappings.size()));
  if (desired <= 0) {
    LOG_E("SSH", "maxReverseListeners must be positive");
    return false;
  }

  for (int i = 0; i < desired; ++i) {
    ListenerEntry entry;
    entry.mapping = mappings[i];
    if (!createListenerForMapping(entry.mapping, entry)) {
      LOGF_E("SSH", "Failed to create listener for %s:%d -> %s:%d",
             entry.mapping.remoteBindHost.c_str(), entry.mapping.remoteBindPort,
             entry.mapping.localHost.c_str(), entry.mapping.localPort);
      cancelAllListeners();
      return false;
    }
    listeners_.push_back(entry);
    if (boundPort_ < 0) {
      boundPort_ = entry.boundPort;
    }
  }

  if (static_cast<int>(mappings.size()) > desired) {
    LOGF_W("SSH", "Only %d/%zu listeners created due to limit", desired,
           mappings.size());
  }

  return !listeners_.empty();
}

// ---------------------------------------------------------------------------
// Private: listener helpers
// ---------------------------------------------------------------------------

bool SSHSession::createListenerForMapping(const TunnelConfig &mapping,
                                          ListenerEntry &entry) {
  const int maxlisten =
      config_ ? std::max(1, config_->getConnectionConfig().maxChannels) : 8;
  const char *bindHost = mapping.remoteBindHost.c_str();
  int bindPort = mapping.remoteBindPort;
  int boundPortResult = 0;
  LIBSSH2_LISTENER *handle = nullptr;
  const int maxAttempts = 50;
  int attempts = 0;

  while (!handle && attempts < maxAttempts) {
    ++attempts;
    if (!lock(pdMS_TO_TICKS(500))) {
      vTaskDelay(pdMS_TO_TICKS(10));
      continue;
    }
    handle = libssh2_channel_forward_listen_ex(session_, bindHost, bindPort,
                                               &boundPortResult, maxlisten);
    unlock();
    if (!handle) {
      vTaskDelay(pdMS_TO_TICKS(10));
    }
  }

  if (!handle) {
    // Fetch libssh2's last error string for diagnostics. If sshd refused
    // the bind because a previous listener is still bound (Bug #2 in the
    // 2026-04-28 baseline report), the message will be along the lines
    // of "channel_setup_fwd_listener_tcpip: cannot listen to port: <N>".
    String errDetail;
    if (lock(pdMS_TO_TICKS(100))) {
      char *errmsg = nullptr;
      int errlen = 0;
      libssh2_session_last_error(session_, &errmsg, &errlen, 0);
      if (errmsg) {
        errDetail = errmsg;
      }
      unlock();
    }
    LOGF_E("SSH",
           "Unable to create reverse listener for %s:%d -> %s:%d "
           "(libssh2: %s) — possible stale listener on sshd; check "
           "ClientAliveInterval / ClientAliveCountMax.",
           mapping.remoteBindHost.c_str(), mapping.remoteBindPort,
           mapping.localHost.c_str(), mapping.localPort,
           errDetail.length() ? errDetail.c_str() : "no detail");
    return false;
  }

  entry.listener = handle;
  entry.mapping = mapping;
  entry.boundPort = boundPortResult;
  if (boundPortResult != bindPort && bindPort != 0) {
    LOGF_W("SSH",
           "Listener bound on port %d but %d was requested — sshd may have "
           "fallen back to a random port",
           boundPortResult, bindPort);
  }
  LOGF_I("SSH", "Reverse listener ready %s:%d (bound %d) -> %s:%d",
         mapping.remoteBindHost.c_str(), mapping.remoteBindPort,
         boundPortResult, mapping.localHost.c_str(), mapping.localPort);
  if (lastAcceptMs_ == 0) {
    lastAcceptMs_ = millis();
  }
  return true;
}

void SSHSession::cancelListener(ListenerEntry &entry) {
  if (!entry.listener) {
    return;
  }
  if (lock(pdMS_TO_TICKS(500))) {
    libssh2_channel_forward_cancel(entry.listener);
    unlock();
  }
  entry.listener = nullptr;
}

void SSHSession::cancelAllListeners() {
  for (auto &entry : listeners_) {
    cancelListener(entry);
  }
  listeners_.clear();
  boundPort_ = -1;
}

bool SSHSession::relistenStuckListeners(unsigned long nowMs,
                                        unsigned long thresholdMs) {
  if (!session_ || socketfd_ < 0 || listeners_.empty()) {
    return false;
  }
  // Require at least one prior accept on this listener: that proves it has
  // worked, so the current idle is suspicious rather than just "no traffic".
  if (thresholdMs == 0 || lastAcceptMs_ == 0 || totalAccepts_ == 0) {
    return false;
  }
  unsigned long idleMs = nowMs - lastAcceptMs_;
  if (idleMs < thresholdMs) {
    return false;
  }

  bool anyRecreated = false;
  for (auto &entry : listeners_) {
    if (!entry.listener) {
      continue;
    }
    TunnelConfig mapping = entry.mapping;
    LOGF_W("SSH",
           "SERVERDIAG forward_listener_stuck_relisten remote=%s:%d "
           "idle_ms=%lu total_accepts=%lu threshold_ms=%lu",
           mapping.remoteBindHost.c_str(), mapping.remoteBindPort, idleMs,
           totalAccepts_, thresholdMs);
    cancelListener(entry);
    if (createListenerForMapping(mapping, entry)) {
      anyRecreated = true;
    } else {
      LOGF_E("SSH",
             "Failed to recreate stuck listener for %s:%d — slot left empty",
             mapping.remoteBindHost.c_str(), mapping.remoteBindPort);
    }
  }
  // Reset idle baseline so we don't immediately re-fire if recreation succeeded
  // but new traffic has not yet been accepted.
  lastAcceptMs_ = nowMs;
  lastAcceptError_ = 0;
  consecutiveFatalAcceptErrors_ = 0;
#ifdef TUNNEL_DIAG_LOG_ONLY
  acceptDiag_.reset();
#endif
  return anyRecreated;
}

// ---------------------------------------------------------------------------
// Private: cleanup
// ---------------------------------------------------------------------------

void SSHSession::cleanupSession() {
  cancelAllListeners();

  if (session_) {
    if (lock(pdMS_TO_TICKS(2000))) {
      libssh2_session_disconnect(session_, "Shutdown");
      libssh2_session_free(session_);
      unlock();
    } else {
      // Best effort: free without lock rather than leak
      LOG_W("SSH", "Session lock timeout during cleanup, forcing free");
      libssh2_session_disconnect(session_, "Shutdown");
      libssh2_session_free(session_);
    }
    session_ = nullptr;
  }

  if (socketfd_ >= 0) {
    close(socketfd_);
    socketfd_ = -1;
  }

  keepAliveFailures_ = 0;
  resetAcceptState();
}
