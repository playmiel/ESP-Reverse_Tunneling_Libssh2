#ifndef NETWORK_OPTIMIZATIONS_H
#define NETWORK_OPTIMIZATIONS_H

#include <errno.h>
#include <logger.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/socket.h>

// Network optimizations to improve tunnel performance
class NetworkOptimizer {
public:
  static bool optimizeSocket(int socket_fd) {
    // On ESP32/lwIP, not all setsockopt options are supported.
    // Consider the operation 'successful' if at least one optimization is
    // applied to avoid log spam when some options are unavailable.
    int attempted = 0;
    int applied = 0;

    // Enable TCP_NODELAY to reduce latency
    int nodelay = 1;
    attempted++;
    if (setsockopt(socket_fd, IPPROTO_TCP, TCP_NODELAY, &nodelay,
                   sizeof(nodelay)) == 0) {
      applied++;
    } else {
      LOGF_W("SSH", "Failed to set TCP_NODELAY: %s", strerror(errno));
    }

    // Increase receive and send buffer sizes
    int rcvbuf = 65536; // 64KB
    int sndbuf = 65536; // 64KB

#ifdef SO_RCVBUF
    attempted++;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) ==
        0) {
      applied++;
    } else {
      if (errno == ENOPROTOOPT || errno == EINVAL || errno == EOPNOTSUPP) {
        LOGF_D("SSH", "SO_RCVBUF not supported: %s", strerror(errno));
      } else {
        LOGF_W("SSH", "Failed to set SO_RCVBUF: %s", strerror(errno));
      }
    }
#endif

#ifdef SO_SNDBUF
    attempted++;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) ==
        0) {
      applied++;
    } else {
      if (errno == ENOPROTOOPT || errno == EINVAL || errno == EOPNOTSUPP) {
        LOGF_D("SSH", "SO_SNDBUF not supported: %s", strerror(errno));
      } else {
        LOGF_W("SSH", "Failed to set SO_SNDBUF: %s", strerror(errno));
      }
    }
#endif

    // Configure timeouts
    struct timeval timeout;
    timeout.tv_sec = 300; // 5 minutes
    timeout.tv_usec = 0;

#ifdef SO_RCVTIMEO
    attempted++;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof(timeout)) == 0) {
      applied++;
    } else {
      if (errno == ENOPROTOOPT || errno == EINVAL || errno == EOPNOTSUPP) {
        LOGF_D("SSH", "SO_RCVTIMEO not supported: %s", strerror(errno));
      } else {
        LOGF_W("SSH", "Failed to set SO_RCVTIMEO: %s", strerror(errno));
      }
    }
#endif

#ifdef SO_SNDTIMEO
    attempted++;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                   sizeof(timeout)) == 0) {
      applied++;
    } else {
      if (errno == ENOPROTOOPT || errno == EINVAL || errno == EOPNOTSUPP) {
        LOGF_D("SSH", "SO_SNDTIMEO not supported: %s", strerror(errno));
      } else {
        LOGF_W("SSH", "Failed to set SO_SNDTIMEO: %s", strerror(errno));
      }
    }
#endif

    // Enable SO_KEEPALIVE to keep connections alive
    int keepalive = 1;
    attempted++;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive,
                   sizeof(keepalive)) == 0) {
      applied++;
    } else {
      LOGF_W("SSH", "Failed to set SO_KEEPALIVE: %s", strerror(errno));
    }
    return applied > 0 || attempted == 0;
  }

  static bool optimizeSSHSocket(int socket_fd) {
    // Specific optimizations for SSH connections
    bool success = optimizeSocket(socket_fd);

    // TCP keepalive parameters for SSH
    int keepidle = 60;  // Start keepalives after 60s
    int keepintvl = 10; // Interval between keepalives
    int keepcnt = 6;    // Number of keepalives before timeout

#ifdef TCP_KEEPIDLE
    if (setsockopt(socket_fd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle,
                   sizeof(keepidle)) < 0) {
      LOGF_W("SSH", "Failed to set TCP_KEEPIDLE: %s", strerror(errno));
      success = false;
    }
#endif

#ifdef TCP_KEEPINTVL
    if (setsockopt(socket_fd, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl,
                   sizeof(keepintvl)) < 0) {
      LOGF_W("SSH", "Failed to set TCP_KEEPINTVL: %s", strerror(errno));
      success = false;
    }
#endif

#ifdef TCP_KEEPCNT
    if (setsockopt(socket_fd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt,
                   sizeof(keepcnt)) < 0) {
      LOGF_W("SSH", "Failed to set TCP_KEEPCNT: %s", strerror(errno));
      success = false;
    }
#endif

    return success;
  }
};

#endif