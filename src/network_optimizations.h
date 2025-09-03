#ifndef NETWORK_OPTIMIZATIONS_H
#define NETWORK_OPTIMIZATIONS_H

#include <sys/socket.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <string.h>
#include <logger.h>

// Optimisations réseau pour améliorer les performances du tunnel
class NetworkOptimizer {
public:
    static bool optimizeSocket(int socket_fd) {
        // Sur ESP32/lwIP, tous les setsockopt ne sont pas supportés.
        // On considère l'opération "réussie" si AU MOINS une optimisation est appliquée,
        // pour éviter de spammer les logs quand certaines options ne sont pas dispo.
        int attempted = 0;
        int applied = 0;

        // Activer TCP_NODELAY pour réduire la latence
        int nodelay = 1;
        attempted++;
        if (setsockopt(socket_fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay)) == 0) {
            applied++;
        } else {
            LOGF_W("SSH", "Failed to set TCP_NODELAY: %s", strerror(errno));
        }

        // Augmenter les buffers de réception et d'envoi
        int rcvbuf = 65536;  // 64KB
        int sndbuf = 65536;  // 64KB

#ifdef SO_RCVBUF
        attempted++;
        if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) == 0) {
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
        if (setsockopt(socket_fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) == 0) {
            applied++;
        } else {
            if (errno == ENOPROTOOPT || errno == EINVAL || errno == EOPNOTSUPP) {
                LOGF_D("SSH", "SO_SNDBUF not supported: %s", strerror(errno));
            } else {
                LOGF_W("SSH", "Failed to set SO_SNDBUF: %s", strerror(errno));
            }
        }
#endif

        // Configurer les timeouts
        struct timeval timeout;
        timeout.tv_sec = 300;  // 5 minutes
        timeout.tv_usec = 0;

#ifdef SO_RCVTIMEO
        attempted++;
        if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0) {
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
        if (setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0) {
            applied++;
        } else {
            if (errno == ENOPROTOOPT || errno == EINVAL || errno == EOPNOTSUPP) {
                LOGF_D("SSH", "SO_SNDTIMEO not supported: %s", strerror(errno));
            } else {
                LOGF_W("SSH", "Failed to set SO_SNDTIMEO: %s", strerror(errno));
            }
        }
#endif

        // Activer SO_KEEPALIVE pour maintenir les connexions
        int keepalive = 1;
        attempted++;
        if (setsockopt(socket_fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive)) == 0) {
            applied++;
        } else {
            LOGF_W("SSH", "Failed to set SO_KEEPALIVE: %s", strerror(errno));
        }
        return applied > 0 || attempted == 0;
    }

    static bool optimizeSSHSocket(int socket_fd) {
        // Optimisations spécifiques pour les connexions SSH
        bool success = optimizeSocket(socket_fd);

        // Paramètres TCP keepalive pour SSH
        int keepidle = 60;     // Commencer les keepalives après 60s
        int keepintvl = 10;    // Intervalle entre keepalives
        int keepcnt = 6;       // Nombre de keepalives avant timeout

#ifdef TCP_KEEPIDLE
        if (setsockopt(socket_fd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle)) < 0) {
            LOGF_W("SSH", "Failed to set TCP_KEEPIDLE: %s", strerror(errno));
            success = false;
        }
#endif

#ifdef TCP_KEEPINTVL
        if (setsockopt(socket_fd, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl)) < 0) {
            LOGF_W("SSH", "Failed to set TCP_KEEPINTVL: %s", strerror(errno));
            success = false;
        }
#endif

#ifdef TCP_KEEPCNT
        if (setsockopt(socket_fd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt)) < 0) {
            LOGF_W("SSH", "Failed to set TCP_KEEPCNT: %s", strerror(errno));
            success = false;
        }
#endif

        return success;
    }
};

#endif