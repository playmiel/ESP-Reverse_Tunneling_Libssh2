#ifndef NETWORK_OPTIMIZATIONS_H
#define NETWORK_OPTIMIZATIONS_H

#include <sys/socket.h>
#include <netinet/tcp.h>

// Optimisations réseau pour améliorer les performances du tunnel
class NetworkOptimizer {
public:
    static bool optimizeSocket(int socket_fd) {
        bool success = true;
        
        // Activer TCP_NODELAY pour réduire la latence
        int nodelay = 1;
        if (setsockopt(socket_fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay)) < 0) {
            success = false;
        }
        
        // Augmenter les buffers de réception et d'envoi
        int rcvbuf = 65536;  // 64KB
        int sndbuf = 65536;  // 64KB
        
        if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
            success = false;
        }
        
        if (setsockopt(socket_fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) < 0) {
            success = false;
        }
        
        // Configurer les timeouts
        struct timeval timeout;
        timeout.tv_sec = 300;  // 5 minutes
        timeout.tv_usec = 0;
        
        if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
            success = false;
        }
        
        if (setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
            success = false;
        }
        
        // Activer SO_KEEPALIVE pour maintenir les connexions
        int keepalive = 1;
        if (setsockopt(socket_fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive)) < 0) {
            success = false;
        }
        
        return success;
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
            success = false;
        }
#endif

#ifdef TCP_KEEPINTVL
        if (setsockopt(socket_fd, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl)) < 0) {
            success = false;
        }
#endif

#ifdef TCP_KEEPCNT
        if (setsockopt(socket_fd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt)) < 0) {
            success = false;
        }
#endif
        
        return success;
    }
};

#endif