#ifndef SSH_TUNNEL_H
#define SSH_TUNNEL_H

#include <libssh2_esp.h>
#include "ssh_config.h"
#include "logger.h"
#include "memory_fixes.h"
#include "ring_buffer.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include "lwip/netdb.h"
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <freertos/task.h>
#include <vector>

enum TunnelState {
    TUNNEL_DISCONNECTED = 0,
    TUNNEL_CONNECTING = 1,
    TUNNEL_CONNECTED = 2,
    TUNNEL_ERROR = 3
};

struct TunnelChannel {
    // Compteur de chunks perdus côté Local->SSH (diagnostic)
    int lostWriteChunks;
    LIBSSH2_CHANNEL* channel;
    bool active;
    int localSocket; // Local socket for this channel
    unsigned long lastActivity;
    size_t pendingBytes; // Données en attente d'écriture
    bool flowControlPaused; // Pause temporaire pour éviter la congestion
    SemaphoreHandle_t readMutex; // Protection thread-safe pour la lecture
    SemaphoreHandle_t writeMutex; // Protection thread-safe pour l'écriture
    
    // NOUVEAU: Ring buffers remplacent les std::queue et buffers différés
    PendingDataRing* writeRing;     // SSH->Local (remplace pendingWriteQueue)
    PendingDataRing* readRing;      // Local->SSH (remplace pendingReadQueue)
    DataRingBuffer* deferredWriteRing; // Buffer continu Local->SSH
    DataRingBuffer* deferredReadRing;  // Buffer continu SSH->Local
    
    // Statistiques et contrôle
    size_t totalBytesReceived; // Statistiques par canal
    size_t totalBytesSent;
    unsigned long lastSuccessfulWrite; // Dernière écriture réussie
    unsigned long lastSuccessfulRead;  // Dernière lecture réussie
    bool gracefulClosing; // Fermeture en cours mais avec données restantes
    int consecutiveErrors; // Nombre d'erreurs consécutives
    // Compteurs supplémentaires pour gestion fine du flow control
    size_t queuedBytesToLocal;   // Somme des bytes dans writeRing
    size_t queuedBytesToRemote;  // Somme des bytes dans readRing
    
    // NOUVEAU: Détection des gros transferts
    bool largeTransferInProgress; // Transfert de gros fichier en cours
    unsigned long transferStartTime; // Début du transfert actuel
    size_t transferredBytes;      // Bytes transférés dans ce transfert
    size_t peakBytesPerSecond;    // Pic de débit pour ce canal
};

class SSHTunnel {
public:
    SSHTunnel();
    ~SSHTunnel();
    
    bool init();
    bool connectSSH();
    void disconnect();
    bool isConnected();
    void loop();
    TunnelState getState();
    String getStateString();
    
    // Statistics
    unsigned long getBytesReceived();
    unsigned long getBytesSent();
    int getActiveChannels();

private:
    // SSH connection management
    bool initializeSSH();
    bool authenticateSSH();
    bool verifyHostKey();
    bool createReverseTunnel();
    void cleanupSSH();

    // Channel management
    bool handleNewConnection();
    void handleChannelData(int channelIndex);
    void closeChannel(int channelIndex);
    void cleanupInactiveChannels();
    void printChannelStatistics();

    // Nouvelles méthodes pour améliorer la fiabilité
    bool processChannelRead(int channelIndex);  // SSH -> Local
    bool processChannelWrite(int channelIndex); // Local -> SSH (poll pour écriture)
    void processPendingData(int channelIndex);  // Traiter les données en attente (poll pour lecture/écriture)
    bool queueData(int channelIndex, uint8_t* data, size_t size, bool isRead);
    void flushPendingData(int channelIndex);
    bool isChannelHealthy(int channelIndex);
    void recoverChannel(int channelIndex);
    size_t getOptimalBufferSize(int channelIndex);
    void checkAndRecoverDeadlocks(); // NOUVEAU: Détection et récupération des deadlocks
    
    // NOUVEAU: Diagnostic de duplication de données
    void printDataTransferStats(int channelIndex);
    
    // NOUVEAU: Gestion des gros transferts et file d'attente des connexions
    bool isLargeTransferActive();
    void detectLargeTransfer(int channelIndex);
    bool shouldAcceptNewConnection();
    void queuePendingConnection(LIBSSH2_CHANNEL* channel);
    bool processPendingConnections();
    bool processQueuedConnection(LIBSSH2_CHANNEL* channel);

    // Poll helpers
    bool isSocketWritable(int sockfd, int timeoutMs = 0);
    bool isSocketReadable(int sockfd, int timeoutMs = 0);

    // Connection monitoring
    void sendKeepAlive();
    bool checkConnection();
    void handleReconnection();

    // Utility functions
    static int socketCallback(LIBSSH2_SESSION* session, libssh2_socket_t fd, void** abstract);

    // Member variables
    LIBSSH2_SESSION* session;
    LIBSSH2_LISTENER* listener;
    int socketfd;

    TunnelChannel* channels; // Allocation dynamique basée sur la config

    TunnelState state;
    unsigned long lastKeepAlive;
    unsigned long lastConnectionAttempt;
    int reconnectAttempts;

    // Statistics
    unsigned long bytesReceived;
    unsigned long bytesSent;

    // Buffers (allocation dynamique basée sur la config)
    uint8_t* rxBuffer;
    uint8_t* txBuffer;

    // Protection thread-safe
    SemaphoreHandle_t tunnelMutex;
    SemaphoreHandle_t statsMutex;

    // Configuration reference
    SSHConfiguration* config;
    
    // NOUVEAU: File d'attente pour les connexions en attente pendant les gros transferts
    struct PendingConnection {
        LIBSSH2_CHANNEL* channel;
        unsigned long timestamp;
    };
    std::vector<PendingConnection> pendingConnections;
    SemaphoreHandle_t pendingConnectionsMutex;
    
    // NOUVEAU: Seuils pour la détection des gros transferts
    static const size_t LARGE_TRANSFER_THRESHOLD = 100 * 1024;  // 100KB (augmenté de 50KB)
    static const size_t LARGE_TRANSFER_RATE_THRESHOLD = 15 * 1024; // 15KB/s (augmenté de 10KB/s)
    static const unsigned long LARGE_TRANSFER_TIME_THRESHOLD = 3000; // 3 secondes (réduit de 5s)

    // Méthodes de protection
    bool lockTunnel();
    void unlockTunnel();
    bool lockStats();
    void unlockStats();

    // Méthodes de protection par canal avec mutex séparés
    bool lockChannelRead(int channelIndex);
    void unlockChannelRead(int channelIndex);
    bool lockChannelWrite(int channelIndex);
    void unlockChannelWrite(int channelIndex);

    // Méthodes de compatibilité (deprecated)
    bool lockChannel(int channelIndex);
    void unlockChannel(int channelIndex);
};

#endif