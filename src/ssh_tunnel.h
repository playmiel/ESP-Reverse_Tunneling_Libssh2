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
    // Lost write chunks counter on Local->SSH side (diagnostic)
    int lostWriteChunks;
    LIBSSH2_CHANNEL* channel;
    bool active;
    int localSocket; // Local socket for this channel
    unsigned long lastActivity;
    size_t pendingBytes; // Pending bytes waiting to be written
    bool flowControlPaused; // Temporary pause to avoid congestion
    SemaphoreHandle_t readMutex; // Thread-safe protection for read (mutex)
    SemaphoreHandle_t writeMutex; // Thread-safe protection for write (mutex)
    
    // OPTIMIZED: Single circular buffer per direction (removes duplication ring+deferred)
    DataRingBuffer* sshToLocalBuffer;   // SSH->Local (unified)
    DataRingBuffer* localToSshBuffer;   // Local->SSH (unified)
    
    // Statistics and control
    size_t totalBytesReceived; // Per-channel statistics
    size_t totalBytesSent;
    unsigned long lastSuccessfulWrite; // Last successful write
    unsigned long lastSuccessfulRead;  // Last successful read
    bool gracefulClosing; // Closing in progress but with remaining data
    int consecutiveErrors; // Number of consecutive errors
    int eagainErrors; // NEW: Separate counter for EAGAIN errors
    
    // FIXED: New counters for mutex failure diagnostics (non-destructive)
    int readMutexFailures;     // Counter for read mutex timeouts
    int writeMutexFailures;    // Counter for write mutex timeouts  
    
    // Additional counters for fine-grained flow control
    size_t queuedBytesToLocal;   // Bytes in sshToLocalBuffer
    size_t queuedBytesToRemote;  // Bytes in localToSshBuffer
    bool remoteEof;              // Remote side has sent EOF
    
    // NEW: Large transfer detection
    bool largeTransferInProgress; // Large file transfer in progress
    unsigned long transferStartTime; // Start time of current transfer
    size_t transferredBytes;      // Bytes transferred in this transfer
    size_t peakBytesPerSecond;    // Peak throughput for this channel

    // NEW: Health tracking to avoid aggressive recoveries/log spam
    int healthUnhealthyCount;           // consecutive unhealthy detections
    unsigned long lastHardRecoveryMs;   // last time a hard recovery was performed
    unsigned long lastHealthWarnMs;     // last time we logged a WARN for health
    // Error classification & backoff
    int socketRecvErrors;
    int fatalCryptoErrors;
    unsigned long lastWriteErrorMs;
    unsigned long lastErrorDetailLogMs;
    int stuckProbeCount;                // consecutive non-blocking mutex probe failures
    // Socket recv (-43) burst handling
    int socketRecvBurstCount;           // consecutive LIBSSH2_ERROR_SOCKET_RECV without success
    unsigned long firstSocketRecvErrorMs; // timestamp of first error in current burst
    bool terminalSocketFailure;         // channel marked unrecoverable due to persistent -43
    int readProbeFailCount;             // consecutive health-check probe failures (read mutex)
    int writeProbeFailCount;            // consecutive health-check probe failures (write mutex)
    bool localReadTerminated;           // local side no longer readable (socket closed/error)

    // NEW (partial enqueue protection): deferred buffers for residual data that
    // could not be placed into the ring buffers (avoids any data loss).
    uint8_t* deferredToLocal;      // SSH->Local residual awaiting enqueue
    size_t deferredToLocalSize;    // total size of residual
    size_t deferredToLocalOffset;  // already enqueued offset
    uint8_t* deferredToRemote;     // Local->SSH residual awaiting enqueue
    size_t deferredToRemoteSize;
    size_t deferredToRemoteOffset;

    // NEW: Metrics for dropped bytes (only when we truly drop data)
    size_t bytesDropped;          // Per-channel dropped bytes counter
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
    unsigned long getBytesDropped();
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

    // New methods to improve reliability
    bool processChannelRead(int channelIndex);  // SSH -> Local
    bool processChannelWrite(int channelIndex); // Local -> SSH (poll for write)
    void processPendingData(int channelIndex);  // Process pending data (poll for read/write)
    bool queueData(int channelIndex, uint8_t* data, size_t size, bool isRead);
    // New version: returns number of bytes actually enqueued into the ring buffer (0..size).
    // No silent loss: if return < size, caller must store the remainder in deferred buffer.
    size_t queueData(int channelIndex, const uint8_t* data, size_t size, bool isRead);
    void flushPendingData(int channelIndex);
    bool isChannelHealthy(int channelIndex);
    void recoverChannel(int channelIndex);
    void gracefulRecoverChannel(int channelIndex); // NEW: Recovery without clearing buffers
    size_t getOptimalBufferSize(int channelIndex);
    void checkAndRecoverDeadlocks(); // NEW: Deadlock detection and recovery
    // NEW: Dedicated task for data processing (producer/consumer pattern)
    static void dataProcessingTaskWrapper(void* parameter);
    void dataProcessingTaskFunction();
    bool startDataProcessingTask();
    void stopDataProcessingTask();
    
    // NEW: Data duplication diagnostic
    void printDataTransferStats(int channelIndex);
    
    // NEW: Large transfer management and pending connections queue
    bool isLargeTransferActive();
    void detectLargeTransfer(int channelIndex);
    bool shouldAcceptNewConnection();
    void queuePendingConnection(LIBSSH2_CHANNEL* channel);
    bool processPendingConnections();
    bool processQueuedConnection(LIBSSH2_CHANNEL* channel);
    void closeLibssh2Channel(LIBSSH2_CHANNEL* channel);
    bool channelEofLocked(LIBSSH2_CHANNEL* channel);

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

    TunnelChannel* channels; // Dynamic allocation based on config

    TunnelState state;
    unsigned long lastKeepAlive;
    unsigned long lastConnectionAttempt;
    int reconnectAttempts;

    // Statistics
    unsigned long bytesReceived;
    unsigned long bytesSent;
    unsigned long droppedBytes; // NEW: Global dropped bytes (sum of channels)

    // Buffers (dynamic allocation based on config)
    uint8_t* rxBuffer;
    uint8_t* txBuffer;

    // Thread-safe protection
    SemaphoreHandle_t tunnelMutex;
    SemaphoreHandle_t statsMutex;
    SemaphoreHandle_t sessionMutex;

    // Configuration reference
    SSHConfiguration* config;
    
    // NEW: Queue for pending connections during large transfers
    struct PendingConnection {
        LIBSSH2_CHANNEL* channel;
        unsigned long timestamp;
    };
    std::vector<PendingConnection> pendingConnections;
    SemaphoreHandle_t pendingConnectionsMutex;
    
    // OPTIMIZED: Thresholds for large transfer detection and flow control
    static const size_t LARGE_TRANSFER_THRESHOLD = 100 * 1024;  // 100KB
    static const size_t LARGE_TRANSFER_RATE_THRESHOLD = 15 * 1024; // 15KB/s
    static const unsigned long LARGE_TRANSFER_TIME_THRESHOLD = 3000; // 3 seconds
    
    // OPTIMIZED: Higher flow control thresholds
    static const size_t HIGH_WATER_LOCAL = 28 * 1024;  // 28KB (increased)
    static const size_t LOW_WATER_LOCAL = 14 * 1024;   // 14KB (50% of HIGH_WATER)
    static const size_t FIXED_BUFFER_SIZE = 8 * 1024;  // Fixed 8KB buffer
    
    // NEW: Dedicated task for data processing
    TaskHandle_t dataProcessingTask;
    SemaphoreHandle_t dataProcessingSemaphore;
    bool dataProcessingTaskRunning;

    // Protection methods
    bool lockTunnel();
    void unlockTunnel();
    bool lockStats();
    void unlockStats();
    bool lockSession(TickType_t ticks = portMAX_DELAY);
    void unlockSession();

    // Per-channel protection methods with separate mutexes
    bool lockChannelRead(int channelIndex);
    void unlockChannelRead(int channelIndex);
    bool lockChannelWrite(int channelIndex);
    void unlockChannelWrite(int channelIndex);

    // Compatibility methods (deprecated)
    bool lockChannel(int channelIndex);
    void unlockChannel(int channelIndex);
    
    // NEW: Method to force release of blocked mutexes
    void safeRetryMutexAccess(int channelIndex); // FIXED: Safe version instead of forceMutexRelease

    // SSH write/drain tuning parameters
    static constexpr int SSH_MAX_WRITES_PER_PASS = 8;      // Max drain iterations per loop
    static constexpr int MIN_SSH_WINDOW_SIZE = 512;        // Minimum assumed remote window (advisory)
    static constexpr int MIN_WRITE_SIZE = 256;             // Aggregate small chunks to at least this size
};

#endif
