#ifndef CONFIG_H
#define CONFIG_H

// SSH Server Configuration
#define SSH_HOST "alcante.eu"
#define SSH_PORT 22
#define SSH_USERNAME "jorge"
#define SSH_PASSWORD "PortaLegre7"
// Alternative: use SSH key authentication
#define USE_SSH_KEY false
#define SSH_PRIVATE_KEY_PATH "/littlefs/.ssh/id_ed25519.pub"

// Tunnel Configuration
#define REMOTE_BIND_HOST "0.0.0.0"  // Remote server bind address
#define REMOTE_BIND_PORT 9000       // Remote server bind port
#define LOCAL_HOST "192.168.3.116"  // Local endpoint to tunnel to
#define LOCAL_PORT 80               // Local endpoint port

// Connection Management
#define KEEPALIVE_INTERVAL_SEC 30
#define RECONNECT_DELAY_MS 5000
#define MAX_RECONNECT_ATTEMPTS 5
#define CONNECTION_TIMEOUT_SEC 30

// Buffer Sizes
#define BUFFER_SIZE 8192
#define MAX_CHANNELS 5
#define CHANNEL_TIMEOUT_MS 1800000  // 30 minutes au lieu de 5

// Debug Configuration
#define DEBUG_ENABLED true
#define SERIAL_BAUD_RATE 115200

#endif