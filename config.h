#ifndef CONFIG_H
#define CONFIG_H

// WiFi Configuration
#define WIFI_SSID "YOUR_WIFI_SSID"
#define WIFI_PASSWORD "YOUR_WIFI_PASSWORD"
#define WIFI_TIMEOUT_MS 20000

// SSH Server Configuration
#define SSH_HOST "your-remote-server.com"
#define SSH_PORT 22
#define SSH_USERNAME "your_username"
#define SSH_PASSWORD "your_password"
// Alternative: use SSH key authentication
#define USE_SSH_KEY false
#define SSH_PRIVATE_KEY_PATH "/ssh_key"

// Tunnel Configuration
#define REMOTE_BIND_HOST "0.0.0.0"  // Remote server bind address
#define REMOTE_BIND_PORT 8080       // Remote server bind port
#define LOCAL_HOST "192.168.1.100"  // Local endpoint to tunnel to
#define LOCAL_PORT 80               // Local endpoint port

// Connection Management
#define KEEPALIVE_INTERVAL_SEC 30
#define RECONNECT_DELAY_MS 5000
#define MAX_RECONNECT_ATTEMPTS 5
#define CONNECTION_TIMEOUT_SEC 30

// Buffer Sizes
#define BUFFER_SIZE 1024
#define MAX_CHANNELS 5

// Status LED Pin (optional)
#define STATUS_LED_PIN 2

// Debug Configuration
#define DEBUG_ENABLED true
#define SERIAL_BAUD_RATE 115200

#endif
