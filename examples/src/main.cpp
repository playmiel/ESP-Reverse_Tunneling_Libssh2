#include <WiFi.h>
#include <Arduino.h>
#include "ESP-Reverse_Tunneling_Libssh2.h"
#include <esp_heap_caps.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

// WiFi configuration
const char* ssid = "YOUR_WIFI_SSID";
const char* password = "YOUR_WIFI_PASSWORD";

// SSH tunnel instance
SSHTunnel tunnel;

// Monitoring variables
unsigned long lastStatsReport = 0;
const unsigned long STATS_INTERVAL = 10000; // 10 seconds

void connectWiFi();
void reportStats();
void configureSSHTunnel();

void setup() {
  Serial.begin(115200);
  while (!Serial) {
    vTaskDelay(pdMS_TO_TICKS(10));
  }

  LOG_I("MAIN", "ESP32 SSH Reverse Tunnel - Enhanced version with dynamic configuration");

  // SSH tunnel configuration
  configureSSHTunnel();

  // WiFi connection
  connectWiFi();

  // SSH tunnel initialization
  if (!tunnel.init()) {
    LOG_E("MAIN", "Failed to initialize SSH tunnel");
    return;
  }

  // Start SSH connection
  if (!tunnel.connectSSH()) {
    LOG_E("MAIN", "Failed to connect SSH tunnel");
  }

  LOG_I("MAIN", "Setup completed successfully");
}

void loop() {
  // Check WiFi connection
  if (WiFi.status() != WL_CONNECTED) {
    LOG_W("MAIN", "WiFi disconnected, reconnecting...");
    connectWiFi();
  }

  // SSH tunnel processing
  tunnel.loop();

  // Statistics report
  reportStats();

  // Use vTaskDelay instead of delay for better FreeRTOS compatibility
  vTaskDelay(pdMS_TO_TICKS(1));
}

void connectWiFi() {
  LOG_I("WIFI", "Connecting to WiFi...");
  WiFi.begin(ssid, password);

  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 30) {
    vTaskDelay(pdMS_TO_TICKS(1000));
    Serial.print(".");
    attempts++;
  }

  if (WiFi.status() == WL_CONNECTED) {
    Serial.println();
    LOG_I("WIFI", "WiFi connected successfully");
    LOGF_I("WIFI", "IP address: %s", WiFi.localIP().toString().c_str());
    LOGF_I("WIFI", "Signal strength: %d dBm", WiFi.RSSI());
  } else {
    LOG_E("WIFI", "Failed to connect to WiFi");
  }
}

void configureSSHTunnel() {
  LOG_I("CONFIG", "Configuring SSH tunnel...");
  
  // ===== METHOD 1: SSH configuration with password =====
  globalSSHConfig.setSSHServer(
  "your-remote-server.com",  // Replace with your server
  22,                        // SSH port
  "your_username",           // Username
  "your_password"            // Password
  );

  // ===== METHOD 2: SSH configuration with key from LittleFS =====
  // This method automatically loads keys from LittleFS into memory
  // globalSSHConfig.setSSHKeyAuth(
  //   "your-remote-server.com",
  //   22,
  //   "your_username",
  //   "/ssh_key",       // Path to private key in LittleFS
  //   ""                // Passphrase for the key (optional)
  // );

  // ===== METHOD 3: SSH configuration with keys directly in memory =====
  // Example RSA private/public key placeholders (DO NOT USE IN PRODUCTION)
  /*
  String privateKey = "PLACEHOLDER_PRIVATE_KEY_EXAMPLE_DO_NOT_USE";
  String publicKey  = "ssh-rsa PLACEHOLDER_PUBLIC_KEY_EXAMPLE_DO_NOT_USE user@host"; // Minimal illustrative form
  globalSSHConfig.setSSHKeyAuthFromMemory(
    "your-remote-server.com",
    22,
    "your_username",
    privateKey,
    publicKey,
    ""  // Passphrase for the key (optional)
  );
  */

  // ===== METHOD 4: Load keys from LittleFS then use them in memory =====
  // Initialize LittleFS if not already done
  // if (!LittleFS.begin(true)) {
  //   LOG_E("CONFIG", "Failed to initialize LittleFS");
  //   return;
  // }
  
  // Manually load keys from LittleFS
  // if (globalSSHConfig.loadSSHKeysFromLittleFS("/ssh_key")) {
  //   LOG_I("CONFIG", "SSH keys loaded from LittleFS and stored in memory");
  // } else {
  //   LOG_E("CONFIG", "Failed to load SSH keys from LittleFS");
  // }
  
  // Tunnel configuration
  globalSSHConfig.setTunnelConfig(
  "0.0.0.0",        // Bind address on remote server
  8080,             // Bind port on remote server
  "192.168.1.100",  // Local address to tunnel
  80                // Local port to tunnel
  );
  
  // Connection configuration
  globalSSHConfig.setConnectionConfig(
  30,    // Keep-alive interval (seconds)
  5000,  // Reconnection delay (ms)
  5,     // Max reconnection attempts
  30     // Connection timeout (seconds)
  );
  
  // Buffer configuration
  globalSSHConfig.setBufferConfig(
    8192,    // Buffer size
    5,       // Max number of channels
    1800000  // Channel timeout (ms) - 30 minutes
  );

  // Channel priority profile (optional tuning)
  globalSSHConfig.setChannelPriorityProfile(
      1,  // Default priority for new channels (0=low, 1=normal, 2=high)
      1,  // Weight applied to low priority channels
      2,  // Weight applied to normal priority channels
      4   // Weight applied to high priority channels
  );

  // Global rate limit (optional, disabled when bytesPerSecond = 0)
  globalSSHConfig.setGlobalRateLimit(
      64 * 1024,  // Bytes per second across all channels
      96 * 1024   // Burst budget (optional); defaults to rate if zero
  );
  
  // Debug configuration
  globalSSHConfig.setDebugConfig(
      true,    // Debug enabled
      115200   // Serial baud rate
  );
  
  LOG_I("CONFIG", "Configuration complete");
}

void reportStats() {
  unsigned long now = millis();
  if (now - lastStatsReport < STATS_INTERVAL) {
    return;
  }

  lastStatsReport = now;

  // Check heap state BEFORE logs
  size_t freeHeap = ESP.getFreeHeap();
  size_t minFreeHeap = ESP.getMinFreeHeap();
  size_t largestFreeBlock = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
  
  // Status report with memory verification
  if (freeHeap > 10000) { // Only if we have enough memory
    LOGF_I("STATS", "Tunnel State: %s", tunnel.getStateString().c_str());
    LOGF_I("STATS", "Active Channels: %d", tunnel.getActiveChannels());
    LOGF_I("STATS", "Bytes Sent: %lu", tunnel.getBytesSent());
    LOGF_I("STATS", "Bytes Received: %lu", tunnel.getBytesReceived());
    LOGF_I("STATS", "Bytes Dropped: %lu", tunnel.getBytesDropped());
  }

  // Throughput calculation (approximate)
  static unsigned long lastBytesSent = 0;
  static unsigned long lastBytesReceived = 0;

  unsigned long bytesSent = tunnel.getBytesSent();
  unsigned long bytesReceived = tunnel.getBytesReceived();
  unsigned long bytesDropped = tunnel.getBytesDropped();

  unsigned long sentRate = (bytesSent - lastBytesSent) * 1000 / STATS_INTERVAL;
  unsigned long receivedRate = (bytesReceived - lastBytesReceived) * 1000 / STATS_INTERVAL;

  if (freeHeap > 8000) { // Reduce logs if low memory
    LOGF_I("STATS", "Send Rate: %lu B/s", sentRate);
    LOGF_I("STATS", "Receive Rate: %lu B/s", receivedRate);
  }

  lastBytesSent = bytesSent;
  lastBytesReceived = bytesReceived;

  // WiFi info (essential)
  LOGF_I("WIFI", "RSSI: %d dBm", WiFi.RSSI());

  // Memory info (critical)
  LOGF_I("SYSTEM", "Free Heap: %d bytes (min: %d, largest: %d)", 
         freeHeap, minFreeHeap, largestFreeBlock);
  LOGF_I("SYSTEM", "Uptime: %lu seconds", millis() / 1000);
  
  // Alert if critical memory
  if (freeHeap < 50000) {
    LOG_W("MEMORY", "LOW HEAP WARNING!");
  }
  
  if (largestFreeBlock < freeHeap / 2) {
    LOG_W("MEMORY", "HEAP FRAGMENTATION DETECTED!");
  }
}
