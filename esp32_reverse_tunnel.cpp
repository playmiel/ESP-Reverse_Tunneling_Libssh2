#include "config_ssh.h"
#include "logger.h"
#include "ssh_tunnel.h"

// Global objects
SSHTunnel tunnel;

// Status tracking
unsigned long lastStatusUpdate = 0;
unsigned long lastStatsUpdate = 0;

void setup() {
    // Initialize status LED if configured
    #ifdef STATUS_LED_PIN
    pinMode(STATUS_LED_PIN, OUTPUT);
    digitalWrite(STATUS_LED_PIN, LOW);
    #endif
    
    // Initialize logger
    Logger::init();
    LOG_I("MAIN", "ESP32 Reverse SSH Tunnel starting...");
    
    // Print configuration
    LOGF_I("MAIN", "Target: %s@%s:%d", SSH_USERNAME, SSH_HOST, SSH_PORT);
    LOGF_I("MAIN", "Tunnel: %s:%d -> %s:%d", REMOTE_BIND_HOST, REMOTE_BIND_PORT, LOCAL_HOST, LOCAL_PORT);
    
    // Initialize SSH tunnel
    if (!tunnel.init()) {
        LOG_E("MAIN", "Failed to initialize SSH tunnel");
        return;
    }
    
    LOG_I("MAIN", "Initialization complete");
}

void loop() {
    unsigned long now = millis();
    
    // Update status LED
    updateStatusLED();
    
    // Handle SSH tunnel
    if (!tunnel.isConnected()) {
        // Attempt to connect tunnel
        tunnel.connect();
    } else {
        // Run tunnel loop
        tunnel.loop();
    }
    
    // Print status updates
    if (now - lastStatusUpdate > 30000) { // Every 30 seconds
        printStatus();
        lastStatusUpdate = now;
    }
    
    // Print statistics
    if (now - lastStatsUpdate > 60000) { // Every minute
        printStatistics();
        lastStatsUpdate = now;
    }
    
    // Small delay to prevent tight loop
    delay(10);
}

void updateStatusLED() {
    #ifdef STATUS_LED_PIN
    static unsigned long lastBlink = 0;
    static bool ledState = false;
    unsigned long now = millis();
    
    TunnelState state = tunnel.getState();
    
    switch (state) {
        case TUNNEL_DISCONNECTED:
            // Slow blink - disconnected
            if (now - lastBlink > 1000) {
                ledState = !ledState;
                digitalWrite(STATUS_LED_PIN, ledState);
                lastBlink = now;
            }
            break;
            
        case TUNNEL_CONNECTING:
            // Fast blink - connecting
            if (now - lastBlink > 200) {
                ledState = !ledState;
                digitalWrite(STATUS_LED_PIN, ledState);
                lastBlink = now;
            }
            break;
            
        case TUNNEL_CONNECTED:
            // Solid on - connected
            digitalWrite(STATUS_LED_PIN, HIGH);
            break;
            
        case TUNNEL_ERROR:
            // Very fast blink - error
            if (now - lastBlink > 100) {
                ledState = !ledState;
                digitalWrite(STATUS_LED_PIN, ledState);
                lastBlink = now;
            }
            break;
    }
    #endif
}

void printStatus() {
    LOG_I("STATUS", "=== System Status ===");
    
    // Tunnel status
    LOGF_I("STATUS", "Tunnel: %s", tunnel.getStateString().c_str());
    LOGF_I("STATUS", "Active channels: %d", tunnel.getActiveChannels());
    
    // Memory status
    LOGF_I("STATUS", "Free heap: %d bytes", ESP.getFreeHeap());
    LOGF_I("STATUS", "Uptime: %lu seconds", millis() / 1000);
}

void printStatistics() {
    if (!tunnel.isConnected()) {
        return;
    }
    
    LOG_I("STATS", "=== Transfer Statistics ===");
    LOGF_I("STATS", "Bytes received: %lu", tunnel.getBytesReceived());
    LOGF_I("STATS", "Bytes sent: %lu", tunnel.getBytesSent());
    LOGF_I("STATS", "Total transferred: %lu", tunnel.getBytesReceived() + tunnel.getBytesSent());
}

// Error handling function
void handleError(const char* context, const char* error) {
    LOGF_E("ERROR", "%s: %s", context, error);
    
    // Could implement additional error handling here:
    // - Send error notifications
    // - Reset system if critical
    // - Log to persistent storage
}

// Watchdog reset function (if needed)
void resetSystem() {
    LOG_E("MAIN", "System reset requested");
    delay(1000);
    ESP.restart();
}
