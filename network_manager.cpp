#include "network_manager.h"

bool NetworkManager::connected = false;
unsigned long NetworkManager::lastConnectionAttempt = 0;

bool NetworkManager::init() {
    WiFi.mode(WIFI_STA);
    WiFi.onEvent(onWiFiEvent);
    LOG_I("NET", "Network manager initialized");
    return true;
}

bool NetworkManager::connect() {
    if (isConnected()) {
        return true;
    }
    
    unsigned long now = millis();
    if (now - lastConnectionAttempt < 5000) {
        return false; // Avoid rapid reconnection attempts
    }
    
    lastConnectionAttempt = now;
    
    LOG_I("NET", "Connecting to WiFi...");
    LOGF_I("NET", "SSID: %s", WIFI_SSID);
    
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    
    unsigned long startTime = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - startTime < WIFI_TIMEOUT_MS) {
        delay(500);
        Serial.print(".");
    }
    Serial.println();
    
    if (WiFi.status() == WL_CONNECTED) {
        connected = true;
        LOGF_I("NET", "WiFi connected! IP: %s", WiFi.localIP().toString().c_str());
        LOGF_I("NET", "Signal strength: %d dBm", WiFi.RSSI());
        return true;
    } else {
        LOG_E("NET", "WiFi connection failed");
        return false;
    }
}

bool NetworkManager::isConnected() {
    return WiFi.status() == WL_CONNECTED && connected;
}

void NetworkManager::disconnect() {
    WiFi.disconnect();
    connected = false;
    LOG_I("NET", "WiFi disconnected");
}

void NetworkManager::handleEvents() {
    // Handle any periodic network tasks
    static unsigned long lastCheck = 0;
    unsigned long now = millis();
    
    if (now - lastCheck > 10000) { // Check every 10 seconds
        lastCheck = now;
        
        if (!isConnected()) {
            LOG_W("NET", "WiFi connection lost, attempting reconnection...");
            connect();
        }
    }
}

String NetworkManager::getLocalIP() {
    return WiFi.localIP().toString();
}

int NetworkManager::getSignalStrength() {
    return WiFi.RSSI();
}

void NetworkManager::onWiFiEvent(WiFiEvent_t event) {
    switch (event) {
        case SYSTEM_EVENT_STA_CONNECTED:
            LOG_I("NET", "WiFi station connected");
            break;
        case SYSTEM_EVENT_STA_GOT_IP:
            connected = true;
            LOGF_I("NET", "Got IP address: %s", WiFi.localIP().toString().c_str());
            break;
        case SYSTEM_EVENT_STA_DISCONNECTED:
            connected = false;
            LOG_W("NET", "WiFi station disconnected");
            break;
        default:
            break;
    }
}
