#ifndef NETWORK_MANAGER_H
#define NETWORK_MANAGER_H

#include <WiFi.h>
#include "config.h"
#include "logger.h"

class NetworkManager {
public:
    static bool init();
    static bool connect();
    static bool isConnected();
    static void disconnect();
    static void handleEvents();
    static String getLocalIP();
    static int getSignalStrength();

private:
    static void onWiFiEvent(WiFiEvent_t event);
    static bool connected;
    static unsigned long lastConnectionAttempt;
};

#endif
