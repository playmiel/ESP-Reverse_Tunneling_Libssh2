#include <WiFi.h>
#include <Arduino.h>
#include "ESP-Reverse_Tunneling_Libssh2.h"
#include "ssh_tunnel.h"
#include "ssh_config.h"
#include "logger.h"

// Configuration WiFi
const char* ssid = "YOUR_WIFI_SSID";
const char* password = "YOUR_WIFI_PASSWORD";

// Instance du tunnel SSH
SSHTunnel tunnel;

// Variables pour le monitoring
unsigned long lastStatsReport = 0;
const unsigned long STATS_INTERVAL = 10000; // 10 secondes

void connectWiFi();
void reportStats();
void configureSSHTunnel();

void setup() {
  Serial.begin(115200);
  while (!Serial) {
    delay(10);
  }

  LOG_I("MAIN", "ESP32 SSH Reverse Tunnel - Version améliorée avec configuration dynamique");

  // Configuration du tunnel SSH
  configureSSHTunnel();

  // Connexion WiFi
  connectWiFi();

  // Initialisation du tunnel SSH
  if (!tunnel.init()) {
    LOG_E("MAIN", "Failed to initialize SSH tunnel");
    return;
  }

  // Démarrage de la connexion SSH
  if (!tunnel.connectSSH()) {
    LOG_E("MAIN", "Failed to connect SSH tunnel");
  }

  LOG_I("MAIN", "Setup completed successfully");
}

void loop() {
  // Vérifier la connexion WiFi
  if (WiFi.status() != WL_CONNECTED) {
    LOG_W("MAIN", "WiFi disconnected, reconnecting...");
    connectWiFi();
  }

  // Traitement du tunnel SSH
  tunnel.loop();

  // Rapport de statistiques
  reportStats();

  // Petit délai pour éviter la surcharge CPU
  delay(1);
}

void connectWiFi() {
  LOG_I("WIFI", "Connecting to WiFi...");
  WiFi.begin(ssid, password);

  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 30) {
    delay(1000);
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
  LOG_I("CONFIG", "Configuration du tunnel SSH...");
  
  // Configuration du serveur SSH
  globalSSHConfig.setSSHServer(
    "your-remote-server.com",  // Remplacez par votre serveur
    22,                        // Port SSH
    "your_username",           // Nom d'utilisateur
    "your_password"            // Mot de passe
  );
  
  // Alternative: Configuration avec clé SSH
  // globalSSHConfig.setSSHKeyAuth(
  //   "your-remote-server.com",
  //   22,
  //   "your_username",
  //   "/ssh_key",
  //   ""  // Passphrase pour la clé (optionnel)
  // );
  
  // Configuration du tunnel
  globalSSHConfig.setTunnelConfig(
    "0.0.0.0",        // Adresse de bind sur le serveur distant
    8080,             // Port de bind sur le serveur distant
    "192.168.1.100",  // Adresse locale à tunneler
    80                // Port local à tunneler
  );
  
  // Configuration de la connexion
  globalSSHConfig.setConnectionConfig(
    30,    // Intervalle keep-alive (secondes)
    5000,  // Délai de reconnexion (ms)
    5,     // Nombre max de tentatives de reconnexion
    30     // Timeout de connexion (secondes)
  );
  
  // Configuration des buffers
  globalSSHConfig.setBufferConfig(
    8192,    // Taille des buffers
    5,       // Nombre max de canaux
    1800000  // Timeout des canaux (ms) - 30 minutes
  );
  
  // Configuration du debug
  globalSSHConfig.setDebugConfig(
    true,   // Debug activé
    115200  // Baud rate série
  );
  
  LOG_I("CONFIG", "Configuration terminée");
}

void reportStats() {
  unsigned long now = millis();
  if (now - lastStatsReport < STATS_INTERVAL) {
    return;
  }

  lastStatsReport = now;

  // Rapport de statut
  LOGF_I("STATS", "Tunnel State: %s", tunnel.getStateString().c_str());
  LOGF_I("STATS", "Active Channels: %d", tunnel.getActiveChannels());
  LOGF_I("STATS", "Bytes Sent: %lu", tunnel.getBytesSent());
  LOGF_I("STATS", "Bytes Received: %lu", tunnel.getBytesReceived());

  // Calcul du débit (approximatif)
  static unsigned long lastBytesSent = 0;
  static unsigned long lastBytesReceived = 0;

  unsigned long bytesSent = tunnel.getBytesSent();
  unsigned long bytesReceived = tunnel.getBytesReceived();

  unsigned long sentRate = (bytesSent - lastBytesSent) * 1000 / STATS_INTERVAL;
  unsigned long receivedRate = (bytesReceived - lastBytesReceived) * 1000 / STATS_INTERVAL;

  LOGF_I("STATS", "Send Rate: %lu B/s", sentRate);
  LOGF_I("STATS", "Receive Rate: %lu B/s", receivedRate);

  lastBytesSent = bytesSent;
  lastBytesReceived = bytesReceived;

  // Information WiFi
  LOGF_I("WIFI", "RSSI: %d dBm", WiFi.RSSI());

  // Information mémoire
  LOGF_I("SYSTEM", "Free Heap: %d bytes", ESP.getFreeHeap());
  LOGF_I("SYSTEM", "Uptime: %lu seconds", millis() / 1000);
}
