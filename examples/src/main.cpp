#include <WiFi.h>
#include <Arduino.h>
#include "ESP-Reverse_Tunneling_Libssh2.h"
#include <esp_heap_caps.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

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
    vTaskDelay(pdMS_TO_TICKS(10));
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

  // Utiliser vTaskDelay au lieu de delay pour être plus compatible FreeRTOS
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
  LOG_I("CONFIG", "Configuration du tunnel SSH...");
  
  // ===== MÉTHODE 1: Configuration SSH avec mot de passe =====
  globalSSHConfig.setSSHServer(
    "your-remote-server.com",  // Remplacez par votre serveur
    22,                        // Port SSH
    "your_username",           // Nom d'utilisateur
    "your_password"            // Mot de passe
  );

  // ===== MÉTHODE 2: Configuration SSH avec clé depuis LittleFS =====
  // Cette méthode charge automatiquement les clés depuis LittleFS en mémoire
  // globalSSHConfig.setSSHKeyAuth(
  //   "your-remote-server.com",
  //   22,
  //   "your_username",
  //   "/ssh_key",       // Chemin vers la clé privée dans LittleFS
  //   ""                // Passphrase pour la clé (optionnel)
  // );

  // ===== MÉTHODE 3: Configuration SSH avec clés directement en mémoire =====
  // Exemple de clé privée RSA (à remplacer par votre vraie clé)
  /*
  String privateKey = R"(-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEA... (votre clé privée ici)
-----END OPENSSH PRIVATE KEY-----)";
  
  String publicKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB... (votre clé publique ici) user@host";
  
  globalSSHConfig.setSSHKeyAuthFromMemory(
    "your-remote-server.com",
    22,
    "your_username",
    privateKey,
    publicKey,
    ""  // Passphrase pour la clé (optionnel)
  );
  */

  // ===== MÉTHODE 4: Charger les clés depuis LittleFS puis les utiliser en mémoire =====
  // Initialiser LittleFS si pas encore fait
  // if (!LittleFS.begin(true)) {
  //   LOG_E("CONFIG", "Failed to initialize LittleFS");
  //   return;
  // }
  
  // Charger manuellement les clés depuis LittleFS
  // if (globalSSHConfig.loadSSHKeysFromLittleFS("/ssh_key")) {
  //   LOG_I("CONFIG", "SSH keys loaded from LittleFS and stored in memory");
  // } else {
  //   LOG_E("CONFIG", "Failed to load SSH keys from LittleFS");
  // }
  
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

  // Vérification de l'état de la heap AVANT les logs
  size_t freeHeap = ESP.getFreeHeap();
  size_t minFreeHeap = ESP.getMinFreeHeap();
  size_t largestFreeBlock = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
  
  // Rapport de statut avec vérification mémoire
  if (freeHeap > 10000) { // Seulement si on a assez de mémoire
    LOGF_I("STATS", "Tunnel State: %s", tunnel.getStateString().c_str());
    LOGF_I("STATS", "Active Channels: %d", tunnel.getActiveChannels());
    LOGF_I("STATS", "Bytes Sent: %lu", tunnel.getBytesSent());
    LOGF_I("STATS", "Bytes Received: %lu", tunnel.getBytesReceived());
  }

  // Calcul du débit (approximatif)
  static unsigned long lastBytesSent = 0;
  static unsigned long lastBytesReceived = 0;

  unsigned long bytesSent = tunnel.getBytesSent();
  unsigned long bytesReceived = tunnel.getBytesReceived();

  unsigned long sentRate = (bytesSent - lastBytesSent) * 1000 / STATS_INTERVAL;
  unsigned long receivedRate = (bytesReceived - lastBytesReceived) * 1000 / STATS_INTERVAL;

  if (freeHeap > 8000) { // Réduire les logs si mémoire faible
    LOGF_I("STATS", "Send Rate: %lu B/s", sentRate);
    LOGF_I("STATS", "Receive Rate: %lu B/s", receivedRate);
  }

  lastBytesSent = bytesSent;
  lastBytesReceived = bytesReceived;

  // Information WiFi (essentiel)
  LOGF_I("WIFI", "RSSI: %d dBm", WiFi.RSSI());

  // Information mémoire (critique)
  LOGF_I("SYSTEM", "Free Heap: %d bytes (min: %d, largest: %d)", 
         freeHeap, minFreeHeap, largestFreeBlock);
  LOGF_I("SYSTEM", "Uptime: %lu seconds", millis() / 1000);
  
  // Alerte si mémoire critique
  if (freeHeap < 50000) {
    LOG_W("MEMORY", "LOW HEAP WARNING!");
  }
  
  if (largestFreeBlock < freeHeap / 2) {
    LOG_W("MEMORY", "HEAP FRAGMENTATION DETECTED!");
  }
}
