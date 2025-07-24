#include <WiFi.h>
#include <Arduino.h>
#include "ESP-Reverse_Tunneling_Libssh2.h"
#include "ssh_tunnel.h"
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
void updateStatusLED();
void reportStats();

void setup() {
  Serial.begin(SERIAL_BAUD_RATE);
  while (!Serial) {
    delay(10);
  }

  LOG_I("MAIN", "ESP32 SSH Reverse Tunnel - Version optimisée");
  LOGF_I("MAIN", "Buffer size: %d bytes", BUFFER_SIZE);
  LOGF_I("MAIN", "Max channels: %d", MAX_CHANNELS);

  // Configuration LED de statut
#ifdef STATUS_LED_PIN
  pinMode(STATUS_LED_PIN, OUTPUT);
  digitalWrite(STATUS_LED_PIN, LOW);
#endif

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

  // Mise à jour LED de statut
  updateStatusLED();

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

void updateStatusLED() {
#ifdef STATUS_LED_PIN
  static unsigned long lastBlink = 0;
  static bool ledState = false;
  unsigned long now = millis();

  switch (tunnel.getState()) {
    case TUNNEL_DISCONNECTED:
      // LED éteinte
      digitalWrite(STATUS_LED_PIN, LOW);
      break;

    case TUNNEL_CONNECTING:
      // LED clignote rapidement
      if (now - lastBlink > 200) {
        ledState = !ledState;
        digitalWrite(STATUS_LED_PIN, ledState);
        lastBlink = now;
      }
      break;

    case TUNNEL_CONNECTED:
      // LED allumée fixe
      digitalWrite(STATUS_LED_PIN, HIGH);
      break;

    case TUNNEL_ERROR:
      // LED clignote lentement
      if (now - lastBlink > 1000) {
        ledState = !ledState;
        digitalWrite(STATUS_LED_PIN, ledState);
        lastBlink = now;
      }
      break;
  }
#endif
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
