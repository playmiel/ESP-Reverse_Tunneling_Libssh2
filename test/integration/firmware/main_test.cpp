// Test firmware for the integration harness. Emits one machine-parsable
// line per second prefixed STATS_TEST so the Python harness can read the
// ESP32's view of the tunnel state without log noise.
//
// All credentials and the docker host IP come from build flags
// (see [env:test_integration] in platformio.ini).

#include "ESP-Reverse_Tunneling_Libssh2.h"
#include <Arduino.h>
#include <WiFi.h>
#include <esp_heap_caps.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#ifndef WIFI_SSID
#error "WIFI_SSID must be defined via -D"
#endif
#ifndef WIFI_PASS
#error "WIFI_PASS must be defined via -D"
#endif
#ifndef DOCKER_HOST_IP
#error "DOCKER_HOST_IP must be defined via -D"
#endif

static constexpr unsigned long STATS_INTERVAL_MS = 1000;

SSHTunnel tunnel;
unsigned long lastStatsReport = 0;

void setup() {
  Serial.begin(115200);
  while (!Serial) {
    vTaskDelay(pdMS_TO_TICKS(10));
  }

  Serial.println("BOOT_TEST firmware=main_test");

  // SSH server: testuser@DOCKER_HOST_IP:2222 (password testpass)
  globalSSHConfig.setSSHServer(DOCKER_HOST_IP, 2222, "testuser", "testpass");

  // Three tunnel mappings (must match harness expectations):
  //   22080 -> DOCKER_HOST_IP:9000  (echo, used by tests A/B/D/F)
  //   22081 -> DOCKER_HOST_IP:9001  (slow_echo, used by test G2)
  //   22082 -> DOCKER_HOST_IP:65500 (dead port, used by test G1)
  globalSSHConfig.clearTunnelMappings();
  globalSSHConfig.setMaxReverseListeners(3);
  globalSSHConfig.addTunnelMapping("127.0.0.1", 22080, DOCKER_HOST_IP, 9000);
  globalSSHConfig.addTunnelMapping("127.0.0.1", 22081, DOCKER_HOST_IP, 9001);
  globalSSHConfig.addTunnelMapping("127.0.0.1", 22082, DOCKER_HOST_IP, 65500);

  globalSSHConfig.setConnectionConfig(30, 5000, 100, 30);
  // Default 64KB ring buffers — BOARD_HAS_PSRAM is set in platformio.ini
  // so the storage lives in PSRAM, not internal heap.
  globalSSHConfig.setBufferConfig(8192, 5, 1800000, 64 * 1024);
  globalSSHConfig.setDebugConfig(true, 115200);

  WiFi.begin(WIFI_SSID, WIFI_PASS);
  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 30) {
    vTaskDelay(pdMS_TO_TICKS(1000));
    Serial.print(".");
    attempts++;
  }
  Serial.println();
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("WIFI_FAIL");
    return;
  }
  Serial.printf("WIFI_OK ip=%s rssi=%d\n",
                WiFi.localIP().toString().c_str(), WiFi.RSSI());

  if (!tunnel.init() || !tunnel.connectSSH()) {
    Serial.println("TUNNEL_INIT_FAIL");
    return;
  }
  Serial.println("TUNNEL_INIT_OK");
}

void loop() {
  if (WiFi.status() != WL_CONNECTED) {
    WiFi.reconnect();
    vTaskDelay(pdMS_TO_TICKS(500));
    return;
  }

  tunnel.loop();

  unsigned long now = millis();
  if (now - lastStatsReport >= STATS_INTERVAL_MS) {
    lastStatsReport = now;
    size_t freeHeap = ESP.getFreeHeap();
    size_t minHeap = ESP.getMinFreeHeap();
    size_t largest = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);

    Serial.printf(
        "STATS_TEST t=%lu state=%s ch=%d sent=%lu recv=%lu dropped=%lu "
        "heap=%u minheap=%u largest=%u breaker_trips=%lu\n",
        now, tunnel.getStateString().c_str(), tunnel.getActiveChannels(),
        tunnel.getBytesSent(), tunnel.getBytesReceived(),
        tunnel.getBytesDropped(), (unsigned)freeHeap, (unsigned)minHeap,
        (unsigned)largest, tunnel.getBreakerTrips());
  }

  vTaskDelay(pdMS_TO_TICKS(1));
}
