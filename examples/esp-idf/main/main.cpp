#include "ESP-Reverse_Tunneling_Libssh2.h"
#include <cstring>
#include <esp_err.h>
#include <esp_event.h>
#include <esp_netif.h>
#include <esp_wifi.h>
#include <freertos/FreeRTOS.h>
#include <freertos/event_groups.h>
#include <freertos/task.h>
#include <nvs_flash.h>

namespace {
EventGroupHandle_t wifiEvents;
constexpr EventBits_t connected = BIT0;

void onWifiEvent(void *, esp_event_base_t base, int32_t id, void *) {
  if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
    esp_wifi_connect();
  } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
    xEventGroupClearBits(wifiEvents, connected);
    esp_wifi_connect();
  } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
    xEventGroupSetBits(wifiEvents, connected);
  }
}
} // namespace

extern "C" void app_main() {
  esp_err_t nvsResult = nvs_flash_init();
  if (nvsResult == ESP_ERR_NVS_NO_FREE_PAGES ||
      nvsResult == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    nvsResult = nvs_flash_init();
  }
  ESP_ERROR_CHECK(nvsResult);
  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());
  esp_netif_create_default_wifi_sta();
  wifiEvents = xEventGroupCreate();

  wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&init));
  ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                             onWifiEvent, nullptr));
  ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                             onWifiEvent, nullptr));
  wifi_config_t wifi = {};
  std::strncpy(reinterpret_cast<char *>(wifi.sta.ssid), CONFIG_EXAMPLE_WIFI_SSID,
               sizeof(wifi.sta.ssid) - 1);
  std::strncpy(reinterpret_cast<char *>(wifi.sta.password),
               CONFIG_EXAMPLE_WIFI_PASSWORD, sizeof(wifi.sta.password) - 1);
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
  ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi));
  ESP_ERROR_CHECK(esp_wifi_start());
  xEventGroupWaitBits(wifiEvents, connected, pdFALSE, pdTRUE, portMAX_DELAY);

  globalSSHConfig.setSSHServer(CONFIG_EXAMPLE_SSH_HOST, 22,
                               CONFIG_EXAMPLE_SSH_USER,
                               CONFIG_EXAMPLE_SSH_PASSWORD);
  globalSSHConfig.setHostKeyVerification(
      CONFIG_EXAMPLE_SSH_HOSTKEY_SHA256, "", true);
  globalSSHConfig.setTunnelConfig("127.0.0.1", 8080, "127.0.0.1", 80);
  SSHTunnel tunnel;
  if (!tunnel.init()) return;
  for (;;) {
    if (xEventGroupGetBits(wifiEvents) & connected) tunnel.loop();
    vTaskDelay(pdMS_TO_TICKS(10));
  }
}
