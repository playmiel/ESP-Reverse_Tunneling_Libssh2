# ESP-IDF example

```bash
git submodule update --init --recursive
cd examples/esp-idf
idf.py set-target esp32
idf.py menuconfig
idf.py build flash monitor
```

Set the Wi-Fi SSID/password, SSH host/user/password, and verified SHA256 host
key fingerprint under **Reverse tunnel example** in menuconfig. The example
forwards remote `127.0.0.1:8080` to the ESP32's local `127.0.0.1:80`.
The local destination must be listening before opening a forwarded connection.
