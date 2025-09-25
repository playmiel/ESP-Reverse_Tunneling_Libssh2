# Examples - ESP-Reverse_Tunneling_Libssh2

This directory contains example implementations for the ESP32 SSH Reverse Tunneling library.

## 📁 Example Files Structure

### PlatformIO Example (Recommended)
- **File**: [`src/main.cpp`](src/main.cpp)
- **Platform**: PlatformIO
- **Compilation**: Automatically compiled when running `pio run` in this directory
- **Features**: 
  - Advanced logging with LOGF_I macros
  - Complete PlatformIO integration
  - Optimized memory usage reporting
  - Status LED management

### Arduino IDE Example
- **File**: [`esp32_reverse_tunnel_example.ino`](esp32_reverse_tunnel_example.ino)
- **Platform**: Arduino IDE
- **Compilation**: Open directly in Arduino IDE
- **Features**:
  - Arduino IDE compatible
  - Simplified logging
  - Same core functionality as PlatformIO version

## 🔧 Which Example is Compiled?

**Important**: When using PlatformIO commands:
```bash
cd examples
pio run          # Compiles src/main.cpp (NOT the .ino file)
```

The PlatformIO build system automatically uses `src/main.cpp` and ignores `.ino` files.

## 🚀 Quick Start

### Using PlatformIO (Recommended)

1. **Navigate to examples directory**:
   ```bash
   cd examples
   ```

2. **If you encounter compilation errors**, run the fix script:
   ```bash
   ../fix_libssh2_simple.sh
   ```

3. **Compile and upload**:
   ```bash
   pio run                    # Compile
   pio run --target upload    # Upload to ESP32
   pio device monitor         # Monitor serial output
   ```

### Using Arduino IDE

1. **Open the .ino file**:
   - Open [`esp32_reverse_tunnel_example.ino`](esp32_reverse_tunnel_example.ino) in Arduino IDE

2. **Install dependencies**:
   - Add the libssh2_esp library manually or use Library Manager

3. **Configure and upload**:
   - Select ESP32 board
   - Configure WiFi credentials in the code
   - Upload to your ESP32

## ⚙️ Configuration

### WiFi Settings
Edit these lines in either example file:
```cpp
const char* ssid = "YOUR_WIFI_SSID";
const char* password = "YOUR_WIFI_PASSWORD";
```

### SSH Server Settings
Configure your SSH server details in the library configuration files.

## 📊 Expected Output

After successful compilation and upload, you should see:
```
ESP32 SSH Reverse Tunnel - Optimized Version
Buffer size: 4096 bytes
Max channels: 10
WiFi connected successfully
IP address: 192.168.1.xxx
SSH tunnel initialized successfully
```

## 🔍 Memory Usage

The example provides real-time memory monitoring:
```
Free Heap: xxxxx bytes
Tunnel State: CONNECTED
Active Channels: x
Bytes Sent: xxxxx
Bytes Received: xxxxx
```

## 🛠️ Troubleshooting

### Compilation Errors
If you encounter `libssh2.h: No such file or directory`:
```bash
# Run the fix script from the examples directory
../fix_libssh2_simple.sh
```

### WiFi Connection Issues
- Verify SSID and password
- Check WiFi signal strength
- Ensure ESP32 is within range

### SSH Connection Issues
- Verify SSH server is accessible
- Check firewall settings
- Ensure SSH keys are properly configured

## 📚 Code Structure

Both examples follow the same structure:
- **setup()**: Initialize WiFi, SSH tunnel, and status LED
- **loop()**: Handle WiFi reconnection, SSH tunnel processing, and status reporting
- **connectWiFi()**: Manage WiFi connection with retry logic
- **updateStatusLED()**: Visual status indication
- **reportStats()**: Performance monitoring and logging

## 🎯 Next Steps

1. Configure your WiFi credentials
2. Set up your SSH server configuration
3. Compile and upload the example
4. Monitor the serial output for connection status
5. Adapt the code for your specific use case

For more advanced usage, see the main library documentation in the parent directory.