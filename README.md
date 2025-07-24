# ESP-Reverse_Tunneling_Libssh2

Library for ESP32 Arduino enabling creation of reverse SSH tunnels using libssh2.

## 🚨 Common Issue with libssh2_esp

If you encounter any of these compilation errors:
- `libssh2.h: No such file or directory`
- `libssh2_setup.h: No such file or directory`
- Compilation errors with libssh2 examples

**➡️ Use one of the solutions below:**

## ✅ Solution 1: Automatic Fix Script (Recommended)

### Download and Usage:

```bash
# Download the fix script
wget https://raw.githubusercontent.com/playmiel/ESP-Reverse_Tunneling_Libssh2/main/fix_libssh2_simple.sh
chmod +x fix_libssh2_simple.sh

# Run the script in your project directory (where platformio.ini is located)
./fix_libssh2_simple.sh
```

### What the script does:
- ✅ Creates a backup of your `platformio.ini`
- ✅ Adds all necessary configurations for libssh2_esp
- ✅ Configures mbedTLS as cryptographic backend
- ✅ Excludes problematic examples
- ✅ Cleans directories that cause errors
- ✅ Automatically tests compilation

### Expected result:
```
✅ Compilation successful!
📊 Memory usage:
RAM:   [==        ]  19.1% (used 62520 bytes from 327680 bytes)
Flash: [=======   ]  65.1% (used 853693 bytes from 1310720 bytes)
```

## ✅ Solution 2: Manual Configuration

If you prefer manual configuration, replace your `platformio.ini` with:

```ini
[env:esp32dev]
platform = espressif32
board = esp32dev
framework = arduino
monitor_speed = 115200

; libssh2_esp dependency for SSH support
lib_deps =
    https://github.com/skuodi/libssh2_esp.git

; Configuration for libssh2_esp - exclude examples
lib_ignore = 
    libssh2_esp/libssh2/example
    libssh2_esp/libssh2/tests
    libssh2_esp/libssh2/docs
    libssh2_esp/libssh2/os400
    libssh2_esp/libssh2/win32
    libssh2_esp/libssh2/vms

; Source filters to avoid compiling examples and platform-specific files
build_src_filter =
    +<*>
    -<.git/>
    -<.svn/>
    -<example/>
    -<examples/>
    -<test/>
    -<tests/>
    -<docs/>
    -<os400/>
    -<win32/>
    -<vms/>
    -<*os400*>
    -<*win32*>
    -<*vms*>

; Specific configuration for libssh2_esp
lib_ldf_mode = chain+
lib_compat_mode = strict

; Build flags for ESP-IDF + Arduino compatibility
build_flags =
    -DCONFIG_ARDUHAL_ESP_LOG
    -DCORE_DEBUG_LEVEL=3
    -DCONFIG_LWIP_SO_REUSE=1
    -I.pio/libdeps/esp32dev/libssh2_esp/libssh2/include
    -I.pio/libdeps/esp32dev/libssh2_esp/libssh2/src
    -I.pio/libdeps/esp32dev/libssh2_esp
    ; Configuration to use mbedTLS as cryptographic backend
    -DLIBSSH2_MBEDTLS
    -DHAVE_LIBSSH2_H
    ; Disable zlib to avoid dependency
    -DLIBSSH2_NO_ZLIB
```

## 📋 Installation and Usage

### 1. Adding the Library

**Option A: PlatformIO**
```bash
# Add to your platformio.ini
lib_deps = 
    https://github.com/playmiel/ESP-Reverse_Tunneling_Libssh2.git
    https://github.com/skuodi/libssh2_esp.git
```

**Option B: Arduino IDE**
1. Download the project
2. Copy files to your libraries folder

### 2. Usage in Your Code

```cpp
#include "ESP-Reverse_Tunneling_Libssh2.h"

void setup() {
    Serial.begin(115200);
    
    // WiFi configuration
    WiFi.begin("YOUR_SSID", "YOUR_PASSWORD");
    
    // SSH tunnel configuration
    // See examples/ for complete example
}
```

### 3. Compilation

```bash
pio run                    # Compilation
pio run --target upload    # Upload to ESP32
```

## 📁 Examples Structure

This project provides two example formats:

### PlatformIO Example (Recommended)
- **File**: [`examples/src/main.cpp`](examples/src/main.cpp)
- **Usage**: Compiled when running `pio run` in the examples/ directory
- **Features**: Full PlatformIO integration with advanced logging

### Arduino IDE Example
- **File**: [`examples/esp32_reverse_tunnel_example.ino`](examples/esp32_reverse_tunnel_example.ino)
- **Usage**: Open directly in Arduino IDE
- **Features**: Compatible with Arduino IDE environment

**Note**: When using PlatformIO (`pio run`), the system compiles `examples/src/main.cpp`, not the `.ino` file.

## 🔧 Troubleshooting

### Error "libssh2.h: No such file or directory"
➡️ **Solution**: Use the `fix_libssh2_simple.sh` script (see Solution 1)

### Error "libssh2_setup.h: No such file or directory"
➡️ **Solution**: The script automatically cleans problematic examples

### Error "qtqiconv.h: No such file or directory" (GitHub Actions)
➡️ **Solution**: OS/400 files are now automatically excluded from compilation
- The configuration excludes `libssh2_esp/libssh2/os400/` directory
- Build filters prevent compilation of platform-specific files

### Error "qadrt.h: No such file or directory" (GitHub Actions)
➡️ **Solution**: IBM i system files are excluded via `lib_ignore` configuration

### Compilation error with mbedTLS
➡️ **Solution**: The script automatically configures mbedTLS

### Error "CONFIG_LWIP_MAX_SOCKETS redefined"
➡️ **Solution**: The script configures appropriate flags

### Submodule changes appearing automatically
➡️ **Solution**: Enhanced `.gitignore` now excludes PlatformIO dependency files
- `.pio/libdeps/` directories are ignored
- `*.piopm` files are excluded from version control

## 🚀 GitHub Actions CI/CD

This project includes a unified GitHub Actions workflow that:
- ✅ **Automatically tests compilation** on every push and pull request
- ✅ **Applies libssh2 configuration fixes** before building
- ✅ **Verifies no OS/400 files are compiled** (prevents `qtqiconv.h` errors)
- ✅ **Checks memory usage** and build artifacts
- ✅ **Uses the same configuration** as local compilation in `examples/` directory

The workflow ensures that GitHub Actions compilation behavior matches exactly what happens when you compile locally with `pio run -e esp32dev` in the examples directory.

## � Technical Documentation

For more technical details:
- [`examples/`](examples/) - Usage examples
- [`fix_libssh2_simple.sh`](fix_libssh2_simple.sh) - Automatic configuration script

## 🎯 Specifications

- **Platform**: ESP32 only
- **Framework**: Arduino
- **Cryptographic Backend**: mbedTLS
- **Protocol**: SSH2 with reverse tunneling
- **Memory**: ~19% RAM, ~65% Flash

## 🤝 Contributing

Contributions are welcome! See documentation guides for more details.

## 📄 License

See LICENSE file for details.