# ESP-IDF component; include this directory and components/libssh2_esp in
# EXTRA_COMPONENT_DIRS from the consuming project's top-level CMakeLists.txt.
idf_component_register(
    SRCS
        src/logger.cpp
        src/ssh_channel.cpp
        src/ssh_config.cpp
        src/ssh_session.cpp
        src/ssh_transport.cpp
        src/ssh_tunnel.cpp
    INCLUDE_DIRS src
    REQUIRES libssh2_esp freertos esp_ringbuf esp_timer esp_system heap
    PRIV_REQUIRES esp_netif lwip)

target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_17)
target_compile_definitions(${COMPONENT_LIB} PUBLIC TUNNEL_NATIVE_IDF)
