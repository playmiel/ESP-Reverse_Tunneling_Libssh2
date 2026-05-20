#include "../../../src/ssh_config_validators.h"
#include <unity.h>

using namespace ssh_validators;

void setUp(void) {}
void tearDown(void) {}

void test_port_boundaries(void) {
    TEST_ASSERT_FALSE(isValidPort(0));
    TEST_ASSERT_TRUE(isValidPort(1));
    TEST_ASSERT_TRUE(isValidPort(22));
    TEST_ASSERT_TRUE(isValidPort(8080));
    TEST_ASSERT_TRUE(isValidPort(65535));
    TEST_ASSERT_FALSE(isValidPort(65536));
    TEST_ASSERT_FALSE(isValidPort(-1));
}

void test_hostname_basic(void) {
    TEST_ASSERT_TRUE(isValidHostname("example.com"));
    TEST_ASSERT_TRUE(isValidHostname("192.168.1.1"));
    TEST_ASSERT_TRUE(isValidHostname("localhost"));
    TEST_ASSERT_TRUE(isValidHostname("a"));
}

void test_hostname_empty_rejected(void) {
    TEST_ASSERT_FALSE(isValidHostname(""));
}

void test_keepalive(void) {
    TEST_ASSERT_FALSE(isValidKeepAlive(0));
    TEST_ASSERT_FALSE(isValidKeepAlive(-5));
    TEST_ASSERT_TRUE(isValidKeepAlive(1));
    TEST_ASSERT_TRUE(isValidKeepAlive(30));
    TEST_ASSERT_TRUE(isValidKeepAlive(3600));
}

void test_buffer_size(void) {
    TEST_ASSERT_FALSE(isValidBufferSize(0));
    TEST_ASSERT_FALSE(isValidBufferSize(-1));
    TEST_ASSERT_TRUE(isValidBufferSize(1));
    TEST_ASSERT_TRUE(isValidBufferSize(8192));
    TEST_ASSERT_TRUE(isValidBufferSize(65536));
}

void test_reconnect_delay(void) {
    TEST_ASSERT_FALSE(isValidReconnectDelay(0));
    TEST_ASSERT_FALSE(isValidReconnectDelay(-100));
    TEST_ASSERT_TRUE(isValidReconnectDelay(1));
    TEST_ASSERT_TRUE(isValidReconnectDelay(5000));
}

void test_max_channels(void) {
    TEST_ASSERT_FALSE(isValidMaxChannels(0));
    TEST_ASSERT_FALSE(isValidMaxChannels(-1));
    TEST_ASSERT_TRUE(isValidMaxChannels(1));
    TEST_ASSERT_TRUE(isValidMaxChannels(10));
    TEST_ASSERT_TRUE(isValidMaxChannels(100));
}

void test_connection_timeout(void) {
    TEST_ASSERT_FALSE(isValidConnectionTimeout(0));
    TEST_ASSERT_FALSE(isValidConnectionTimeout(-30));
    TEST_ASSERT_TRUE(isValidConnectionTimeout(1));
    TEST_ASSERT_TRUE(isValidConnectionTimeout(30));
}

void test_max_reconnect_attempts(void) {
    TEST_ASSERT_FALSE(isValidMaxReconnectAttempts(0));
    TEST_ASSERT_FALSE(isValidMaxReconnectAttempts(-1));
    TEST_ASSERT_TRUE(isValidMaxReconnectAttempts(1));
    TEST_ASSERT_TRUE(isValidMaxReconnectAttempts(5));
}

int main(int, char **) {
    UNITY_BEGIN();
    RUN_TEST(test_port_boundaries);
    RUN_TEST(test_hostname_basic);
    RUN_TEST(test_hostname_empty_rejected);
    RUN_TEST(test_keepalive);
    RUN_TEST(test_buffer_size);
    RUN_TEST(test_reconnect_delay);
    RUN_TEST(test_max_channels);
    RUN_TEST(test_connection_timeout);
    RUN_TEST(test_max_reconnect_attempts);
    return UNITY_END();
}
