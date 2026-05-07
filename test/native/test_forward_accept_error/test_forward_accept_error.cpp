#include <unity.h>

#include "../../../src/forward_accept_error.h"

static constexpr int kEagain = -37;
static constexpr int kChannelUnknown = -23;
static constexpr int kChannelClosed = -26;
static constexpr int kSocketSend = -7;
static constexpr int kSocketDisconnect = -13;

void setUp() {}
void tearDown() {}

void test_eagain_is_not_fatal_accept_error() {
  TEST_ASSERT_FALSE(forward_accept_error::isFatal(
      kEagain, kEagain, kChannelUnknown, kChannelClosed, kSocketSend,
      kSocketDisconnect));
}

void test_channel_unknown_is_fatal_accept_error() {
  TEST_ASSERT_TRUE(forward_accept_error::isFatal(
      kChannelUnknown, kEagain, kChannelUnknown, kChannelClosed, kSocketSend,
      kSocketDisconnect));
}

void test_reconnect_after_repeated_fatal_accept_errors() {
  TEST_ASSERT_FALSE(forward_accept_error::shouldReconnectAfterConsecutiveErrors(
      2, kChannelUnknown, kEagain, kChannelUnknown, kChannelClosed, kSocketSend,
      kSocketDisconnect));
  TEST_ASSERT_TRUE(forward_accept_error::shouldReconnectAfterConsecutiveErrors(
      3, kChannelUnknown, kEagain, kChannelUnknown, kChannelClosed, kSocketSend,
      kSocketDisconnect));
}

int main() {
  UNITY_BEGIN();
  RUN_TEST(test_eagain_is_not_fatal_accept_error);
  RUN_TEST(test_channel_unknown_is_fatal_accept_error);
  RUN_TEST(test_reconnect_after_repeated_fatal_accept_errors);
  return UNITY_END();
}
