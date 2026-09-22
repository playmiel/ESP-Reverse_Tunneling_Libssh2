#include "../../../src/channel_lifecycle.h"
#include <cstdint>
#include <unity.h>

using channel_lifecycle::State;

void setUp(void) {}
void tearDown(void) {}

void test_pre_open_states_are_explicit(void) {
  TEST_ASSERT_TRUE(channel_lifecycle::isPreOpen(State::Negotiating));
  TEST_ASSERT_TRUE(channel_lifecycle::isPreOpen(State::Resolving));
  TEST_ASSERT_TRUE(channel_lifecycle::isPreOpen(State::Connecting));
  TEST_ASSERT_FALSE(channel_lifecycle::isPreOpen(State::Open));
  TEST_ASSERT_FALSE(channel_lifecycle::isPreOpen(State::Draining));
  TEST_ASSERT_FALSE(channel_lifecycle::isPreOpen(State::Closed));
}

void test_local_socket_is_used_only_after_connect(void) {
  TEST_ASSERT_FALSE(channel_lifecycle::canUseLocalSocket(State::Negotiating));
  TEST_ASSERT_FALSE(channel_lifecycle::canUseLocalSocket(State::Resolving));
  TEST_ASSERT_FALSE(channel_lifecycle::canUseLocalSocket(State::Connecting));
  TEST_ASSERT_TRUE(channel_lifecycle::canUseLocalSocket(State::Open));
  TEST_ASSERT_TRUE(channel_lifecycle::canUseLocalSocket(State::Draining));
  TEST_ASSERT_FALSE(channel_lifecycle::canUseLocalSocket(State::Closed));
}

void test_local_half_close_waits_for_ssh_to_local_drain(void) {
  TEST_ASSERT_FALSE(channel_lifecycle::shouldShutdownLocalWrite(
      true, false, false, true, false));
  TEST_ASSERT_TRUE(channel_lifecycle::shouldShutdownLocalWrite(
      true, false, false, true, true));

  TEST_ASSERT_FALSE(channel_lifecycle::shouldShutdownLocalWrite(
      false, false, false, true, true));
  TEST_ASSERT_FALSE(channel_lifecycle::shouldShutdownLocalWrite(
      true, true, false, true, true));
  TEST_ASSERT_FALSE(channel_lifecycle::shouldShutdownLocalWrite(
      true, false, true, true, true));
  TEST_ASSERT_FALSE(channel_lifecycle::shouldShutdownLocalWrite(
      true, false, false, false, true));
}

void test_connect_timeout_boundary(void) {
  TEST_ASSERT_FALSE(channel_lifecycle::connectTimedOut(2999U, 1000U, 2000U));
  TEST_ASSERT_TRUE(channel_lifecycle::connectTimedOut(3000U, 1000U, 2000U));
  TEST_ASSERT_FALSE(channel_lifecycle::connectTimedOut(3000U, 1000U, 0U));
}

void test_connect_timeout_handles_millis_wrap(void) {
  const uint32_t started = UINT32_MAX - 50U;
  TEST_ASSERT_FALSE(channel_lifecycle::connectTimedOut(48U, started, 100U));
  TEST_ASSERT_TRUE(channel_lifecycle::connectTimedOut(49U, started, 100U));
}

int main(int, char **) {
  UNITY_BEGIN();
  RUN_TEST(test_pre_open_states_are_explicit);
  RUN_TEST(test_local_socket_is_used_only_after_connect);
  RUN_TEST(test_local_half_close_waits_for_ssh_to_local_drain);
  RUN_TEST(test_connect_timeout_boundary);
  RUN_TEST(test_connect_timeout_handles_millis_wrap);
  return UNITY_END();
}
