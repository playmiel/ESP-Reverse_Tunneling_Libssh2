#include "../../../src/channel_inactivity.h"
#include <climits>
#include <unity.h>

using channel_inactivity::hasExpired;

void setUp(void) {}
void tearDown(void) {}

void test_expires_only_after_configured_timeout(void) {
  TEST_ASSERT_FALSE(hasExpired(1100UL, 1000UL, 100UL));
  TEST_ASSERT_TRUE(hasExpired(1101UL, 1000UL, 100UL));
}

void test_zero_timestamp_or_timeout_is_not_expired(void) {
  TEST_ASSERT_FALSE(hasExpired(1000UL, 0UL, 100UL));
  TEST_ASSERT_FALSE(hasExpired(1000UL, 500UL, 0UL));
}

void test_millis_wrap_is_supported(void) {
  const unsigned long last = ULONG_MAX - 50UL;
  TEST_ASSERT_FALSE(hasExpired(25UL, last, 100UL));
  TEST_ASSERT_TRUE(hasExpired(51UL, last, 100UL));
}

int main(int, char **) {
  UNITY_BEGIN();
  RUN_TEST(test_expires_only_after_configured_timeout);
  RUN_TEST(test_zero_timestamp_or_timeout_is_not_expired);
  RUN_TEST(test_millis_wrap_is_supported);
  return UNITY_END();
}
