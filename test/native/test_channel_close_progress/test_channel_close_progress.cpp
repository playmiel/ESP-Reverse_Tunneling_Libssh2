#include "../../../src/channel_close_progress.h"
#include <unity.h>

static constexpr int kEagain = -37;

void setUp(void) {}
void tearDown(void) {}

void test_close_eagain_requires_retry_before_free(void) {
  channel_close_progress::Progress progress;

  TEST_ASSERT_FALSE(
      channel_close_progress::recordCloseResult(progress, kEagain, kEagain));
  TEST_ASSERT_FALSE(progress.closeComplete);
  TEST_ASSERT_FALSE(channel_close_progress::readyForFree(progress));
  TEST_ASSERT_FALSE(channel_close_progress::readyForFinalize(progress));
}

void test_free_eagain_requires_retry_before_finalize(void) {
  channel_close_progress::Progress progress;

  TEST_ASSERT_TRUE(
      channel_close_progress::recordCloseResult(progress, 0, kEagain));
  TEST_ASSERT_TRUE(progress.closeComplete);
  TEST_ASSERT_TRUE(channel_close_progress::readyForFree(progress));

  TEST_ASSERT_FALSE(
      channel_close_progress::recordFreeResult(progress, kEagain, kEagain));
  TEST_ASSERT_FALSE(progress.freeComplete);
  TEST_ASSERT_FALSE(channel_close_progress::readyForFinalize(progress));
}

void test_close_and_free_success_allow_finalize(void) {
  channel_close_progress::Progress progress;

  TEST_ASSERT_TRUE(
      channel_close_progress::recordCloseResult(progress, 0, kEagain));
  TEST_ASSERT_TRUE(
      channel_close_progress::recordFreeResult(progress, 0, kEagain));

  TEST_ASSERT_TRUE(progress.closeComplete);
  TEST_ASSERT_TRUE(progress.freeComplete);
  TEST_ASSERT_TRUE(channel_close_progress::readyForFinalize(progress));
}

int main(int, char **) {
  UNITY_BEGIN();
  RUN_TEST(test_close_eagain_requires_retry_before_free);
  RUN_TEST(test_free_eagain_requires_retry_before_finalize);
  RUN_TEST(test_close_and_free_success_allow_finalize);
  return UNITY_END();
}
