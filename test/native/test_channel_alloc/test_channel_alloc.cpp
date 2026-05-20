#include "../../../src/channel_slot_alloc.h"
#include <unity.h>

// Minimal stub — findFreeSlot only reads `active` and `lastFinalizeMs`,
// so we don't need any of the heavy ChannelSlot fields here.
struct StubSlot {
  bool active = false;
  unsigned long lastFinalizeMs = 0;
};

void setUp(void) {}
void tearDown(void) {}

void test_finds_first_inactive_slot_when_no_finalize(void) {
  StubSlot slots[3];
  // All inactive, none finalized yet
  int idx = channel_alloc::findFreeSlot(slots, 3, 1000UL);
  TEST_ASSERT_EQUAL_INT(0, idx);
}

void test_skips_active_slots(void) {
  StubSlot slots[3];
  slots[0].active = true;
  slots[1].active = true;
  // slot 2 is inactive
  int idx = channel_alloc::findFreeSlot(slots, 3, 1000UL);
  TEST_ASSERT_EQUAL_INT(2, idx);
}

void test_returns_minus_one_when_all_active(void) {
  StubSlot slots[3];
  for (int i = 0; i < 3; ++i) slots[i].active = true;
  int idx = channel_alloc::findFreeSlot(slots, 3, 1000UL);
  TEST_ASSERT_EQUAL_INT(-1, idx);
}

void test_skips_slot_within_finalize_cooldown(void) {
  StubSlot slots[2];
  // slot 0 was just finalized, slot 1 was never finalized
  slots[0].lastFinalizeMs = 1000UL;
  slots[1].lastFinalizeMs = 0;
  // now=1000 means 0ms since finalize for slot 0 — must be skipped
  int idx = channel_alloc::findFreeSlot(slots, 2, 1000UL);
  TEST_ASSERT_EQUAL_INT(1, idx);
}

void test_picks_slot_after_cooldown_elapses(void) {
  StubSlot slots[2];
  slots[0].lastFinalizeMs = 1000UL;
  slots[1].active = true; // force candidate to slot 0
  // now = 1000 + DEFAULT_COOLDOWN: cooldown elapsed
  unsigned long now =
      1000UL + channel_alloc::FINALIZE_COOLDOWN_MS;
  int idx = channel_alloc::findFreeSlot(slots, 2, now);
  TEST_ASSERT_EQUAL_INT(0, idx);
}

void test_explicit_cooldown_argument_is_respected(void) {
  StubSlot slots[1];
  slots[0].lastFinalizeMs = 1000UL;
  // 30 ms after finalize, with explicit 25 ms cooldown -> available
  int idx = channel_alloc::findFreeSlot(slots, 1, 1030UL,
                                        /*cooldown_ms*/ 25UL);
  TEST_ASSERT_EQUAL_INT(0, idx);

  // 30 ms after finalize, with explicit 100 ms cooldown -> still skipped
  idx = channel_alloc::findFreeSlot(slots, 1, 1030UL,
                                    /*cooldown_ms*/ 100UL);
  TEST_ASSERT_EQUAL_INT(-1, idx);
}

void test_null_or_zero_size_returns_minus_one(void) {
  StubSlot slots[1];
  TEST_ASSERT_EQUAL_INT(-1, channel_alloc::findFreeSlot<StubSlot>(
                                nullptr, 1, 1000UL));
  TEST_ASSERT_EQUAL_INT(-1, channel_alloc::findFreeSlot(slots, 0, 1000UL));
}

int main(int, char **) {
  UNITY_BEGIN();
  RUN_TEST(test_finds_first_inactive_slot_when_no_finalize);
  RUN_TEST(test_skips_active_slots);
  RUN_TEST(test_returns_minus_one_when_all_active);
  RUN_TEST(test_skips_slot_within_finalize_cooldown);
  RUN_TEST(test_picks_slot_after_cooldown_elapses);
  RUN_TEST(test_explicit_cooldown_argument_is_respected);
  RUN_TEST(test_null_or_zero_size_returns_minus_one);
  return UNITY_END();
}
