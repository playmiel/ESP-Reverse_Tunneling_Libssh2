#define TUNNEL_DIAG_LOG_ONLY

#include "../../../src/forward_accept_diag.h"
#include <unity.h>

void setUp(void) {}
void tearDown(void) {}

void test_idle_summary_becomes_due_after_interval(void) {
  forward_accept_diag::Tracker tracker;

  tracker.recordPoll(1000UL);
  tracker.recordNoChannel(1000UL, -37, true);
  tracker.recordPoll(1300UL);
  tracker.recordLockUnavailable(1300UL);

  TEST_ASSERT_FALSE(tracker.idleSummaryDue(1800UL, 1000UL));
  TEST_ASSERT_TRUE(tracker.idleSummaryDue(2000UL, 1000UL));

  forward_accept_diag::Snapshot snapshot = tracker.snapshot(2000UL);
  TEST_ASSERT_EQUAL_UINT32(2, snapshot.pollsSinceAccept);
  TEST_ASSERT_EQUAL_UINT32(1, snapshot.eagainSinceAccept);
  TEST_ASSERT_EQUAL_UINT32(1, snapshot.lockMissesSinceAccept);
  TEST_ASSERT_EQUAL_UINT32(1000, snapshot.idleMs);
  TEST_ASSERT_EQUAL_INT(-37, snapshot.lastErr);
}

void test_accept_snapshot_resets_since_accept_counters(void) {
  forward_accept_diag::Tracker tracker;

  tracker.recordPoll(1000UL);
  tracker.recordNoChannel(1000UL, -37, true);
  tracker.recordPoll(1100UL);
  tracker.recordNoChannel(1100UL, -5, false);

  forward_accept_diag::Snapshot accepted = tracker.recordAccept(1500UL);
  TEST_ASSERT_EQUAL_UINT32(2, accepted.pollsSinceAccept);
  TEST_ASSERT_EQUAL_UINT32(1, accepted.eagainSinceAccept);
  TEST_ASSERT_EQUAL_UINT32(1, accepted.errorsSinceAccept);
  TEST_ASSERT_EQUAL_UINT32(500, accepted.idleMs);
  TEST_ASSERT_EQUAL_INT(-5, accepted.lastErr);

  forward_accept_diag::Snapshot after = tracker.snapshot(1600UL);
  TEST_ASSERT_EQUAL_UINT32(0, after.pollsSinceAccept);
  TEST_ASSERT_EQUAL_UINT32(0, after.eagainSinceAccept);
  TEST_ASSERT_EQUAL_UINT32(0, after.errorsSinceAccept);
  TEST_ASSERT_EQUAL_UINT32(0, after.idleMs);
}

void test_reset_clears_total_and_since_accept_counters(void) {
  forward_accept_diag::Tracker tracker;

  tracker.recordPoll(1000UL);
  tracker.recordNoChannel(1000UL, -37, true);
  tracker.recordAccept(1100UL);
  tracker.recordPoll(1200UL);
  tracker.recordLockUnavailable(1200UL);

  tracker.reset();

  forward_accept_diag::Snapshot after = tracker.snapshot(1300UL);
  TEST_ASSERT_EQUAL_UINT32(0, after.totalPolls);
  TEST_ASSERT_EQUAL_UINT32(0, after.totalAccepts);
  TEST_ASSERT_EQUAL_UINT32(0, after.pollsSinceAccept);
  TEST_ASSERT_EQUAL_UINT32(0, after.lockMissesSinceAccept);
  TEST_ASSERT_EQUAL_INT(0, after.lastErr);
}

int main(int, char **) {
  UNITY_BEGIN();
  RUN_TEST(test_idle_summary_becomes_due_after_interval);
  RUN_TEST(test_accept_snapshot_resets_since_accept_counters);
  RUN_TEST(test_reset_clears_total_and_since_accept_counters);
  return UNITY_END();
}
