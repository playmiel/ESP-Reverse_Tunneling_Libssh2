#include "../../../src/circuit_breaker.h"
#include <unity.h>

void setUp(void) {}
void tearDown(void) {}

void test_initial_state_not_backed_off(void) {
    CircuitBreaker cb;
    TEST_ASSERT_FALSE(cb.isBackedOff(22080, 0));
    TEST_ASSERT_FALSE(cb.isBackedOff(22080, 999999));
}

void test_below_threshold_not_backed_off(void) {
    CircuitBreaker cb;
    cb.recordFailure(22080, 100);
    cb.recordFailure(22080, 200);
    TEST_ASSERT_FALSE(cb.isBackedOff(22080, 300));
}

void test_at_threshold_engages_backoff(void) {
    CircuitBreaker cb;
    cb.recordFailure(22080, 100);
    cb.recordFailure(22080, 200);
    bool tripped = cb.recordFailure(22080, 300);
    TEST_ASSERT_TRUE(tripped);
    TEST_ASSERT_TRUE(cb.isBackedOff(22080, 300));
    TEST_ASSERT_TRUE(cb.isBackedOff(22080, 300 + CircuitBreaker::BACKOFF_BASE_MS - 1));
}

void test_backoff_expires(void) {
    CircuitBreaker cb;
    cb.recordFailure(22080, 100);
    cb.recordFailure(22080, 200);
    cb.recordFailure(22080, 300);
    TEST_ASSERT_FALSE(cb.isBackedOff(22080, 300 + CircuitBreaker::BACKOFF_BASE_MS));
}

void test_exponential_growth(void) {
    CircuitBreaker cb;
    for (int i = 0; i < 3; ++i) cb.recordFailure(22080, 100);
    auto* h1 = cb.peek(22080);
    unsigned long delay1 = h1->backoffUntilMs - 100;

    cb.recordFailure(22080, 100);
    auto* h2 = cb.peek(22080);
    unsigned long delay2 = h2->backoffUntilMs - 100;

    TEST_ASSERT_EQUAL_UINT32(delay1 * 2, delay2);
}

void test_backoff_capped(void) {
    CircuitBreaker cb;
    for (int i = 0; i < 100; ++i) cb.recordFailure(22080, 100);
    auto* h = cb.peek(22080);
    TEST_ASSERT_EQUAL_UINT32(100 + CircuitBreaker::BACKOFF_CAP_MS, h->backoffUntilMs);
}

void test_recovery_resets_state(void) {
    CircuitBreaker cb;
    for (int i = 0; i < 5; ++i) cb.recordFailure(22080, 100);
    TEST_ASSERT_TRUE(cb.isBackedOff(22080, 200));
    cb.recordSuccess(22080);
    TEST_ASSERT_FALSE(cb.isBackedOff(22080, 200));
    auto* h = cb.peek(22080);
    TEST_ASSERT_EQUAL_UINT16(0, h->consecutiveFails);
    TEST_ASSERT_EQUAL_UINT32(0, h->backoffUntilMs);
}

void test_multi_port_isolation(void) {
    CircuitBreaker cb;
    for (int i = 0; i < 3; ++i) cb.recordFailure(22080, 100);
    TEST_ASSERT_TRUE(cb.isBackedOff(22080, 200));
    TEST_ASSERT_FALSE(cb.isBackedOff(22081, 200));
}

void test_table_saturation_silent(void) {
    CircuitBreaker cb;
    // Fill 8 distinct ports
    for (int i = 0; i < CircuitBreaker::MAX_MAPPING_HEALTH; ++i) {
        cb.recordFailure(20000 + i, 100);
    }
    // 9th distinct port should be silently ignored, not crash, not overwrite
    bool tripped = cb.recordFailure(99999, 100);
    TEST_ASSERT_FALSE(tripped);
    TEST_ASSERT_FALSE(cb.isBackedOff(99999, 200));
    // Existing ports unaffected
    TEST_ASSERT_NOT_NULL(cb.peek(20000));
}

void test_millis_wrap(void) {
    CircuitBreaker cb;
    unsigned long nearMax = 0xFFFFFFFEUL;
    for (int i = 0; i < 3; ++i) cb.recordFailure(22080, nearMax);
    // backoffUntilMs has wrapped past 0
    TEST_ASSERT_TRUE(cb.isBackedOff(22080, nearMax));
    TEST_ASSERT_TRUE(cb.isBackedOff(22080, 0));        // just after wrap, still in backoff
    TEST_ASSERT_FALSE(cb.isBackedOff(22080, CircuitBreaker::BACKOFF_BASE_MS));
}

void test_sentinel_port_zero_is_noop(void) {
    CircuitBreaker cb;
    bool tripped = cb.recordFailure(0, 100);
    TEST_ASSERT_FALSE(tripped);
    cb.recordSuccess(0);  // must not crash
    TEST_ASSERT_NULL(cb.peek(0));
}

void test_re_arm_after_recovery(void) {
    CircuitBreaker cb;
    for (int i = 0; i < 3; ++i) cb.recordFailure(22080, 100);
    cb.recordSuccess(22080);
    for (int i = 0; i < 2; ++i) cb.recordFailure(22080, 200);
    TEST_ASSERT_FALSE(cb.isBackedOff(22080, 250));
    bool tripped = cb.recordFailure(22080, 300);
    TEST_ASSERT_TRUE(tripped);
    TEST_ASSERT_TRUE(cb.isBackedOff(22080, 300));
}

int main(int, char **) {
    UNITY_BEGIN();
    RUN_TEST(test_initial_state_not_backed_off);
    RUN_TEST(test_below_threshold_not_backed_off);
    RUN_TEST(test_at_threshold_engages_backoff);
    RUN_TEST(test_backoff_expires);
    RUN_TEST(test_exponential_growth);
    RUN_TEST(test_backoff_capped);
    RUN_TEST(test_recovery_resets_state);
    RUN_TEST(test_multi_port_isolation);
    RUN_TEST(test_table_saturation_silent);
    RUN_TEST(test_millis_wrap);
    RUN_TEST(test_sentinel_port_zero_is_noop);
    RUN_TEST(test_re_arm_after_recovery);
    return UNITY_END();
}
