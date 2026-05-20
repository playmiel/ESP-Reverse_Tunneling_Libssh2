#include "../../../src/prepend_buffer.h"
#include <unity.h>

void setUp(void) {}
void tearDown(void) {}

void test_unbound_rejects_writes(void) {
    PrependBuffer pb;
    TEST_ASSERT_FALSE(pb.isBound());
    uint8_t data[] = {1, 2};
    TEST_ASSERT_EQUAL_size_t(0, pb.writeToFront(data, 2));
    uint8_t out[8] = {};
    TEST_ASSERT_EQUAL_size_t(0, pb.read(out, 8));
}

void test_initially_empty_after_bind(void) {
    uint8_t storage[128];
    PrependBuffer pb(storage, sizeof(storage));
    TEST_ASSERT_TRUE(pb.isBound());
    TEST_ASSERT_TRUE(pb.empty());
    TEST_ASSERT_EQUAL_size_t(0, pb.pending());
    TEST_ASSERT_EQUAL_size_t(128, pb.capacity());
}

void test_write_and_read_full(void) {
    uint8_t storage[128];
    PrependBuffer pb(storage, sizeof(storage));
    uint8_t data[] = {1, 2, 3, 4};
    TEST_ASSERT_EQUAL_size_t(4, pb.writeToFront(data, 4));
    TEST_ASSERT_FALSE(pb.empty());
    TEST_ASSERT_EQUAL_size_t(4, pb.pending());

    uint8_t out[8] = {};
    TEST_ASSERT_EQUAL_size_t(4, pb.read(out, 8));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(data, out, 4);
    TEST_ASSERT_TRUE(pb.empty());
}

void test_partial_read(void) {
    uint8_t storage[128];
    PrependBuffer pb(storage, sizeof(storage));
    uint8_t data[] = {1, 2, 3, 4, 5};
    pb.writeToFront(data, 5);
    uint8_t out[3] = {};
    TEST_ASSERT_EQUAL_size_t(3, pb.read(out, 3));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(data, out, 3);
    TEST_ASSERT_EQUAL_size_t(2, pb.pending());

    uint8_t out2[8] = {};
    TEST_ASSERT_EQUAL_size_t(2, pb.read(out2, 8));
    uint8_t expected[] = {4, 5};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, out2, 2);
    TEST_ASSERT_TRUE(pb.empty());
}

void test_oversized_write_rejected(void) {
    uint8_t storage[8];
    PrependBuffer pb(storage, sizeof(storage));
    uint8_t data[16] = {};
    TEST_ASSERT_EQUAL_size_t(0, pb.writeToFront(data, 16));
    TEST_ASSERT_TRUE(pb.empty());
}

void test_write_when_non_empty_rejected(void) {
    uint8_t storage[128];
    PrependBuffer pb(storage, sizeof(storage));
    uint8_t a[] = {1, 2, 3};
    uint8_t b[] = {9, 9};
    pb.writeToFront(a, 3);
    TEST_ASSERT_EQUAL_size_t(0, pb.writeToFront(b, 2));
    TEST_ASSERT_EQUAL_size_t(3, pb.pending());
}

void test_write_after_full_drain_succeeds(void) {
    uint8_t storage[128];
    PrependBuffer pb(storage, sizeof(storage));
    uint8_t a[] = {1, 2};
    uint8_t b[] = {7, 8, 9};
    pb.writeToFront(a, 2);
    uint8_t tmp[8] = {};
    pb.read(tmp, 8);
    TEST_ASSERT_EQUAL_size_t(3, pb.writeToFront(b, 3));
}

void test_null_or_zero_rejected(void) {
    uint8_t storage[128];
    PrependBuffer pb(storage, sizeof(storage));
    TEST_ASSERT_EQUAL_size_t(0, pb.writeToFront(nullptr, 4));
    uint8_t data[] = {1};
    TEST_ASSERT_EQUAL_size_t(0, pb.writeToFront(data, 0));
    uint8_t out[8] = {};
    TEST_ASSERT_EQUAL_size_t(0, pb.read(nullptr, 8));
    TEST_ASSERT_EQUAL_size_t(0, pb.read(out, 0));
}

void test_clear(void) {
    uint8_t storage[128];
    PrependBuffer pb(storage, sizeof(storage));
    uint8_t a[] = {1, 2, 3};
    pb.writeToFront(a, 3);
    pb.clear();
    TEST_ASSERT_TRUE(pb.empty());
    TEST_ASSERT_EQUAL_size_t(3, pb.writeToFront(a, 3));
}

void test_capacity_exact_fit(void) {
    uint8_t storage[4];
    PrependBuffer pb(storage, sizeof(storage));
    uint8_t data[] = {1, 2, 3, 4};
    TEST_ASSERT_EQUAL_size_t(4, pb.writeToFront(data, 4));
    uint8_t one_more[] = {5};
    pb.read(data, 4);
    TEST_ASSERT_EQUAL_size_t(1, pb.writeToFront(one_more, 1));
}

void test_reset_rebinds_storage(void) {
    uint8_t storage1[16];
    uint8_t storage2[32];
    PrependBuffer pb(storage1, sizeof(storage1));
    uint8_t a[] = {1, 2, 3};
    pb.writeToFront(a, 3);
    pb.reset(storage2, sizeof(storage2));
    TEST_ASSERT_TRUE(pb.empty());
    TEST_ASSERT_EQUAL_size_t(32, pb.capacity());
    uint8_t big[24] = {};
    TEST_ASSERT_EQUAL_size_t(24, pb.writeToFront(big, 24));
}

int main(int, char **) {
    UNITY_BEGIN();
    RUN_TEST(test_unbound_rejects_writes);
    RUN_TEST(test_initially_empty_after_bind);
    RUN_TEST(test_write_and_read_full);
    RUN_TEST(test_partial_read);
    RUN_TEST(test_oversized_write_rejected);
    RUN_TEST(test_write_when_non_empty_rejected);
    RUN_TEST(test_write_after_full_drain_succeeds);
    RUN_TEST(test_null_or_zero_rejected);
    RUN_TEST(test_clear);
    RUN_TEST(test_capacity_exact_fit);
    RUN_TEST(test_reset_rebinds_storage);
    return UNITY_END();
}
