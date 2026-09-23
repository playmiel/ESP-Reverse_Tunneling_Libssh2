#include "../../../src/socks5_protocol.h"
#include <cstring>
#include <unity.h>

void setUp(void) {}
void tearDown(void) {}

static socks5::Event feed(socks5::Negotiator &parser, const uint8_t *data,
                          size_t length) {
  socks5::Event event = socks5::Event::NeedMore;
  size_t offset = 0;
  while (offset < length) {
    size_t chunk = parser.bytesNeeded();
    TEST_ASSERT_GREATER_THAN_UINT32(0, chunk);
    if (chunk > 1) {
      chunk = 1; // exercise fragmented delivery
    }
    event = parser.consume(data + offset, chunk);
    offset += chunk;
  }
  return event;
}

void test_no_auth_ipv4_connect_fragmented(void) {
  socks5::Negotiator parser;
  const uint8_t greeting[] = {0x05, 0x02, 0x02, 0x00};
  TEST_ASSERT_EQUAL_INT(static_cast<int>(socks5::Event::MethodAccepted),
                        static_cast<int>(feed(parser, greeting,
                                              sizeof(greeting))));

  const uint8_t request[] = {0x05, 0x01, 0x00, 0x01, 192,
                             168,  0,    190,  0x23, 0x28};
  TEST_ASSERT_EQUAL_INT(static_cast<int>(socks5::Event::ConnectRequest),
                        static_cast<int>(feed(parser, request,
                                              sizeof(request))));
  TEST_ASSERT_TRUE(parser.complete());
  TEST_ASSERT_EQUAL_STRING("192.168.0.190", parser.targetHost());
  TEST_ASSERT_EQUAL_UINT16(9000, parser.targetPort());
}

void test_no_auth_domain_connect(void) {
  socks5::Negotiator parser;
  const uint8_t greeting[] = {0x05, 0x01, 0x00};
  TEST_ASSERT_EQUAL_INT(static_cast<int>(socks5::Event::MethodAccepted),
                        static_cast<int>(feed(parser, greeting,
                                              sizeof(greeting))));

  const char *domain = "echo.example.test";
  uint8_t request[4 + 1 + 255 + 2] = {0x05, 0x01, 0x00, 0x03};
  const size_t domainLength = strlen(domain);
  request[4] = static_cast<uint8_t>(domainLength);
  memcpy(request + 5, domain, domainLength);
  request[5 + domainLength] = 0x01;
  request[6 + domainLength] = 0xbb;

  TEST_ASSERT_EQUAL_INT(
      static_cast<int>(socks5::Event::ConnectRequest),
      static_cast<int>(feed(parser, request, 7 + domainLength)));
  TEST_ASSERT_EQUAL_STRING(domain, parser.targetHost());
  TEST_ASSERT_EQUAL_UINT16(443, parser.targetPort());
}

void test_rejects_authentication_when_no_auth_is_absent(void) {
  socks5::Negotiator parser;
  const uint8_t greeting[] = {0x05, 0x02, 0x01, 0x02};
  TEST_ASSERT_EQUAL_INT(static_cast<int>(socks5::Event::MethodRejected),
                        static_cast<int>(feed(parser, greeting,
                                              sizeof(greeting))));
}

void test_rejects_non_connect_command(void) {
  socks5::Negotiator parser;
  const uint8_t greeting[] = {0x05, 0x01, 0x00};
  feed(parser, greeting, sizeof(greeting));
  const uint8_t requestHeader[] = {0x05, 0x02, 0x00, 0x01};
  TEST_ASSERT_EQUAL_INT(
      static_cast<int>(socks5::Event::CommandNotSupported),
      static_cast<int>(feed(parser, requestHeader, sizeof(requestHeader))));
}

void test_rejects_ipv6_address_type(void) {
  socks5::Negotiator parser;
  const uint8_t greeting[] = {0x05, 0x01, 0x00};
  feed(parser, greeting, sizeof(greeting));
  const uint8_t requestHeader[] = {0x05, 0x01, 0x00, 0x04};
  TEST_ASSERT_EQUAL_INT(
      static_cast<int>(socks5::Event::AddressTypeNotSupported),
      static_cast<int>(feed(parser, requestHeader, sizeof(requestHeader))));
}

void test_reply_encoders(void) {
  uint8_t response[10] = {};
  TEST_ASSERT_EQUAL_UINT32(
      2, socks5::writeMethodSelection(true, response, sizeof(response)));
  TEST_ASSERT_EQUAL_HEX8(0x05, response[0]);
  TEST_ASSERT_EQUAL_HEX8(0x00, response[1]);

  TEST_ASSERT_EQUAL_UINT32(
      10, socks5::writeConnectReply(socks5::Reply::ConnectionRefused,
                                    response, sizeof(response)));
  const uint8_t expected[] = {0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
  TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, response, sizeof(expected));
}

int main(int, char **) {
  UNITY_BEGIN();
  RUN_TEST(test_no_auth_ipv4_connect_fragmented);
  RUN_TEST(test_no_auth_domain_connect);
  RUN_TEST(test_rejects_authentication_when_no_auth_is_absent);
  RUN_TEST(test_rejects_non_connect_command);
  RUN_TEST(test_rejects_ipv6_address_type);
  RUN_TEST(test_reply_encoders);
  return UNITY_END();
}
