#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "common/secret_id.h"
#include "protocol/protocol.h"

namespace z::vault::protocol {
namespace {

TEST(protocol, round_trips_put_request) {
  const std::array<std::byte, 4> value{std::byte{1}, std::byte{2}, std::byte{3},
                                       std::byte{4}};
  const auto payload = encode_put_request("agent_openai_default", value);
  const auto frame =
      encode_frame(message_type::put_secret_request, 42, payload);

  frame_header header;
  std::string diagnostic;
  ASSERT_TRUE(
      decode_header(std::span<const std::byte>{frame}.first(header_size),
                    header, diagnostic));
  EXPECT_EQ(header.protocol_version, version);
  EXPECT_EQ(header.type, message_type::put_secret_request);
  EXPECT_EQ(header.request_id, 42);
  EXPECT_EQ(header.payload_size, payload.size());

  std::string id;
  std::vector<std::byte> decoded;
  ASSERT_TRUE(
      decode_put_request(std::span<const std::byte>{frame}.subspan(header_size),
                         id, decoded, diagnostic));
  EXPECT_EQ(id, "agent_openai_default");
  EXPECT_EQ(decoded, std::vector<std::byte>(value.begin(), value.end()));
}

TEST(protocol, rejects_wrong_magic) {
  const auto payload = encode_id_request("trader_exchange_main");
  auto frame = encode_frame(message_type::get_secret_request, 7, payload);
  frame.front() = std::byte{0};
  frame_header header;
  std::string diagnostic;
  EXPECT_FALSE(
      decode_header(std::span<const std::byte>{frame}.first(header_size),
                    header, diagnostic));
  EXPECT_EQ(diagnostic, "invalid frame magic");
}

TEST(protocol, validates_lowercase_c_style_secret_identifiers) {
  EXPECT_TRUE(is_valid_secret_id("a"));
  EXPECT_TRUE(is_valid_secret_id(std::string(63, 'a')));
  EXPECT_TRUE(is_valid_secret_id("agent_openai_2"));
  EXPECT_FALSE(is_valid_secret_id(""));
  EXPECT_FALSE(is_valid_secret_id(std::string(64, 'a')));
  EXPECT_FALSE(is_valid_secret_id("2agent"));
  EXPECT_FALSE(is_valid_secret_id("_agent"));
  EXPECT_FALSE(is_valid_secret_id("Agent"));
  EXPECT_FALSE(is_valid_secret_id("agent/openai"));
  EXPECT_FALSE(is_valid_secret_id("agent-openai"));
  EXPECT_FALSE(is_valid_secret_id("agent openai"));
  EXPECT_FALSE(is_valid_secret_id("agent_\xc3\xa9"));
}

TEST(protocol, round_trips_sorted_secret_identifier_lists) {
  const std::vector<std::string> expected{"agent_alpha", "agent_beta",
                                          "trader_main"};
  const auto encoded = encode_id_list(expected);
  std::vector<std::string> decoded;
  std::string diagnostic;
  ASSERT_TRUE(decode_id_list(encoded, decoded, diagnostic));
  EXPECT_EQ(decoded, expected);

  auto malformed = encoded;
  malformed.push_back(std::byte{0});
  EXPECT_FALSE(decode_id_list(malformed, decoded, diagnostic));
  EXPECT_EQ(diagnostic, "trailing bytes in secret identifier list");
}

TEST(protocol, keeps_maximum_identifier_list_within_payload_limit) {
  std::vector<std::string> identifiers;
  identifiers.reserve(10000);
  for (std::size_t index = 0; index < 10000; ++index) {
    std::array<char, 16> identifier{};
    const auto length = std::snprintf(identifier.data(), identifier.size(),
                                      "secret_%05zu", index);
    ASSERT_GT(length, 0);
    identifiers.emplace_back(identifier.data(),
                             static_cast<std::size_t>(length));
  }
  const auto encoded = encode_id_list(identifiers);
  EXPECT_LT(encoded.size(), maximum_payload_size);
  std::vector<std::string> decoded;
  std::string diagnostic;
  ASSERT_TRUE(decode_id_list(encoded, decoded, diagnostic));
  EXPECT_EQ(decoded, identifiers);
}

TEST(protocol, round_trips_response) {
  const std::array<std::byte, 3> value{std::byte{'k'}, std::byte{'e'},
                                       std::byte{'y'}};
  const auto encoded = encode_response(ZETA_VAULT_STATUS_OK, {}, value);
  response_payload response;
  std::string diagnostic;
  ASSERT_TRUE(decode_response(encoded, response, diagnostic));
  EXPECT_EQ(response.status, ZETA_VAULT_STATUS_OK);
  EXPECT_TRUE(response.diagnostic.empty());
  EXPECT_EQ(response.data, std::vector<std::byte>(value.begin(), value.end()));
}

} // namespace
} // namespace z::vault::protocol
