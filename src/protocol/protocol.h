#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <zeta_vault/zeta_vault.h>

namespace z::vault::protocol {

/** Current on-wire protocol version. */
inline constexpr std::uint16_t version = 1;

/** Fixed encoded frame header size. */
inline constexpr std::size_t header_size = 24;

/** Maximum accepted payload size. */
inline constexpr std::size_t maximum_payload_size = 1024U * 1024U;

/** Vault protocol message types. */
enum class message_type : std::uint16_t {
  ping_request = 1,
  ping_response = 2,
  put_secret_request = 3,
  put_secret_response = 4,
  get_secret_request = 5,
  get_secret_response = 6,
  remove_secret_request = 7,
  remove_secret_response = 8,
  lock_request = 9,
  lock_response = 10,
  list_secrets_request = 11,
  list_secrets_response = 12,
};

/** Decoded fixed frame header. */
struct frame_header {
  std::uint16_t protocol_version{0};
  message_type type{};
  std::uint64_t request_id{0};
  std::uint32_t payload_size{0};
};

/** Decoded generic response payload. */
struct response_payload {
  zeta_vault_status_t status{ZETA_VAULT_STATUS_INTERNAL_ERROR};
  std::string diagnostic;
  std::vector<std::byte> data;
};

/** Encodes a complete framed message. */
[[nodiscard]] std::vector<std::byte>
encode_frame(message_type type, std::uint64_t request_id,
             std::span<const std::byte> payload);

/** Decodes and validates a fixed-size frame header. */
[[nodiscard]] bool decode_header(std::span<const std::byte> encoded,
                                 frame_header &header,
                                 std::string &diagnostic) noexcept;

/** Encodes a secret identifier request. */
[[nodiscard]] std::vector<std::byte>
encode_id_request(std::string_view secret_id);

/** Decodes a secret identifier request. */
[[nodiscard]] bool decode_id_request(std::span<const std::byte> payload,
                                     std::string &secret_id,
                                     std::string &diagnostic);

/** Encodes a put-secret request payload. */
[[nodiscard]] std::vector<std::byte>
encode_put_request(std::string_view secret_id,
                   std::span<const std::byte> secret);

/** Decodes a put-secret request payload. */
[[nodiscard]] bool decode_put_request(std::span<const std::byte> payload,
                                      std::string &secret_id,
                                      std::vector<std::byte> &secret,
                                      std::string &diagnostic);

/** Encodes a sorted list of secret identifiers. */
[[nodiscard]] std::vector<std::byte>
encode_id_list(const std::vector<std::string> &secret_ids);

/** Decodes and validates a sorted list of secret identifiers. */
[[nodiscard]] bool decode_id_list(std::span<const std::byte> payload,
                                  std::vector<std::string> &secret_ids,
                                  std::string &diagnostic);

/** Encodes a generic response payload. */
[[nodiscard]] std::vector<std::byte>
encode_response(zeta_vault_status_t status, std::string_view diagnostic,
                std::span<const std::byte> data = {});

/** Decodes a generic response payload. */
[[nodiscard]] bool decode_response(std::span<const std::byte> payload,
                                   response_payload &response,
                                   std::string &diagnostic);

/** Returns whether a response type matches a request type. */
[[nodiscard]] bool is_matching_response(message_type request,
                                        message_type response) noexcept;

/** Returns the response type associated with a request type. */
[[nodiscard]] message_type response_type(message_type request);

} // namespace z::vault::protocol
