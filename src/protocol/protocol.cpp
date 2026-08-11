#include "protocol/protocol.h"

#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>

#include <zpp/wire/reader.h>
#include <zpp/wire/size_counter.h>
#include <zpp/wire/writer.h>

#include "common/secret_id.h"

namespace z::vault::protocol {
namespace {

constexpr std::array<std::byte, 4> magic{std::byte{'Z'}, std::byte{'V'},
                                         std::byte{'L'}, std::byte{'T'}};
constexpr std::uint32_t reserved = 0;
constexpr std::size_t maximum_secret_count = 10000;
constexpr std::size_t maximum_diagnostic_size = 64U * 1024U;

/** Erases a partially encoded sensitive buffer after an exception. */
class wipe_on_failure {
public:
  explicit wipe_on_failure(std::vector<std::byte> &value) noexcept
      : value_(value) {}
  wipe_on_failure(const wipe_on_failure &) = delete;
  wipe_on_failure &operator=(const wipe_on_failure &) = delete;
  ~wipe_on_failure() noexcept {
    if (active_ && !value_.empty()) {
      std::fill(value_.begin(), value_.end(), std::byte{0});
    }
  }
  void release() noexcept { active_ = false; }

private:
  std::vector<std::byte> &value_;
  bool active_{true};
};

std::span<const std::byte> as_bytes(std::string_view value) noexcept {
  return {reinterpret_cast<const std::byte *>(value.data()), value.size()};
}

template <typename Writer>
bool write_sized_bytes(Writer &writer, std::span<const std::byte> value) {
  if (value.size() > std::numeric_limits<std::uint32_t>::max()) {
    return false;
  }
  return writer.write_u32(static_cast<std::uint32_t>(value.size())) &&
         writer.write_bytes(value);
}

template <typename Writer>
bool write_string(Writer &writer, std::string_view value) {
  return write_sized_bytes(writer, as_bytes(value));
}

bool read_sized_bytes(z::wire::reader &reader, std::vector<std::byte> &value,
                      std::size_t maximum_size) {
  std::uint32_t encoded_size{0};
  if (!reader.read_u32(encoded_size) || encoded_size > maximum_size ||
      encoded_size > reader.remaining()) {
    return false;
  }
  value.resize(encoded_size);
  return reader.read_bytes(value);
}

bool read_string(z::wire::reader &reader, std::string &value,
                 std::size_t maximum_size) {
  std::vector<std::byte> bytes;
  if (!read_sized_bytes(reader, bytes, maximum_size)) {
    return false;
  }
  value.assign(reinterpret_cast<const char *>(bytes.data()), bytes.size());
  return true;
}

template <typename Encode>
std::vector<std::byte> encode_payload(Encode &&encode) {
  z::wire::size_counter counter;
  if (!encode(counter) || !counter.ok() ||
      counter.size() > maximum_payload_size) {
    throw std::length_error("vault protocol payload exceeds the limit");
  }
  std::vector<std::byte> payload(counter.size());
  wipe_on_failure guard{payload};
  z::wire::writer writer{payload};
  if (!encode(writer) || !writer.complete()) {
    throw std::runtime_error("vault protocol payload encoding failed");
  }
  guard.release();
  return payload;
}

} // namespace

std::vector<std::byte> encode_frame(message_type type, std::uint64_t request_id,
                                    std::span<const std::byte> payload) {
  if (payload.size() > maximum_payload_size ||
      payload.size() > std::numeric_limits<std::uint32_t>::max()) {
    throw std::length_error("vault frame payload exceeds the limit");
  }
  std::vector<std::byte> encoded(header_size + payload.size());
  wipe_on_failure guard{encoded};
  z::wire::writer writer{encoded};
  if (!writer.write_bytes(magic) || !writer.write_u16(version) ||
      !writer.write_u16(static_cast<std::uint16_t>(type)) ||
      !writer.write_u64(request_id) ||
      !writer.write_u32(static_cast<std::uint32_t>(payload.size())) ||
      !writer.write_u32(reserved) || !writer.write_bytes(payload) ||
      !writer.complete()) {
    throw std::runtime_error("vault frame encoding failed");
  }
  guard.release();
  return encoded;
}

bool decode_header(std::span<const std::byte> encoded, frame_header &header,
                   std::string &diagnostic) noexcept {
  diagnostic.clear();
  if (encoded.size() != header_size) {
    diagnostic = "invalid frame header size";
    return false;
  }
  z::wire::reader reader{encoded};
  std::array<std::byte, magic.size()> decoded_magic{};
  std::uint16_t type{0};
  std::uint32_t decoded_reserved{0};
  if (!reader.read_bytes(decoded_magic) ||
      !reader.read_u16(header.protocol_version) || !reader.read_u16(type) ||
      !reader.read_u64(header.request_id) ||
      !reader.read_u32(header.payload_size) ||
      !reader.read_u32(decoded_reserved) || !reader.complete()) {
    diagnostic = "truncated frame header";
    return false;
  }
  if (decoded_magic != magic) {
    diagnostic = "invalid frame magic";
    return false;
  }
  if (header.protocol_version != version) {
    diagnostic = "unsupported protocol version";
    return false;
  }
  if (decoded_reserved != reserved) {
    diagnostic = "non-zero reserved header field";
    return false;
  }
  if (header.payload_size > maximum_payload_size) {
    diagnostic = "frame payload exceeds the limit";
    return false;
  }
  header.type = static_cast<message_type>(type);
  return true;
}

std::vector<std::byte> encode_id_request(std::string_view secret_id) {
  if (!is_valid_secret_id(secret_id)) {
    throw std::invalid_argument("invalid secret identifier");
  }
  return encode_payload(
      [secret_id](auto &writer) { return write_string(writer, secret_id); });
}

bool decode_id_request(std::span<const std::byte> payload,
                       std::string &secret_id, std::string &diagnostic) {
  diagnostic.clear();
  z::wire::reader reader{payload};
  if (!read_string(reader, secret_id, maximum_secret_id_size) ||
      !is_valid_secret_id(secret_id) || !reader.complete()) {
    diagnostic = "invalid secret identifier payload";
    return false;
  }
  return true;
}

std::vector<std::byte> encode_put_request(std::string_view secret_id,
                                          std::span<const std::byte> secret) {
  if (!is_valid_secret_id(secret_id) || secret.size() > maximum_payload_size) {
    throw std::invalid_argument("invalid put-secret payload size");
  }
  return encode_payload([secret_id, secret](auto &writer) {
    return write_string(writer, secret_id) && write_sized_bytes(writer, secret);
  });
}

bool decode_put_request(std::span<const std::byte> payload,
                        std::string &secret_id, std::vector<std::byte> &secret,
                        std::string &diagnostic) {
  diagnostic.clear();
  z::wire::reader reader{payload};
  if (!read_string(reader, secret_id, maximum_secret_id_size) ||
      !is_valid_secret_id(secret_id) ||
      !read_sized_bytes(reader, secret, maximum_payload_size) ||
      !reader.complete()) {
    diagnostic = "invalid put-secret payload";
    return false;
  }
  return true;
}

std::vector<std::byte>
encode_id_list(const std::vector<std::string> &secret_ids) {
  if (secret_ids.size() > maximum_secret_count) {
    throw std::invalid_argument("secret identifier count exceeds the limit");
  }
  return encode_payload([&secret_ids](auto &writer) {
    if (!writer.write_u32(static_cast<std::uint32_t>(secret_ids.size()))) {
      return false;
    }
    std::string_view previous;
    bool has_previous = false;
    for (const auto &identifier : secret_ids) {
      if (!is_valid_secret_id(identifier) ||
          (has_previous && identifier <= previous) ||
          !write_string(writer, identifier)) {
        return false;
      }
      previous = identifier;
      has_previous = true;
    }
    return true;
  });
}

bool decode_id_list(std::span<const std::byte> payload,
                    std::vector<std::string> &secret_ids,
                    std::string &diagnostic) {
  diagnostic.clear();
  z::wire::reader reader{payload};
  std::uint32_t count{0};
  if (!reader.read_u32(count) || count > maximum_secret_count) {
    diagnostic = "invalid secret identifier list count";
    return false;
  }
  std::vector<std::string> decoded;
  decoded.reserve(count);
  for (std::uint32_t index = 0; index < count; ++index) {
    std::string identifier;
    if (!read_string(reader, identifier, maximum_secret_id_size) ||
        !is_valid_secret_id(identifier) ||
        (!decoded.empty() && identifier <= decoded.back())) {
      diagnostic = "invalid secret identifier list";
      return false;
    }
    decoded.push_back(std::move(identifier));
  }
  if (!reader.complete()) {
    diagnostic = "trailing bytes in secret identifier list";
    return false;
  }
  secret_ids = std::move(decoded);
  return true;
}

std::vector<std::byte> encode_response(zeta_vault_status_t status,
                                       std::string_view diagnostic,
                                       std::span<const std::byte> data) {
  if (diagnostic.size() > maximum_diagnostic_size ||
      data.size() > maximum_payload_size) {
    throw std::invalid_argument("invalid response payload size");
  }
  return encode_payload([status, diagnostic, data](auto &writer) {
    return writer.write_u32(static_cast<std::uint32_t>(status)) &&
           write_string(writer, diagnostic) && write_sized_bytes(writer, data);
  });
}

bool decode_response(std::span<const std::byte> payload,
                     response_payload &response, std::string &diagnostic) {
  diagnostic.clear();
  z::wire::reader reader{payload};
  std::uint32_t status{0};
  if (!reader.read_u32(status) ||
      !read_string(reader, response.diagnostic, maximum_diagnostic_size) ||
      !read_sized_bytes(reader, response.data, maximum_payload_size) ||
      !reader.complete()) {
    diagnostic = "invalid response payload";
    return false;
  }
  if (status > ZETA_VAULT_STATUS_INTERNAL_ERROR) {
    diagnostic = "unknown response status";
    return false;
  }
  response.status = static_cast<zeta_vault_status_t>(status);
  return true;
}

bool is_matching_response(message_type request,
                          message_type response) noexcept {
  try {
    return response_type(request) == response;
  } catch (...) {
    return false;
  }
}

message_type response_type(message_type request) {
  switch (request) {
  case message_type::ping_request:
    return message_type::ping_response;
  case message_type::put_secret_request:
    return message_type::put_secret_response;
  case message_type::get_secret_request:
    return message_type::get_secret_response;
  case message_type::remove_secret_request:
    return message_type::remove_secret_response;
  case message_type::lock_request:
    return message_type::lock_response;
  case message_type::list_secrets_request:
    return message_type::list_secrets_response;
  default:
    throw std::invalid_argument("message type is not a request");
  }
}

} // namespace z::vault::protocol
