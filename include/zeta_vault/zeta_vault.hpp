#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <zeta_vault/zeta_vault.h>

namespace z::vault {

/** Exception raised by the header-only C++ wrapper. */
class error : public std::runtime_error {
public:
  /** Creates an error with the originating C ABI status. */
  error(zeta_vault_status_t status, std::string message)
      : std::runtime_error(std::move(message)), status_(status) {}

  /** Returns the originating C ABI status. */
  [[nodiscard]] zeta_vault_status_t status() const noexcept { return status_; }

private:
  zeta_vault_status_t status_;
};

/** Move-only secret buffer that erases itself through the C ABI. */
class secret {
public:
  /** Creates an empty secret buffer. */
  secret() noexcept = default;

  /** Takes ownership of a C ABI secret buffer. */
  explicit secret(zeta_vault_secret_t value) noexcept : value_(value) {}

  /** Secret buffers are not copyable. */
  secret(const secret &) = delete;

  /** Secret buffers are not copy assignable. */
  secret &operator=(const secret &) = delete;

  /** Moves a secret buffer. */
  secret(secret &&other) noexcept
      : value_(std::exchange(other.value_, zeta_vault_secret_t{})) {}

  /** Replaces this secret buffer by moving another buffer. */
  secret &operator=(secret &&other) noexcept {
    if (this != &other) {
      reset();
      value_ = std::exchange(other.value_, zeta_vault_secret_t{});
    }
    return *this;
  }

  /** Securely erases and releases the buffer. */
  ~secret() noexcept { reset(); }

  /** Returns a read-only byte view. */
  [[nodiscard]] std::span<const std::byte> bytes() const noexcept {
    return {reinterpret_cast<const std::byte *>(value_.data), value_.size};
  }

  /** Returns whether the buffer contains no bytes. */
  [[nodiscard]] bool empty() const noexcept { return value_.size == 0; }

  /** Returns the number of bytes in the secret. */
  [[nodiscard]] std::size_t size() const noexcept { return value_.size; }

  /** Securely erases and releases the current buffer. */
  void reset() noexcept { zeta_vault_secret_free(&value_); }

private:
  zeta_vault_secret_t value_{};
};

/**
 * Header-only RAII wrapper around the stable zeta_vault C ABI.
 *
 * Instances are single-threaded; use separate clients or external
 * synchronization for concurrent access.
 */
class client {
public:
  /** Connects to the default zeta_vault endpoint. */
  client() { create(nullptr, 0); }

  /** Connects to the default endpoint with a specific timeout. */
  explicit client(std::uint32_t timeout_ms) { create(nullptr, timeout_ms); }

  /** Connects to a specific Unix socket endpoint. */
  explicit client(std::string_view endpoint, std::uint32_t timeout_ms = 0) {
    endpoint_storage_.assign(endpoint);
    create(endpoint_storage_.c_str(), timeout_ms);
  }

  /** Client handles are not copyable. */
  client(const client &) = delete;

  /** Client handles are not copy assignable. */
  client &operator=(const client &) = delete;

  /** Moves a client handle. */
  client(client &&other) noexcept
      : handle_(std::exchange(other.handle_, nullptr)),
        endpoint_storage_(std::move(other.endpoint_storage_)) {}

  /** Replaces this client handle by moving another handle. */
  client &operator=(client &&other) noexcept {
    if (this != &other) {
      reset();
      handle_ = std::exchange(other.handle_, nullptr);
      endpoint_storage_ = std::move(other.endpoint_storage_);
    }
    return *this;
  }

  /** Closes the client connection. */
  ~client() noexcept { reset(); }

  /** Checks server availability. */
  void ping() { check(zeta_vault_client_ping(handle_)); }

  /** Stores or replaces a secret. */
  void put(std::string_view id, std::span<const std::byte> value) {
    check(zeta_vault_client_put_secret(
        handle_, id.data(), id.size(),
        reinterpret_cast<const std::uint8_t *>(value.data()), value.size()));
  }

  /** Retrieves an exportable secret. */
  [[nodiscard]] secret get(std::string_view id) {
    zeta_vault_secret_t value{};
    check(zeta_vault_client_get_secret(handle_, id.data(), id.size(), &value));
    return secret{value};
  }

  /** Removes a secret. */
  void remove(std::string_view id) {
    check(zeta_vault_client_remove_secret(handle_, id.data(), id.size()));
  }

  /** Lists all secret identifiers in lexical order. */
  [[nodiscard]] std::vector<std::string> list() {
    zeta_vault_secret_id_list_t identifiers{};
    check(zeta_vault_client_list_secrets(handle_, &identifiers));
    try {
      std::vector<std::string> result;
      result.reserve(identifiers.count);
      for (std::size_t index = 0; index < identifiers.count; ++index) {
        const auto &identifier = identifiers.items[index];
        result.emplace_back(identifier.data, identifier.size);
      }
      zeta_vault_secret_id_list_free(&identifiers);
      return result;
    } catch (...) {
      zeta_vault_secret_id_list_free(&identifiers);
      throw;
    }
  }

  /** Locks the server. */
  void lock() { check(zeta_vault_client_lock(handle_)); }

private:
  void create(const char *endpoint, std::uint32_t timeout_ms) {
    zeta_vault_client_options_t options{};
    options.struct_size = sizeof(options);
    options.endpoint = endpoint;
    options.timeout_ms = timeout_ms;
    const auto status = zeta_vault_client_create(&options, &handle_);
    if (status != ZETA_VAULT_STATUS_OK) {
      const char *detail = zeta_vault_client_last_error(nullptr);
      std::string message = zeta_vault_status_name(status);
      if (detail != nullptr && *detail != '\0') {
        message.append(": ").append(detail);
      }
      throw error(status, std::move(message));
    }
  }

  void check(zeta_vault_status_t status) const {
    if (status == ZETA_VAULT_STATUS_OK) {
      return;
    }
    const char *detail = zeta_vault_client_last_error(handle_);
    std::string message = zeta_vault_status_name(status);
    if (detail != nullptr && *detail != '\0') {
      message.append(": ").append(detail);
    }
    throw error(status, std::move(message));
  }

  void reset() noexcept {
    zeta_vault_client_destroy(handle_);
    handle_ = nullptr;
  }

  zeta_vault_client_t *handle_{nullptr};
  std::string endpoint_storage_;
};

} // namespace z::vault
