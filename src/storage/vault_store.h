#pragma once

#include <array>
#include <cstddef>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <sodium.h>

#include "storage/secure_bytes.h"

namespace z::vault {

/** Encrypted local storage for exportable secrets. */
class vault_store {
public:
  /** Opens an existing vault or creates a new one. */
  vault_store(std::filesystem::path path, std::string_view password);

  /** Store instances are not copyable. */
  vault_store(const vault_store &) = delete;

  /** Store instances are not copy assignable. */
  vault_store &operator=(const vault_store &) = delete;

  /** Erases in-memory key material and releases the file lock. */
  ~vault_store() noexcept;

  /** Returns whether the store has been locked. */
  [[nodiscard]] bool locked() const noexcept { return locked_; }

  /** Stores or replaces a secret and persists the vault. */
  void put(std::string_view id, std::span<const std::byte> value);

  /** Retrieves a secret copy into secure storage. */
  [[nodiscard]] secure_bytes get(std::string_view id) const;

  /** Removes a secret and persists the vault. */
  [[nodiscard]] bool remove(std::string_view id);

  /** Returns all secret identifiers in lexical order. */
  [[nodiscard]] std::vector<std::string> list() const;

  /** Erases all in-memory key material until process restart. */
  void lock() noexcept;

private:
  /** Fixed-size data-encryption key material. */
  using key_type =
      std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_KEYBYTES>;
  /** Fixed-size Argon2id salt material. */
  using salt_type = std::array<unsigned char, crypto_pwhash_SALTBYTES>;
  /** In-memory mapping from public identifiers to protected secret buffers. */
  using secret_map = std::unordered_map<std::string, secure_bytes>;

  void acquire_file_lock();
  void release_file_lock() noexcept;
  void create_new(std::string_view password);
  void load_existing(std::string_view password);
  void derive_key(std::string_view password);
  void persist(const secret_map &secrets) const;
  [[nodiscard]] std::vector<std::byte>
  serialize_plaintext(const secret_map &secrets) const;
  void deserialize_plaintext(std::span<const std::byte> plaintext);
  [[nodiscard]] static secret_map clone_secrets(const secret_map &source);
  void require_unlocked() const;

  std::filesystem::path path_;
  key_type key_{};
  salt_type salt_{};
  std::uint64_t opslimit_{crypto_pwhash_OPSLIMIT_MODERATE};
  std::uint64_t memlimit_{crypto_pwhash_MEMLIMIT_MODERATE};
  secret_map secrets_;
  int lock_fd_{-1};
  bool locked_{true};
};

} // namespace z::vault
