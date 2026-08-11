#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <span>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

#include <unistd.h>

#include <gtest/gtest.h>
#include <sodium.h>
#include <zpp/wire/writer.h>

#include "storage/vault_store.h"

namespace z::vault {
namespace {

/** Owns a temporary directory for one test scope. */
class temporary_directory {
public:
  temporary_directory() {
    path_ = std::filesystem::temp_directory_path() /
            std::filesystem::path{"zeta-vault-test-XXXXXX"};
    std::string value = path_.string();
    value.push_back('\0');
    char *created = ::mkdtemp(value.data());
    if (created == nullptr) {
      throw std::runtime_error("mkdtemp failed");
    }
    path_ = created;
  }

  temporary_directory(const temporary_directory &) = delete;
  temporary_directory &operator=(const temporary_directory &) = delete;

  ~temporary_directory() noexcept {
    std::error_code ignored;
    std::filesystem::remove_all(path_, ignored);
  }

  [[nodiscard]] std::filesystem::path path() const { return path_; }

private:
  std::filesystem::path path_;
};

void write_all(int descriptor, std::span<const std::byte> data) {
  std::size_t offset{0};
  while (offset < data.size()) {
    const auto written =
        ::write(descriptor, data.data() + offset, data.size() - offset);
    ASSERT_GT(written, 0);
    offset += static_cast<std::size_t>(written);
  }
}

void write_legacy_vault_with_invalid_id(const std::filesystem::path &path,
                                        std::string_view password,
                                        std::string_view legacy_id) {
  ASSERT_GE(sodium_init(), 0);
  constexpr std::array<std::byte, 8> magic{
      std::byte{'Z'}, std::byte{'V'}, std::byte{'L'}, std::byte{'T'},
      std::byte{'D'}, std::byte{'B'}, std::byte{'0'}, std::byte{'1'}};
  constexpr std::array<unsigned char, 13> associated_data{
      'z', 'e', 't', 'a', '_', 'v', 'a', 'u', 'l', 't', ':', 'v', '1'};
  constexpr std::array<std::byte, 1> value{std::byte{7}};
  std::array<unsigned char, crypto_pwhash_SALTBYTES> salt{};
  std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>
      nonce{};
  std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> key{};
  ASSERT_EQ(crypto_pwhash(
                key.data(), static_cast<unsigned long long>(key.size()),
                password.data(),
                static_cast<unsigned long long>(password.size()), salt.data(),
                crypto_pwhash_OPSLIMIT_MODERATE,
                crypto_pwhash_MEMLIMIT_MODERATE, crypto_pwhash_ALG_ARGON2ID13),
            0);

  std::vector<std::byte> plaintext(sizeof(std::uint32_t) * 3 +
                                   legacy_id.size() + value.size());
  z::wire::writer plaintext_writer{plaintext};
  ASSERT_TRUE(plaintext_writer.write_u32(1));
  ASSERT_TRUE(
      plaintext_writer.write_u32(static_cast<std::uint32_t>(legacy_id.size())));
  ASSERT_TRUE(
      plaintext_writer.write_bytes(std::as_bytes(std::span{legacy_id})));
  ASSERT_TRUE(
      plaintext_writer.write_u32(static_cast<std::uint32_t>(value.size())));
  ASSERT_TRUE(plaintext_writer.write_bytes(value));
  ASSERT_TRUE(plaintext_writer.complete());

  std::vector<std::byte> ciphertext(plaintext.size() +
                                    crypto_aead_xchacha20poly1305_ietf_ABYTES);
  unsigned long long ciphertext_size{0};
  ASSERT_EQ(crypto_aead_xchacha20poly1305_ietf_encrypt(
                reinterpret_cast<unsigned char *>(ciphertext.data()),
                &ciphertext_size,
                reinterpret_cast<const unsigned char *>(plaintext.data()),
                static_cast<unsigned long long>(plaintext.size()),
                associated_data.data(),
                static_cast<unsigned long long>(associated_data.size()),
                nullptr, nonce.data(), key.data()),
            0);
  ciphertext.resize(static_cast<std::size_t>(ciphertext_size));

  constexpr std::size_t header_size =
      magic.size() + sizeof(std::uint32_t) + 2 * sizeof(std::uint64_t) +
      crypto_pwhash_SALTBYTES + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES +
      sizeof(std::uint64_t);
  std::vector<std::byte> encoded(header_size + ciphertext.size());
  z::wire::writer writer{encoded};
  ASSERT_TRUE(writer.write_bytes(magic));
  ASSERT_TRUE(writer.write_u32(1));
  ASSERT_TRUE(writer.write_u64(
      static_cast<std::uint64_t>(crypto_pwhash_OPSLIMIT_MODERATE)));
  ASSERT_TRUE(writer.write_u64(
      static_cast<std::uint64_t>(crypto_pwhash_MEMLIMIT_MODERATE)));
  ASSERT_TRUE(writer.write_bytes(std::as_bytes(std::span{salt})));
  ASSERT_TRUE(writer.write_bytes(std::as_bytes(std::span{nonce})));
  ASSERT_TRUE(writer.write_u64(static_cast<std::uint64_t>(ciphertext.size())));
  ASSERT_TRUE(writer.write_bytes(ciphertext));
  ASSERT_TRUE(writer.complete());

  const int descriptor = ::open(
      path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, S_IRUSR | S_IWUSR);
  ASSERT_GE(descriptor, 0);
  write_all(descriptor, encoded);
  ASSERT_EQ(::close(descriptor), 0);
  sodium_memzero(key.data(), key.size());
  sodium_memzero(plaintext.data(), plaintext.size());
}

TEST(vault_store, persists_and_reopens_secrets) {
  temporary_directory directory;
  const auto path = directory.path() / "vault.bin";
  const std::array<std::byte, 4> original{std::byte{'t'}, std::byte{'e'},
                                          std::byte{'s'}, std::byte{'t'}};
  {
    vault_store store{path, "correct horse battery staple"};
    store.put("agent_openai_default", original);
    const auto loaded = store.get("agent_openai_default");
    EXPECT_TRUE(std::ranges::equal(loaded.view(), original));
  }
  {
    vault_store store{path, "correct horse battery staple"};
    const auto loaded = store.get("agent_openai_default");
    EXPECT_TRUE(std::ranges::equal(loaded.view(), original));
    EXPECT_TRUE(store.remove("agent_openai_default"));
    EXPECT_THROW(static_cast<void>(store.get("agent_openai_default")),
                 std::out_of_range);
  }
}

TEST(vault_store, validates_and_lists_secret_identifiers) {
  temporary_directory directory;
  vault_store store{directory.path() / "vault.bin", "password"};
  const std::array<std::byte, 1> value{std::byte{1}};
  store.put("trader_main", value);
  store.put("agent_beta", value);
  store.put("agent_alpha", value);
  EXPECT_EQ(store.list(), (std::vector<std::string>{"agent_alpha", "agent_beta",
                                                    "trader_main"}));
  EXPECT_THROW(store.put("agent/legacy", value), std::invalid_argument);
  EXPECT_THROW(static_cast<void>(store.get("Agent")), std::invalid_argument);
  EXPECT_THROW(static_cast<void>(store.remove("2agent")),
               std::invalid_argument);
}

TEST(vault_store, rejects_legacy_vault_with_invalid_identifier) {
  temporary_directory directory;
  const std::array<std::string, 2> invalid_identifiers{"agent/legacy",
                                                       std::string(64, 'a')};
  for (std::size_t index = 0; index < invalid_identifiers.size(); ++index) {
    const auto path =
        directory.path() / ("legacy-" + std::to_string(index) + ".bin");
    write_legacy_vault_with_invalid_id(path, "password",
                                       invalid_identifiers[index]);
    try {
      vault_store store{path, "password"};
      FAIL() << "legacy vault unexpectedly opened";
    } catch (const std::runtime_error &error) {
      EXPECT_NE(std::string_view{error.what()}.find("not permitted by v0.3.0"),
                std::string_view::npos);
      EXPECT_EQ(std::string_view{error.what()}.find(invalid_identifiers[index]),
                std::string_view::npos);
    }
  }
}

TEST(vault_store, rejects_wrong_password) {
  temporary_directory directory;
  const auto path = directory.path() / "vault.bin";
  {
    vault_store store{path, "first password"};
  }
  EXPECT_THROW(vault_store(path, "different password"), std::runtime_error);
}

TEST(vault_store, prevents_concurrent_open_of_same_file) {
  temporary_directory directory;
  const auto path = directory.path() / "vault.bin";
  vault_store first{path, "password"};
  EXPECT_THROW(vault_store(path, "password"), std::runtime_error);
}

TEST(vault_store, lock_erases_runtime_access) {
  temporary_directory directory;
  vault_store store{directory.path() / "vault.bin", "password"};
  store.lock();
  EXPECT_TRUE(store.locked());
  EXPECT_THROW(static_cast<void>(store.get("missing")), std::logic_error);
}

} // namespace
} // namespace z::vault
