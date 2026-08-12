#include <algorithm>
#include <array>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>

#include <gtest/gtest.h>

#include <zeta_vault/zeta_vault.h>

#include "server/server.h"
#include "storage/vault_store.h"

namespace z::vault {
namespace {

/** Owns a private temporary directory for an integration test. */
class temporary_directory {
public:
  /** Creates a new mode-0700 temporary directory. */
  temporary_directory() {
    path_ = std::filesystem::temp_directory_path() /
            std::filesystem::path{"zeta-vault-integration-XXXXXX"};
    std::string value = path_.string();
    value.push_back('\0');
    char *created = ::mkdtemp(value.data());
    if (created == nullptr) {
      throw std::runtime_error("mkdtemp failed");
    }
    path_ = created;
  }

  /** Temporary directories are not copyable. */
  temporary_directory(const temporary_directory &) = delete;

  /** Temporary directories are not copy assignable. */
  temporary_directory &operator=(const temporary_directory &) = delete;

  /** Removes the directory and its contents. */
  ~temporary_directory() noexcept {
    std::error_code ignored;
    std::filesystem::remove_all(path_, ignored);
  }

  /** Returns the temporary directory path. */
  [[nodiscard]] const std::filesystem::path &path() const noexcept {
    return path_;
  }

private:
  std::filesystem::path path_;
};

/** Stops and joins a running server thread on every test exit path. */
class server_thread_guard {
public:
  /** Starts guarding an existing server thread. */
  server_thread_guard(volatile std::sig_atomic_t &stop_requested,
                      std::thread &thread) noexcept
      : stop_requested_(stop_requested), thread_(thread) {}

  /** Thread guards are not copyable. */
  server_thread_guard(const server_thread_guard &) = delete;

  /** Thread guards are not copy assignable. */
  server_thread_guard &operator=(const server_thread_guard &) = delete;

  /** Requests shutdown and joins the server thread. */
  ~server_thread_guard() noexcept { stop(); }

  /** Requests shutdown and joins the server thread once. */
  void stop() noexcept {
    stop_requested_ = 1;
    if (thread_.joinable()) {
      thread_.join();
    }
  }

private:
  volatile std::sig_atomic_t &stop_requested_;
  std::thread &thread_;
};

/** Owns a C ABI client handle for one test scope. */
class client_guard {
public:
  /** Creates an empty client guard. */
  client_guard() noexcept = default;

  /** Client guards are not copyable. */
  client_guard(const client_guard &) = delete;

  /** Client guards are not copy assignable. */
  client_guard &operator=(const client_guard &) = delete;

  /** Destroys the guarded C ABI client. */
  ~client_guard() noexcept { reset(); }

  /** Destroys the current client handle once. */
  void reset() noexcept {
    zeta_vault_client_destroy(value);
    value = nullptr;
  }

  /** Returns the address used by the C create function. */
  [[nodiscard]] zeta_vault_client_t **out() noexcept { return &value; }

  /** Returns the guarded client handle. */
  [[nodiscard]] zeta_vault_client_t *get() const noexcept { return value; }

private:
  zeta_vault_client_t *value{nullptr};
};

/** Owns a C ABI secret result for one test scope. */
class secret_guard {
public:
  /** Secret guards are not copyable. */
  secret_guard(const secret_guard &) = delete;

  /** Secret guards are not copy assignable. */
  secret_guard &operator=(const secret_guard &) = delete;

  /** Creates an empty secret result. */
  secret_guard() noexcept = default;

  /** Erases and releases the guarded result. */
  ~secret_guard() noexcept { zeta_vault_secret_free(&value); }

  /** Returns the address used by the C get function. */
  [[nodiscard]] zeta_vault_secret_t *out() noexcept { return &value; }

  /** Returns the guarded secret result. */
  [[nodiscard]] const zeta_vault_secret_t &get() const noexcept {
    return value;
  }

private:
  zeta_vault_secret_t value{};
};

/** Owns a C ABI secret identifier list for one test scope. */
class secret_id_list_guard {
public:
  /** Creates an empty identifier list. */
  secret_id_list_guard() noexcept = default;

  /** Identifier list guards are not copyable. */
  secret_id_list_guard(const secret_id_list_guard &) = delete;

  /** Identifier list guards are not copy assignable. */
  secret_id_list_guard &operator=(const secret_id_list_guard &) = delete;

  /** Releases all listed identifiers. */
  ~secret_id_list_guard() noexcept { reset(); }

  /** Releases the list and leaves it empty. */
  void reset() noexcept { zeta_vault_secret_id_list_free(&value); }

  /** Returns the address used by the C list function. */
  [[nodiscard]] zeta_vault_secret_id_list_t *out() noexcept { return &value; }

  /** Returns the guarded identifier list. */
  [[nodiscard]] const zeta_vault_secret_id_list_t &get() const noexcept {
    return value;
  }

private:
  zeta_vault_secret_id_list_t value{};
};

TEST(server_client, reports_client_creation_diagnostics) {
  temporary_directory directory;
  const auto missing_endpoint = (directory.path() / "missing.sock").string();
  zeta_vault_client_options_t options{};
  options.struct_size = sizeof(options);
  options.endpoint = missing_endpoint.c_str();

  client_guard client;
  EXPECT_EQ(zeta_vault_client_create(&options, client.out()),
            ZETA_VAULT_STATUS_IO_ERROR);
  EXPECT_EQ(client.get(), nullptr);
  const char *diagnostic = zeta_vault_client_last_error(nullptr);
  ASSERT_NE(diagnostic, nullptr);
  EXPECT_NE(std::string_view{diagnostic}.find("connect:"),
            std::string_view::npos);
}

TEST(server_client, completes_secret_lifecycle_and_lock) {
  temporary_directory directory;
  const auto vault_path = directory.path() / "vault.bin";
  const auto endpoint = (directory.path() / "vault.sock").string();

  volatile std::sig_atomic_t stop_requested = 0;
  auto store =
      std::make_unique<vault_store>(vault_path, "integration password");
  server service{{vault_path, endpoint}, std::move(store)};
  int server_result = -1;
  std::string server_error;
  std::thread server_thread{[&] {
    try {
      server_result = service.run(stop_requested);
    } catch (const std::exception &exception) {
      server_error = exception.what();
      server_result = -2;
    }
  }};
  server_thread_guard thread_guard{stop_requested, server_thread};

  for (int attempt = 0; attempt < 100 && !std::filesystem::exists(endpoint);
       ++attempt) {
    std::this_thread::sleep_for(std::chrono::milliseconds{20});
  }
  ASSERT_TRUE(std::filesystem::exists(endpoint));

  zeta_vault_client_options_t options{};
  options.struct_size = sizeof(options);
  options.endpoint = endpoint.c_str();
  options.timeout_ms = 2000;
  client_guard client;
  ASSERT_EQ(zeta_vault_client_create(&options, client.out()),
            ZETA_VAULT_STATUS_OK);
  EXPECT_STREQ(zeta_vault_client_last_error(nullptr), "");

  secret_id_list_guard identifiers;
  ASSERT_EQ(zeta_vault_client_list_secrets(client.get(), identifiers.out()),
            ZETA_VAULT_STATUS_OK);
  EXPECT_EQ(identifiers.get().count, 0U);
  EXPECT_EQ(identifiers.get().items, nullptr);

  const std::array<std::uint8_t, 4> expected{1, 2, 3, 4};
  ASSERT_EQ(zeta_vault_client_put_secret(client.get(), "agent_test", 10,
                                         expected.data(), expected.size()),
            ZETA_VAULT_STATUS_OK);

  secret_guard secret;
  ASSERT_EQ(zeta_vault_client_put_secret(client.get(), "trader_main", 11,
                                         expected.data(), expected.size()),
            ZETA_VAULT_STATUS_OK);

  ASSERT_EQ(zeta_vault_client_list_secrets(client.get(), identifiers.out()),
            ZETA_VAULT_STATUS_OK);
  ASSERT_EQ(identifiers.get().count, 2U);
  EXPECT_STREQ(identifiers.get().items[0].data, "agent_test");
  EXPECT_EQ(identifiers.get().items[0].size, 10U);
  EXPECT_STREQ(identifiers.get().items[1].data, "trader_main");
  identifiers.reset();
  identifiers.reset();

  ASSERT_EQ(zeta_vault_client_get_secret(client.get(), "agent_test", 10,
                                         secret.out()),
            ZETA_VAULT_STATUS_OK);
  ASSERT_EQ(secret.get().size, expected.size());
  EXPECT_TRUE(std::equal(expected.begin(), expected.end(), secret.get().data));

  EXPECT_EQ(zeta_vault_client_remove_secret(client.get(), "agent_test", 10),
            ZETA_VAULT_STATUS_OK);
  secret_guard missing;
  EXPECT_EQ(zeta_vault_client_get_secret(client.get(), "agent_test", 10,
                                         missing.out()),
            ZETA_VAULT_STATUS_NOT_FOUND);
  EXPECT_EQ(zeta_vault_client_lock(client.get()), ZETA_VAULT_STATUS_OK);
  EXPECT_EQ(zeta_vault_client_list_secrets(client.get(), identifiers.out()),
            ZETA_VAULT_STATUS_LOCKED);
  EXPECT_EQ(zeta_vault_client_put_secret(client.get(), "agent_test", 10,
                                         expected.data(), expected.size()),
            ZETA_VAULT_STATUS_LOCKED);

  client.reset();
  thread_guard.stop();
  EXPECT_EQ(server_result, 0);
  EXPECT_TRUE(server_error.empty());
}

} // namespace
} // namespace z::vault
