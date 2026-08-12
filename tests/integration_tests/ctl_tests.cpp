#include <array>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <memory>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include "ctl/ctl.h"
#include "server/server.h"
#include "storage/vault_store.h"

namespace z::vault::ctl {
namespace {

/** Owns a private temporary directory for one CLI integration test. */
class temporary_directory {
public:
  /** Creates a new mode-0700 temporary directory. */
  temporary_directory() {
    path_ = std::filesystem::temp_directory_path() /
            std::filesystem::path{"zeta-vault-ctl-XXXXXX"};
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

/** Stops and joins one server thread on every exit path. */
class server_thread_guard {
public:
  /** Starts guarding an existing server thread. */
  server_thread_guard(volatile std::sig_atomic_t &stop_requested,
                      std::thread &thread) noexcept
      : stop_requested_(stop_requested), thread_(thread) {}

  /** Server thread guards are not copyable. */
  server_thread_guard(const server_thread_guard &) = delete;

  /** Server thread guards are not copy assignable. */
  server_thread_guard &operator=(const server_thread_guard &) = delete;

  /** Stops and joins the guarded thread. */
  ~server_thread_guard() noexcept { stop(); }

  /** Stops and joins the guarded thread once. */
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

void write_test_file(const std::filesystem::path &path,
                     std::span<const std::byte> data, mode_t mode) {
  const int descriptor =
      ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode);
  ASSERT_GE(descriptor, 0);
  std::size_t offset{0};
  while (offset < data.size()) {
    const auto written =
        ::write(descriptor, data.data() + offset, data.size() - offset);
    ASSERT_GT(written, 0);
    offset += static_cast<std::size_t>(written);
  }
  ASSERT_EQ(::fchmod(descriptor, mode), 0);
  ASSERT_EQ(::close(descriptor), 0);
}

[[nodiscard]] std::vector<std::byte>
read_test_file(const std::filesystem::path &path) {
  const auto size = std::filesystem::file_size(path);
  std::vector<std::byte> data(static_cast<std::size_t>(size));
  const int descriptor = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (descriptor < 0) {
    ADD_FAILURE() << "failed to open test file: " << path;
    return {};
  }
  std::size_t offset{0};
  while (offset < data.size()) {
    const auto received =
        ::read(descriptor, data.data() + offset, data.size() - offset);
    EXPECT_GT(received, 0);
    if (received <= 0) {
      break;
    }
    offset += static_cast<std::size_t>(received);
  }
  EXPECT_EQ(::close(descriptor), 0);
  return data;
}

[[nodiscard]] secret_input make_secret_input(std::string_view value) {
  return secret_input{
      std::as_bytes(std::span<const char>{value.data(), value.size()})};
}

int invoke(std::vector<std::string> arguments, std::string &output,
           std::string &error) {
  std::vector<char *> values;
  values.reserve(arguments.size());
  for (auto &argument : arguments) {
    values.push_back(argument.data());
  }
  std::ostringstream captured_output;
  std::ostringstream captured_error;
  const int result = run(static_cast<int>(values.size()), values.data(),
                         captured_output, captured_error);
  output = captured_output.str();
  error = captured_error.str();
  return result;
}

int invoke_with_hidden_input(std::vector<std::string> arguments,
                             const hidden_input_reader &read_hidden_input,
                             std::string &output, std::string &error) {
  std::vector<char *> values;
  values.reserve(arguments.size());
  for (auto &argument : arguments) {
    values.push_back(argument.data());
  }
  std::ostringstream captured_output;
  std::ostringstream captured_error;
  const int result =
      run_with_hidden_input(static_cast<int>(values.size()), values.data(),
                            captured_output, captured_error, read_hidden_input);
  output = captured_output.str();
  error = captured_error.str();
  return result;
}

TEST(ctl, reads_and_validates_hidden_input_before_connecting) {
  temporary_directory directory;
  const auto missing_endpoint = (directory.path() / "missing.sock").string();
  std::size_t hidden_reader_calls{0};
  const hidden_input_reader invalid_reader = [&](std::string_view, std::size_t,
                                                 std::string_view) {
    ++hidden_reader_calls;
    return make_secret_input("");
  };
  const hidden_input_reader valid_reader = [&](std::string_view, std::size_t,
                                               std::string_view) {
    ++hidden_reader_calls;
    return make_secret_input("delayed secret");
  };

  std::string output;
  std::string error;
  EXPECT_EQ(
      invoke_with_hidden_input({"zeta_vault_ctl", "--socket", missing_endpoint,
                                "put-utf8", "invalid_secret"},
                               invalid_reader, output, error),
      1);
  EXPECT_EQ(hidden_reader_calls, 1U);
  EXPECT_TRUE(output.empty());
  EXPECT_NE(error.find("must not be empty"), std::string::npos);
  EXPECT_EQ(error.find("connect:"), std::string::npos);

  EXPECT_EQ(
      invoke_with_hidden_input({"zeta_vault_ctl", "--socket", missing_endpoint,
                                "put-utf8", "delayed_secret"},
                               valid_reader, output, error),
      1);
  EXPECT_EQ(hidden_reader_calls, 2U);
  EXPECT_TRUE(output.empty());
  EXPECT_NE(error.find("I/O error"), std::string::npos);
}

TEST(ctl, completes_binary_file_lifecycle_and_enforces_file_safety) {
  temporary_directory directory;
  const auto vault_path = directory.path() / "vault.bin";
  const auto endpoint = (directory.path() / "vault.sock").string();

  volatile std::sig_atomic_t stop_requested = 0;
  auto store = std::make_unique<vault_store>(vault_path, "ctl password");
  server service{{vault_path, endpoint}, std::move(store)};
  int server_result = -1;
  std::string server_error;
  std::thread server_thread{[&] {
    try {
      server_result = service.run(stop_requested);
    } catch (const std::exception &exception) {
      server_error = exception.what();
    }
  }};
  server_thread_guard thread_guard{stop_requested, server_thread};
  for (int attempt = 0; attempt < 100 && !std::filesystem::exists(endpoint);
       ++attempt) {
    std::this_thread::sleep_for(std::chrono::milliseconds{20});
  }
  ASSERT_TRUE(std::filesystem::exists(endpoint));

  const std::array<std::byte, 5> expected{
      std::byte{0}, std::byte{1}, std::byte{2}, std::byte{0xff}, std::byte{4}};
  const auto input = directory.path() / "input.bin";
  const auto output_path = directory.path() / "output.bin";
  write_test_file(input, expected, S_IRUSR | S_IWUSR);

  std::string output;
  std::string error;
  EXPECT_EQ(invoke({"zeta_vault_ctl", "--help"}, output, error), 0);
  EXPECT_NE(output.find("put-utf8 ID"), std::string::npos);
  EXPECT_TRUE(error.empty());

  EXPECT_EQ(invoke({"zeta_vault_ctl", "--socket", endpoint, "put",
                    "binary_secret", input.string()},
                   output, error),
            0);
  EXPECT_TRUE(error.empty());
  EXPECT_EQ(invoke({"zeta_vault_ctl", "--socket", endpoint, "put",
                    "alpha_secret", input.string()},
                   output, error),
            0);

  const std::string utf8_value{
      "api key \xc2\xa9 \xe4\xb8\xad\xe6\x96\x87 \xf0\x9f\x94\x91"};
  const auto utf8_bytes = std::as_bytes(
      std::span<const char>{utf8_value.data(), utf8_value.size()});
  const std::vector<std::byte> expected_utf8{utf8_bytes.begin(),
                                             utf8_bytes.end()};
  bool hidden_reader_called{false};
  const hidden_input_reader valid_reader = [&](std::string_view prompt,
                                               std::size_t maximum_size,
                                               std::string_view value_name) {
    hidden_reader_called = true;
    EXPECT_EQ(prompt, "Secret value for utf8_secret (UTF-8, input hidden): ");
    EXPECT_EQ(maximum_size, 1024U * 1024U);
    EXPECT_EQ(value_name, "UTF-8 secret");
    return make_secret_input(utf8_value);
  };
  EXPECT_EQ(invoke_with_hidden_input({"zeta_vault_ctl", "--socket", endpoint,
                                      "put-utf8", "utf8_secret"},
                                     valid_reader, output, error),
            0);
  EXPECT_TRUE(hidden_reader_called);
  EXPECT_TRUE(error.empty());
  EXPECT_EQ(output, "stored utf8_secret (" + std::to_string(utf8_value.size()) +
                        " bytes)\n");

  EXPECT_EQ(invoke({"zeta_vault_ctl", "--socket", endpoint, "put-utf8",
                    "unexpected_argument", "not-a-secret"},
                   output, error),
            2);
  EXPECT_NE(error.find("exactly one secret identifier"), std::string::npos);
  EXPECT_EQ(error.find("not-a-secret"), std::string::npos);

  const std::vector<std::string> invalid_utf8_values{
      std::string{},
      std::string{"\0", 1},
      std::string{"line\nbreak"},
      std::string{"line\rbreak"},
      std::string{"\x80", 1},
      std::string{"\xc0\xaf", 2},
      std::string{"\xe2\x82", 2},
      std::string{"\xed\xa0\x80", 3},
      std::string{"\xf4\x90\x80\x80", 4},
  };
  for (const auto &invalid_value : invalid_utf8_values) {
    const hidden_input_reader invalid_reader =
        [&](std::string_view, std::size_t, std::string_view) {
          return make_secret_input(invalid_value);
        };
    EXPECT_EQ(invoke_with_hidden_input({"zeta_vault_ctl", "--socket", endpoint,
                                        "put-utf8", "invalid_utf8"},
                                       invalid_reader, output, error),
              1);
    EXPECT_TRUE(output.empty());
    EXPECT_TRUE(error.find("must not be empty") != std::string::npos ||
                error.find("one valid line") != std::string::npos);
  }

  const std::string oversized_value(1024U * 1024U + 1U, 'x');
  const hidden_input_reader oversized_reader =
      [&](std::string_view, std::size_t, std::string_view) {
        return make_secret_input(oversized_value);
      };
  EXPECT_EQ(invoke_with_hidden_input({"zeta_vault_ctl", "--socket", endpoint,
                                      "put-utf8", "oversized_utf8"},
                                     oversized_reader, output, error),
            1);
  EXPECT_NE(error.find("1 MiB limit"), std::string::npos);

  EXPECT_EQ(
      invoke({"zeta_vault_ctl", "--socket", endpoint, "list"}, output, error),
      0);
  EXPECT_EQ(output, "alpha_secret\nbinary_secret\nutf8_secret\n");
  EXPECT_TRUE(error.empty());

  EXPECT_EQ(invoke({"zeta_vault_ctl", "--socket", endpoint, "get",
                    "binary_secret", output_path.string()},
                   output, error),
            0);
  EXPECT_EQ(read_test_file(output_path),
            std::vector<std::byte>(expected.begin(), expected.end()));

  const auto utf8_output_path = directory.path() / "utf8-output.bin";
  EXPECT_EQ(invoke({"zeta_vault_ctl", "--socket", endpoint, "get",
                    "utf8_secret", utf8_output_path.string()},
                   output, error),
            0);
  EXPECT_EQ(read_test_file(utf8_output_path), expected_utf8);
  struct stat output_metadata{};
  ASSERT_EQ(::stat(output_path.c_str(), &output_metadata), 0);
  EXPECT_EQ(output_metadata.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO),
            S_IRUSR | S_IWUSR);

  EXPECT_EQ(invoke({"zeta_vault_ctl", "--socket", endpoint, "get",
                    "binary_secret", output_path.string()},
                   output, error),
            1);
  EXPECT_NE(error.find("already exists"), std::string::npos);
  EXPECT_EQ(read_test_file(output_path),
            std::vector<std::byte>(expected.begin(), expected.end()));

  const auto public_input = directory.path() / "public.bin";
  write_test_file(public_input, expected,
                  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  EXPECT_EQ(invoke({"zeta_vault_ctl", "--socket", endpoint, "put",
                    "public_secret", public_input.string()},
                   output, error),
            1);
  EXPECT_NE(error.find("permissions"), std::string::npos);

  const auto input_link = directory.path() / "input-link.bin";
  std::filesystem::create_symlink(input, input_link);
  ASSERT_TRUE(std::filesystem::is_symlink(input_link));
  EXPECT_EQ(invoke({"zeta_vault_ctl", "--socket", endpoint, "put",
                    "linked_secret", input_link.string()},
                   output, error),
            1);

  EXPECT_EQ(invoke({"zeta_vault_ctl", "--socket", endpoint, "remove",
                    "binary_secret"},
                   output, error),
            0);
  EXPECT_EQ(invoke({"zeta_vault_ctl", "--socket", endpoint, "remove",
                    "binary_secret"},
                   output, error),
            1);
  EXPECT_EQ(
      invoke({"zeta_vault_ctl", "--socket", endpoint, "remove", "alpha_secret"},
             output, error),
      0);
  EXPECT_EQ(
      invoke({"zeta_vault_ctl", "--socket", endpoint, "remove", "utf8_secret"},
             output, error),
      0);
  EXPECT_EQ(
      invoke({"zeta_vault_ctl", "--socket", endpoint, "list"}, output, error),
      0);
  EXPECT_TRUE(output.empty());

  thread_guard.stop();
  EXPECT_TRUE(server_error.empty()) << server_error;
  EXPECT_EQ(server_result, 0);
}

} // namespace
} // namespace z::vault::ctl
