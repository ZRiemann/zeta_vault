#include "ctl/ctl.h"

#include <array>
#include <cerrno>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <limits>
#include <ostream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <sodium.h>

#include <zeta_vault/zeta_vault.hpp>

#include "common/secret_id.h"

namespace z::vault::ctl {
namespace {

constexpr std::size_t maximum_secret_size = 1024U * 1024U;

/** Supported zeta_vault_ctl operations. */
enum class operation { put, put_utf8, get, show_utf8, remove, list };

/** Fully parsed command-line request. */
struct command_line {
  operation command{operation::list};
  std::string socket;
  std::uint32_t timeout_ms{0};
  std::string secret_id;
  std::filesystem::path secret_path;
};

/** Error caused by invalid command-line syntax. */
class usage_error : public std::invalid_argument {
public:
  /** Creates one usage error. */
  using std::invalid_argument::invalid_argument;
};

/** Owns one POSIX file descriptor. */
class file_descriptor {
public:
  /** Takes ownership of a descriptor. */
  explicit file_descriptor(int value) noexcept : value_(value) {}

  /** File descriptors are not copyable. */
  file_descriptor(const file_descriptor &) = delete;

  /** File descriptors are not copy assignable. */
  file_descriptor &operator=(const file_descriptor &) = delete;

  /** Closes the descriptor. */
  ~file_descriptor() noexcept { close(); }

  /** Returns the owned descriptor. */
  [[nodiscard]] int get() const noexcept { return value_; }

  /** Closes the descriptor and reports an error. */
  void close_checked() {
    if (value_ >= 0 && ::close(value_) != 0) {
      value_ = -1;
      throw std::runtime_error(std::string{"close file: "} +
                               std::strerror(errno));
    }
    value_ = -1;
  }

private:
  void close() noexcept {
    if (value_ >= 0) {
      (void)::close(value_);
      value_ = -1;
    }
  }

  int value_{-1};
};

/** Erases a temporary plaintext buffer when leaving scope. */
class buffer_wipe_guard {
public:
  /** Starts guarding one plaintext buffer. */
  explicit buffer_wipe_guard(std::vector<std::byte> &value) noexcept
      : value_(value) {}

  /** Wipe guards are not copyable. */
  buffer_wipe_guard(const buffer_wipe_guard &) = delete;

  /** Wipe guards are not copy assignable. */
  buffer_wipe_guard &operator=(const buffer_wipe_guard &) = delete;

  /** Erases the guarded plaintext bytes. */
  ~buffer_wipe_guard() noexcept {
    if (!value_.empty()) {
      sodium_memzero(value_.data(), value_.size());
    }
  }

private:
  std::vector<std::byte> &value_;
};

[[nodiscard]] std::runtime_error system_error(std::string_view operation_name) {
  return std::runtime_error(std::string{operation_name} + ": " +
                            std::strerror(errno));
}

void print_usage(std::string_view executable, std::ostream &output) {
  output << "Usage:\n"
         << "  " << executable
         << " [--socket PATH] [--timeout-ms MS] put ID SECRET_PATH\n"
         << "  " << executable
         << " [--socket PATH] [--timeout-ms MS] put-utf8 ID\n"
         << "  " << executable
         << " [--socket PATH] [--timeout-ms MS] get ID SECRET_PATH\n"
         << "  " << executable
         << " [--socket PATH] [--timeout-ms MS] show-utf8 ID\n"
         << "  " << executable
         << " [--socket PATH] [--timeout-ms MS] remove ID\n"
         << "  " << executable << " [--socket PATH] [--timeout-ms MS] list\n\n"
         << "ID must match ^[a-z][a-z0-9_]{0,62}$.\n"
         << "put requires a current-user-owned private regular file.\n"
         << "put-utf8 reads one hidden UTF-8 line from /dev/tty.\n"
         << "show-utf8 writes one display-safe UTF-8 line only to a terminal.\n"
         << "get creates a new mode-0600 file and never overwrites.\n";
}

[[nodiscard]] std::uint32_t parse_timeout(std::string_view value) {
  std::uint32_t timeout{0};
  const auto [end, error] =
      std::from_chars(value.data(), value.data() + value.size(), timeout);
  if (error != std::errc{} || end != value.data() + value.size()) {
    throw usage_error("--timeout-ms requires an unsigned 32-bit integer");
  }
  return timeout;
}

[[nodiscard]] operation parse_operation(std::string_view value) {
  if (value == "put") {
    return operation::put;
  }
  if (value == "put-utf8") {
    return operation::put_utf8;
  }
  if (value == "get") {
    return operation::get;
  }
  if (value == "show-utf8") {
    return operation::show_utf8;
  }
  if (value == "remove") {
    return operation::remove;
  }
  if (value == "list") {
    return operation::list;
  }
  throw usage_error("unknown command: " + std::string{value});
}

[[nodiscard]] command_line parse_arguments(int argc, char **argv,
                                           std::ostream &output) {
  if (argc <= 1) {
    throw usage_error("missing command");
  }
  command_line result;
  int index = 1;
  while (index < argc) {
    const std::string_view argument{argv[index]};
    if (argument == "--help") {
      print_usage(argv[0], output);
      throw usage_error("");
    }
    if (argument != "--socket" && argument != "--timeout-ms") {
      break;
    }
    if (++index >= argc) {
      throw usage_error(std::string{argument} + " requires a value");
    }
    if (argument == "--socket") {
      result.socket = argv[index];
      if (result.socket.empty()) {
        throw usage_error("--socket must not be empty");
      }
    } else {
      result.timeout_ms = parse_timeout(argv[index]);
    }
    ++index;
  }
  if (index >= argc) {
    throw usage_error("missing command");
  }
  result.command = parse_operation(argv[index++]);
  const int remaining = argc - index;
  if (result.command == operation::list) {
    if (remaining != 0) {
      throw usage_error("list does not accept positional arguments");
    }
    return result;
  }
  if (remaining < 1) {
    throw usage_error("command requires a secret identifier");
  }
  result.secret_id = argv[index++];
  if (!is_valid_secret_id(result.secret_id)) {
    throw usage_error("secret identifier must match ^[a-z][a-z0-9_]{0,62}$");
  }
  if (result.command == operation::remove ||
      result.command == operation::show_utf8) {
    if (index != argc) {
      const auto name =
          result.command == operation::remove ? "remove" : "show-utf8";
      throw usage_error(std::string{name} +
                        " accepts exactly one secret identifier");
    }
    return result;
  }
  if (result.command == operation::put_utf8) {
    if (index != argc) {
      throw usage_error("put-utf8 accepts exactly one secret identifier");
    }
    return result;
  }
  if (index >= argc) {
    throw usage_error("command requires a secret file path");
  }
  result.secret_path = argv[index++];
  if (index != argc || result.secret_path.empty()) {
    throw usage_error("command accepts exactly one secret file path");
  }
  return result;
}

[[nodiscard]] std::vector<std::byte>
read_private_file(const std::filesystem::path &path) {
  const int raw = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (raw < 0) {
    throw system_error("open secret input file");
  }
  file_descriptor descriptor{raw};
  struct stat metadata{};
  if (::fstat(descriptor.get(), &metadata) != 0) {
    throw system_error("fstat secret input file");
  }
  if (!S_ISREG(metadata.st_mode) || metadata.st_uid != ::geteuid()) {
    throw std::runtime_error(
        "secret input must be a regular file owned by the effective user");
  }
  if ((metadata.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
    throw std::runtime_error(
        "secret input permissions must deny group and other access");
  }
  if (metadata.st_size < 0 ||
      static_cast<std::uint64_t>(metadata.st_size) > maximum_secret_size) {
    throw std::runtime_error("secret input size exceeds the 1 MiB limit");
  }
  std::vector<std::byte> data(static_cast<std::size_t>(metadata.st_size));
  std::size_t offset{0};
  while (offset < data.size()) {
    const auto received =
        ::read(descriptor.get(), data.data() + offset, data.size() - offset);
    if (received < 0) {
      if (errno == EINTR) {
        continue;
      }
      throw system_error("read secret input file");
    }
    if (received == 0) {
      throw std::runtime_error("secret input file changed while reading");
    }
    offset += static_cast<std::size_t>(received);
  }
  std::byte extra{};
  ssize_t extra_size{-1};
  do {
    extra_size = ::read(descriptor.get(), &extra, 1);
  } while (extra_size < 0 && errno == EINTR);
  if (extra_size < 0) {
    throw system_error("read secret input file");
  }
  if (extra_size != 0) {
    throw std::runtime_error("secret input file changed while reading");
  }
  descriptor.close_checked();
  return data;
}

[[nodiscard]] bool is_utf8_continuation(std::uint8_t value) noexcept {
  return value >= 0x80U && value <= 0xbfU;
}

[[nodiscard]] bool
is_valid_single_line_utf8(std::span<const std::byte> value) noexcept {
  std::size_t index{0};
  while (index < value.size()) {
    const auto first = std::to_integer<std::uint8_t>(value[index]);
    if (first <= 0x7fU) {
      if (first == 0U || first == 0x0aU || first == 0x0dU) {
        return false;
      }
      ++index;
      continue;
    }

    if (first >= 0xc2U && first <= 0xdfU) {
      if (index + 1 >= value.size() ||
          !is_utf8_continuation(
              std::to_integer<std::uint8_t>(value[index + 1]))) {
        return false;
      }
      index += 2;
      continue;
    }

    if (first >= 0xe0U && first <= 0xefU) {
      if (index + 2 >= value.size()) {
        return false;
      }
      const auto second = std::to_integer<std::uint8_t>(value[index + 1]);
      const auto third = std::to_integer<std::uint8_t>(value[index + 2]);
      const bool ordinary_second = ((first >= 0xe1U && first <= 0xecU) ||
                                    (first >= 0xeeU && first <= 0xefU)) &&
                                   is_utf8_continuation(second);
      const bool valid_second =
          (first == 0xe0U && second >= 0xa0U && second <= 0xbfU) ||
          (first == 0xedU && second >= 0x80U && second <= 0x9fU) ||
          ordinary_second;
      if (!valid_second || !is_utf8_continuation(third)) {
        return false;
      }
      index += 3;
      continue;
    }

    if (first >= 0xf0U && first <= 0xf4U) {
      if (index + 3 >= value.size()) {
        return false;
      }
      const auto second = std::to_integer<std::uint8_t>(value[index + 1]);
      const auto third = std::to_integer<std::uint8_t>(value[index + 2]);
      const auto fourth = std::to_integer<std::uint8_t>(value[index + 3]);
      const bool valid_second =
          (first == 0xf0U && second >= 0x90U && second <= 0xbfU) ||
          (first >= 0xf1U && first <= 0xf3U && is_utf8_continuation(second)) ||
          (first == 0xf4U && second >= 0x80U && second <= 0x8fU);
      if (!valid_second || !is_utf8_continuation(third) ||
          !is_utf8_continuation(fourth)) {
        return false;
      }
      index += 4;
      continue;
    }
    return false;
  }
  return true;
}

[[nodiscard]] bool is_terminal_safe_code_point(std::uint32_t value) noexcept {
  return value > 0x1fU && (value < 0x7fU || value > 0x9fU);
}

[[nodiscard]] bool
is_display_safe_single_line_utf8(std::span<const std::byte> value) noexcept {
  if (!is_valid_single_line_utf8(value)) {
    return false;
  }

  std::size_t index{0};
  while (index < value.size()) {
    const auto first = std::to_integer<std::uint8_t>(value[index]);
    std::uint32_t code_point{0};
    if (first <= 0x7fU) {
      code_point = first;
      ++index;
    } else if (first <= 0xdfU) {
      code_point = (static_cast<std::uint32_t>(first & 0x1fU) << 6U) |
                   static_cast<std::uint32_t>(
                       std::to_integer<std::uint8_t>(value[index + 1]) & 0x3fU);
      index += 2;
    } else if (first <= 0xefU) {
      code_point = (static_cast<std::uint32_t>(first & 0x0fU) << 12U) |
                   (static_cast<std::uint32_t>(
                        std::to_integer<std::uint8_t>(value[index + 1]) & 0x3fU)
                    << 6U) |
                   static_cast<std::uint32_t>(
                       std::to_integer<std::uint8_t>(value[index + 2]) & 0x3fU);
      index += 3;
    } else {
      code_point = (static_cast<std::uint32_t>(first & 0x07U) << 18U) |
                   (static_cast<std::uint32_t>(
                        std::to_integer<std::uint8_t>(value[index + 1]) & 0x3fU)
                    << 12U) |
                   (static_cast<std::uint32_t>(
                        std::to_integer<std::uint8_t>(value[index + 2]) & 0x3fU)
                    << 6U) |
                   static_cast<std::uint32_t>(
                       std::to_integer<std::uint8_t>(value[index + 3]) & 0x3fU);
      index += 4;
    }
    if (!is_terminal_safe_code_point(code_point)) {
      return false;
    }
  }
  return true;
}

[[nodiscard]] std::string random_suffix() {
  std::array<unsigned char, 8> random{};
  randombytes_buf(random.data(), random.size());
  constexpr char hexadecimal[] = "0123456789abcdef";
  std::string result;
  result.reserve(random.size() * 2);
  for (const auto value : random) {
    result.push_back(hexadecimal[value >> 4U]);
    result.push_back(hexadecimal[value & 0x0fU]);
  }
  return result;
}

void write_new_file_atomically(const std::filesystem::path &path,
                               std::span<const std::byte> data) {
  if (path.empty() || path.filename().empty()) {
    throw std::invalid_argument("secret output path must name a file");
  }
  const auto parent =
      path.has_parent_path() ? path.parent_path() : std::filesystem::path{"."};
  std::error_code status_error;
  const auto parent_status = std::filesystem::status(parent, status_error);
  if (status_error || !std::filesystem::is_directory(parent_status)) {
    throw std::runtime_error("secret output parent directory does not exist");
  }
  const auto temporary = path.string() + ".tmp." + random_suffix();
  const int raw = ::open(temporary.c_str(),
                         O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                         S_IRUSR | S_IWUSR);
  if (raw < 0) {
    throw system_error("open temporary secret output file");
  }
  try {
    file_descriptor descriptor{raw};
    if (::fchmod(descriptor.get(), S_IRUSR | S_IWUSR) != 0) {
      throw system_error("set secret output file permissions");
    }
    std::size_t offset{0};
    while (offset < data.size()) {
      const auto written =
          ::write(descriptor.get(), data.data() + offset, data.size() - offset);
      if (written < 0) {
        if (errno == EINTR) {
          continue;
        }
        throw system_error("write temporary secret output file");
      }
      if (written == 0) {
        throw std::runtime_error(
            "write temporary secret output file returned zero");
      }
      offset += static_cast<std::size_t>(written);
    }
    if (::fsync(descriptor.get()) != 0) {
      throw system_error("fsync temporary secret output file");
    }
    descriptor.close_checked();
    if (::renameat2(AT_FDCWD, temporary.c_str(), AT_FDCWD, path.c_str(),
                    RENAME_NOREPLACE) != 0) {
      if (errno == EEXIST) {
        throw std::runtime_error("secret output file already exists");
      }
      throw system_error("publish secret output file");
    }
    const int parent_raw =
        ::open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (parent_raw >= 0) {
      file_descriptor parent_descriptor{parent_raw};
      (void)::fsync(parent_descriptor.get());
    }
  } catch (...) {
    (void)::unlink(temporary.c_str());
    throw;
  }
}

[[nodiscard]] client make_client(const command_line &command) {
  if (command.socket.empty()) {
    return client{command.timeout_ms};
  }
  return client{command.socket, command.timeout_ms};
}

int execute(const command_line &command, std::ostream &output,
            const hidden_input_reader &read_hidden_input,
            bool output_is_terminal) {
  switch (command.command) {
  case operation::put: {
    auto vault = make_client(command);
    auto data = read_private_file(command.secret_path);
    buffer_wipe_guard guard{data};
    vault.put(command.secret_id, data);
    output << "stored " << command.secret_id << " (" << data.size()
           << " bytes)\n";
    return 0;
  }
  case operation::put_utf8: {
    std::string prompt{"Secret value for "};
    prompt.append(command.secret_id).append(" (UTF-8, input hidden): ");
    auto data = read_hidden_input(prompt, maximum_secret_size, "UTF-8 secret");
    if (data.empty()) {
      throw std::runtime_error("UTF-8 secret must not be empty");
    }
    if (data.size() > maximum_secret_size) {
      throw std::runtime_error("UTF-8 secret exceeds the 1 MiB limit");
    }
    if (!is_valid_single_line_utf8(data.bytes())) {
      throw std::runtime_error(
          "UTF-8 secret must contain one valid line without NUL bytes");
    }
    auto vault = make_client(command);
    vault.put(command.secret_id, data.bytes());
    output << "stored " << command.secret_id << " (" << data.size()
           << " bytes)\n";
    return 0;
  }
  case operation::get: {
    auto vault = make_client(command);
    auto secret = vault.get(command.secret_id);
    write_new_file_atomically(command.secret_path, secret.bytes());
    output << "wrote " << secret.size() << " bytes to "
           << command.secret_path.string() << '\n';
    return 0;
  }
  case operation::show_utf8: {
    if (!output_is_terminal) {
      throw std::runtime_error("show-utf8 requires stdout to be a terminal");
    }
    auto vault = make_client(command);
    auto secret = vault.get(command.secret_id);
    if (secret.empty() || !is_display_safe_single_line_utf8(secret.bytes())) {
      throw std::runtime_error(
          "secret is not a non-empty display-safe single-line UTF-8 value");
    }
    const auto bytes = secret.bytes();
    output.write(reinterpret_cast<const char *>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    output << '\n';
    return 0;
  }
  case operation::remove: {
    auto vault = make_client(command);
    vault.remove(command.secret_id);
    output << "removed " << command.secret_id << '\n';
    return 0;
  }
  case operation::list: {
    auto vault = make_client(command);
    for (const auto &identifier : vault.list()) {
      output << identifier << '\n';
    }
    return 0;
  }
  }
  throw std::logic_error("unsupported zeta_vault_ctl operation");
}

} // namespace

int run_with_hidden_input(int argc, char **argv, std::ostream &output,
                          std::ostream &error,
                          const hidden_input_reader &read_hidden_input,
                          bool output_is_terminal) {
  try {
    if (sodium_init() < 0) {
      throw std::runtime_error("libsodium initialization failed");
    }
    return execute(parse_arguments(argc, argv, output), output,
                   read_hidden_input, output_is_terminal);
  } catch (const usage_error &exception) {
    if (*exception.what() != '\0') {
      error << "zeta_vault_ctl: " << exception.what() << '\n';
      print_usage(argc > 0 ? argv[0] : "zeta_vault_ctl", error);
      return 2;
    }
    return 0;
  } catch (const std::exception &exception) {
    error << "zeta_vault_ctl: " << exception.what() << '\n';
    return 1;
  }
}

int run(int argc, char **argv, std::ostream &output, std::ostream &error) {
  return run_with_hidden_input(argc, argv, output, error, prompt_hidden_input,
                               ::isatty(STDOUT_FILENO) != 0);
}

} // namespace z::vault::ctl
