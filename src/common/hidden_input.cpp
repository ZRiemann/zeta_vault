#include "common/hidden_input.h"

#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <string>
#include <utility>

#include <fcntl.h>
#include <termios.h>
#include <unistd.h>

#include <sodium.h>

namespace z::vault {
namespace {

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
  ~file_descriptor() noexcept {
    if (value_ >= 0) {
      (void)::close(value_);
    }
  }

  /** Returns the owned descriptor. */
  [[nodiscard]] int get() const noexcept { return value_; }

private:
  int value_{-1};
};

/** Restores terminal attributes after hidden input. */
class terminal_guard {
public:
  /** Disables terminal echo while preserving the original attributes. */
  explicit terminal_guard(int fd) : fd_(fd) {
    if (::tcgetattr(fd_, &original_) != 0) {
      throw std::runtime_error(std::string{"tcgetattr /dev/tty: "} +
                               std::strerror(errno));
    }
    termios hidden = original_;
    hidden.c_lflag &= static_cast<tcflag_t>(~ECHO);
    if (::tcsetattr(fd_, TCSAFLUSH, &hidden) != 0) {
      throw std::runtime_error(std::string{"tcsetattr /dev/tty: "} +
                               std::strerror(errno));
    }
    active_ = true;
  }

  /** Terminal guards are not copyable. */
  terminal_guard(const terminal_guard &) = delete;

  /** Terminal guards are not copy assignable. */
  terminal_guard &operator=(const terminal_guard &) = delete;

  /** Restores the original terminal attributes and flushes unread input. */
  ~terminal_guard() noexcept {
    if (active_) {
      (void)::tcsetattr(fd_, TCSAFLUSH, &original_);
    }
  }

private:
  int fd_;
  termios original_{};
  bool active_{false};
};

void write_text(int fd, std::string_view value) {
  std::size_t offset{0};
  while (offset < value.size()) {
    const auto written =
        ::write(fd, value.data() + offset, value.size() - offset);
    if (written < 0) {
      if (errno == EINTR) {
        continue;
      }
      throw std::runtime_error(std::string{"write /dev/tty: "} +
                               std::strerror(errno));
    }
    if (written == 0) {
      throw std::runtime_error("write /dev/tty returned zero");
    }
    offset += static_cast<std::size_t>(written);
  }
}

} // namespace

secret_input::secret_input(std::size_t capacity) { bytes_.reserve(capacity); }

secret_input::secret_input(std::span<const std::byte> value)
    : bytes_(value.begin(), value.end()) {}

secret_input::secret_input(secret_input &&other) noexcept
    : bytes_(std::move(other.bytes_)) {}

secret_input &secret_input::operator=(secret_input &&other) noexcept {
  if (this != &other) {
    clear();
    bytes_ = std::move(other.bytes_);
  }
  return *this;
}

secret_input::~secret_input() noexcept { clear(); }

void secret_input::push_back(std::byte value) { bytes_.push_back(value); }

std::span<const std::byte> secret_input::bytes() const noexcept {
  return bytes_;
}

std::string_view secret_input::text() const noexcept {
  if (bytes_.empty()) {
    return {};
  }
  return {reinterpret_cast<const char *>(bytes_.data()), bytes_.size()};
}

bool secret_input::empty() const noexcept { return bytes_.empty(); }

std::size_t secret_input::size() const noexcept { return bytes_.size(); }

void secret_input::clear() noexcept {
  if (!bytes_.empty()) {
    sodium_memzero(bytes_.data(), bytes_.size());
    bytes_.clear();
  }
}

secret_input prompt_hidden_input(std::string_view prompt,
                                 std::size_t maximum_size,
                                 std::string_view value_name) {
  if (maximum_size == 0) {
    throw std::invalid_argument("hidden input size limit must be positive");
  }
  const int raw = ::open("/dev/tty", O_RDWR | O_CLOEXEC);
  if (raw < 0) {
    throw std::runtime_error(std::string{"open /dev/tty: "} +
                             std::strerror(errno));
  }
  file_descriptor descriptor{raw};
  write_text(descriptor.get(), prompt);

  secret_input value{maximum_size};
  {
    terminal_guard guard{descriptor.get()};
    for (;;) {
      char byte{0};
      const auto received = ::read(descriptor.get(), &byte, 1);
      if (received < 0) {
        if (errno == EINTR) {
          continue;
        }
        throw std::runtime_error(std::string{"read /dev/tty: "} +
                                 std::strerror(errno));
      }
      if (received == 0 || byte == '\n' || byte == '\r') {
        break;
      }
      if (value.size() >= maximum_size) {
        throw std::runtime_error(std::string{value_name} + " exceeds the " +
                                 std::to_string(maximum_size) + "-byte limit");
      }
      value.push_back(static_cast<std::byte>(byte));
    }
  }
  write_text(descriptor.get(), "\n");
  return value;
}

} // namespace z::vault
