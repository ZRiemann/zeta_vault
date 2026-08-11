#include "server/password_prompt.h"

#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <string>
#include <string_view>

#include <fcntl.h>
#include <termios.h>
#include <unistd.h>

#include <sodium.h>

namespace z::vault {
namespace {

/** Restores terminal attributes after password input. */
class terminal_guard {
public:
  /** Disables terminal echo while preserving the original attributes. */
  explicit terminal_guard(int fd) : fd_(fd) {
    if (::tcgetattr(fd_, &original_) != 0) {
      throw std::runtime_error(std::string{"tcgetattr: "} +
                               std::strerror(errno));
    }
    termios hidden = original_;
    hidden.c_lflag &= static_cast<tcflag_t>(~ECHO);
    if (::tcsetattr(fd_, TCSAFLUSH, &hidden) != 0) {
      throw std::runtime_error(std::string{"tcsetattr: "} +
                               std::strerror(errno));
    }
    active_ = true;
  }

  /** Terminal guards are not copyable. */
  terminal_guard(const terminal_guard &) = delete;

  /** Terminal guards are not copy assignable. */
  terminal_guard &operator=(const terminal_guard &) = delete;

  /** Restores the original terminal attributes. */
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

/** Erases a partially entered password after an exception. */
class password_wipe_guard {
public:
  /** Starts guarding a password string. */
  explicit password_wipe_guard(std::string &password) noexcept
      : password_(password) {}

  /** Password guards are not copyable. */
  password_wipe_guard(const password_wipe_guard &) = delete;

  /** Password guards are not copy assignable. */
  password_wipe_guard &operator=(const password_wipe_guard &) = delete;

  /** Erases the guarded password unless ownership was released. */
  ~password_wipe_guard() noexcept {
    if (active_ && !password_.empty()) {
      sodium_memzero(password_.data(), password_.size());
    }
  }

  /** Leaves password erasure to the caller after a successful return. */
  void release() noexcept { active_ = false; }

private:
  std::string &password_;
  bool active_{true};
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

std::string prompt_password(std::string_view prompt) {
  const int fd = ::open("/dev/tty", O_RDWR | O_CLOEXEC);
  if (fd < 0) {
    throw std::runtime_error(std::string{"open /dev/tty: "} +
                             std::strerror(errno));
  }
  try {
    write_text(fd, prompt);
    std::string password;
    password_wipe_guard password_guard{password};
    {
      terminal_guard guard{fd};
      for (;;) {
        char value{0};
        const auto received = ::read(fd, &value, 1);
        if (received < 0) {
          if (errno == EINTR) {
            continue;
          }
          throw std::runtime_error(std::string{"read /dev/tty: "} +
                                   std::strerror(errno));
        }
        if (received == 0 || value == '\n' || value == '\r') {
          break;
        }
        if (password.size() >= 4096) {
          throw std::runtime_error("master password exceeds the limit");
        }
        password.push_back(value);
      }
    }
    write_text(fd, "\n");
    (void)::close(fd);
    password_guard.release();
    return password;
  } catch (...) {
    (void)::close(fd);
    throw;
  }
}

} // namespace z::vault
