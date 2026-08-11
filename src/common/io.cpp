#include "common/io.h"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <stdexcept>
#include <string>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace z::vault::io {
namespace {

std::string errno_message(std::string_view operation) {
  std::string message{operation};
  message.append(": ").append(std::strerror(errno));
  return message;
}

} // namespace

bool write_all(int fd, std::span<const std::byte> data,
               std::string &diagnostic) noexcept {
  diagnostic.clear();
  std::size_t offset{0};
  while (offset < data.size()) {
    const auto written =
        ::send(fd, data.data() + offset, data.size() - offset, MSG_NOSIGNAL);
    if (written < 0) {
      if (errno == EINTR) {
        continue;
      }
      diagnostic = errno_message("send");
      return false;
    }
    if (written == 0) {
      diagnostic = "send returned zero";
      return false;
    }
    offset += static_cast<std::size_t>(written);
  }
  return true;
}

bool read_all(int fd, std::span<std::byte> data,
              std::string &diagnostic) noexcept {
  diagnostic.clear();
  std::size_t offset{0};
  while (offset < data.size()) {
    const auto received =
        ::recv(fd, data.data() + offset, data.size() - offset, 0);
    if (received < 0) {
      if (errno == EINTR) {
        continue;
      }
      diagnostic = errno_message("recv");
      return false;
    }
    if (received == 0) {
      diagnostic = "peer closed the connection";
      return false;
    }
    offset += static_cast<std::size_t>(received);
  }
  return true;
}

bool set_socket_timeout(int fd, unsigned timeout_ms,
                        std::string &diagnostic) noexcept {
  diagnostic.clear();
  const auto seconds = timeout_ms / 1000U;
  const auto microseconds = (timeout_ms % 1000U) * 1000U;
  timeval timeout{};
  timeout.tv_sec = static_cast<decltype(timeout.tv_sec)>(seconds);
  timeout.tv_usec = static_cast<decltype(timeout.tv_usec)>(microseconds);
  if (::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) !=
          0 ||
      ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) !=
          0) {
    diagnostic = errno_message("setsockopt timeout");
    return false;
  }
  return true;
}

std::string default_endpoint() {
  if (const char *runtime = std::getenv("XDG_RUNTIME_DIR");
      runtime != nullptr && *runtime != '\0') {
    return std::string{runtime} + "/zeta/vault.sock";
  }
  return "/tmp/zeta-vault-" + std::to_string(::geteuid()) +
         "/vault.sock";
}

std::string default_vault_path() {
  if (const char *home = std::getenv("HOME");
      home != nullptr && *home != '\0') {
    return std::string{home} + "/.local/share/zeta/vault.bin";
  }
  throw std::runtime_error("HOME is not set; specify --vault explicitly");
}

void ensure_private_parent(std::string_view path) {
  const std::filesystem::path target{path};
  const auto parent = target.parent_path();
  if (parent.empty()) {
    return;
  }

  const bool created = std::filesystem::create_directories(parent);
  if (created && ::chmod(parent.c_str(), S_IRWXU) != 0) {
    throw std::runtime_error(errno_message("chmod private directory"));
  }

  struct stat metadata {};
  if (::lstat(parent.c_str(), &metadata) != 0) {
    throw std::runtime_error(errno_message("lstat private directory"));
  }
  if (!S_ISDIR(metadata.st_mode) || metadata.st_uid != ::geteuid()) {
    throw std::runtime_error(
        "private directory must be a real directory owned by this user");
  }
  if ((metadata.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
    throw std::runtime_error(
        "private directory must deny group and other access");
  }
}

} // namespace z::vault::io
