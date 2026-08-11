#include "server/server.h"

#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <sodium.h>

#include "common/io.h"
#include "protocol/protocol.h"

namespace z::vault {
namespace {

using protocol::message_type;

constexpr std::size_t unix_path_capacity =
    sizeof(((sockaddr_un *)nullptr)->sun_path);

/** Erases a temporary protocol buffer when leaving scope. */
class wipe_guard {
public:
  explicit wipe_guard(std::vector<std::byte> &value) noexcept : value_(value) {}
  wipe_guard(const wipe_guard &) = delete;
  wipe_guard &operator=(const wipe_guard &) = delete;
  ~wipe_guard() noexcept {
    if (!value_.empty()) {
      sodium_memzero(value_.data(), value_.size());
    }
  }

private:
  std::vector<std::byte> &value_;
};

std::runtime_error system_error(std::string_view operation) {
  return std::runtime_error(std::string{operation} + ": " +
                            std::strerror(errno));
}

sockaddr_un make_address(std::string_view endpoint) {
  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  std::memcpy(address.sun_path, endpoint.data(), endpoint.size());
  address.sun_path[endpoint.size()] = '\0';
  return address;
}

void remove_stale_endpoint(std::string_view endpoint) {
  struct stat metadata{};
  if (::lstat(std::string{endpoint}.c_str(), &metadata) != 0) {
    if (errno == ENOENT) {
      return;
    }
    throw system_error("lstat vault socket");
  }
  if (!S_ISSOCK(metadata.st_mode) || metadata.st_uid != ::geteuid()) {
    throw std::runtime_error(
        "vault endpoint exists but is not a socket owned by this user");
  }

  const int probe = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (probe < 0) {
    throw system_error("create vault endpoint probe");
  }
  const auto address = make_address(endpoint);
  if (::connect(probe, reinterpret_cast<const sockaddr *>(&address),
                sizeof(address)) == 0) {
    (void)::close(probe);
    throw std::runtime_error("vault endpoint is already serving clients");
  }
  const int connect_error = errno;
  (void)::close(probe);
  if (connect_error != ECONNREFUSED && connect_error != ENOENT) {
    errno = connect_error;
    throw system_error("probe vault endpoint");
  }
  if (::unlink(std::string{endpoint}.c_str()) != 0 && errno != ENOENT) {
    throw system_error("remove stale vault socket");
  }
}

zeta_vault_status_t classify_exception(const std::exception &exception) {
  if (dynamic_cast<const std::invalid_argument *>(&exception) != nullptr) {
    return ZETA_VAULT_STATUS_INVALID_ARGUMENT;
  }
  if (dynamic_cast<const std::out_of_range *>(&exception) != nullptr) {
    return ZETA_VAULT_STATUS_NOT_FOUND;
  }
  if (dynamic_cast<const std::logic_error *>(&exception) != nullptr) {
    return ZETA_VAULT_STATUS_LOCKED;
  }
  return ZETA_VAULT_STATUS_INTERNAL_ERROR;
}

} // namespace

server::server(server_config config, std::unique_ptr<vault_store> store)
    : config_(std::move(config)), store_(std::move(store)) {
  if (!store_) {
    throw std::invalid_argument("vault store must not be null");
  }
}

server::~server() noexcept { close_listener(); }

int server::run(const volatile std::sig_atomic_t &stop_requested) {
  open_listener();
  std::cout << "zeta_vault server listening on " << config_.endpoint << '\n';
  while (stop_requested == 0) {
    pollfd descriptor{listener_, POLLIN, 0};
    const int ready = ::poll(&descriptor, 1, 500);
    if (ready < 0) {
      if (errno == EINTR) {
        continue;
      }
      throw system_error("poll vault listener");
    }
    if (ready == 0) {
      continue;
    }
    const int client = ::accept4(listener_, nullptr, nullptr, SOCK_CLOEXEC);
    if (client < 0) {
      if (errno == EINTR) {
        continue;
      }
      throw system_error("accept vault client");
    }
    std::string timeout_diagnostic;
    if (!io::set_socket_timeout(client, 5000U, timeout_diagnostic)) {
      std::cerr << "vault client timeout setup failed: " << timeout_diagnostic
                << '\n';
      (void)::close(client);
      continue;
    }
    try {
      handle_client(client);
    } catch (const std::exception &exception) {
      std::cerr << "vault client session failed: " << exception.what() << '\n';
    }
    (void)::close(client);
  }
  return 0;
}

void server::open_listener() {
  if (config_.endpoint.empty() ||
      config_.endpoint.size() >= unix_path_capacity) {
    throw std::invalid_argument("Unix socket path is empty or too long");
  }
  io::ensure_private_parent(config_.endpoint);
  remove_stale_endpoint(config_.endpoint);

  listener_ = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (listener_ < 0) {
    throw system_error("create vault listener");
  }
  const auto address = make_address(config_.endpoint);
  if (::bind(listener_, reinterpret_cast<const sockaddr *>(&address),
             sizeof(address)) != 0) {
    close_listener();
    throw system_error("bind vault listener");
  }
  owns_endpoint_ = true;
  if (::chmod(config_.endpoint.c_str(), S_IRUSR | S_IWUSR) != 0) {
    close_listener();
    throw system_error("chmod vault socket");
  }
  if (::listen(listener_, 16) != 0) {
    close_listener();
    throw system_error("listen vault socket");
  }
}

void server::close_listener() noexcept {
  if (listener_ >= 0) {
    (void)::close(listener_);
    listener_ = -1;
  }
  if (!owns_endpoint_ || config_.endpoint.empty()) {
    return;
  }

  struct stat metadata{};
  if (::lstat(config_.endpoint.c_str(), &metadata) == 0 &&
      S_ISSOCK(metadata.st_mode) && metadata.st_uid == ::geteuid()) {
    (void)::unlink(config_.endpoint.c_str());
  }
  owns_endpoint_ = false;
}

void server::handle_client(int client_fd) {
  std::string diagnostic;
  if (!authorize_peer(client_fd, diagnostic)) {
    throw std::runtime_error(diagnostic);
  }
  for (;;) {
    std::array<std::byte, protocol::header_size> encoded_header{};
    if (!io::read_all(client_fd, encoded_header, diagnostic)) {
      if (diagnostic == "peer closed the connection") {
        return;
      }
      throw std::runtime_error(diagnostic);
    }
    protocol::frame_header header;
    if (!protocol::decode_header(encoded_header, header, diagnostic)) {
      throw std::runtime_error(diagnostic);
    }

    const auto reply_type = protocol::response_type(header.type);
    std::vector<std::byte> payload(header.payload_size);
    wipe_guard payload_guard{payload};
    if (!io::read_all(client_fd, payload, diagnostic)) {
      throw std::runtime_error(diagnostic);
    }

    auto response_status = ZETA_VAULT_STATUS_OK;
    std::string response_diagnostic;
    secure_bytes response_secret;
    std::vector<std::byte> response_data;
    wipe_guard response_data_guard{response_data};
    try {
      switch (header.type) {
      case message_type::ping_request:
        if (!payload.empty()) {
          throw std::invalid_argument("ping request payload must be empty");
        }
        break;
      case message_type::put_secret_request: {
        std::string id;
        std::vector<std::byte> value;
        wipe_guard value_guard{value};
        if (!protocol::decode_put_request(payload, id, value, diagnostic)) {
          throw std::invalid_argument(diagnostic);
        }
        store_->put(id, value);
        break;
      }
      case message_type::get_secret_request: {
        std::string id;
        if (!protocol::decode_id_request(payload, id, diagnostic)) {
          throw std::invalid_argument(diagnostic);
        }
        response_secret = store_->get(id);
        break;
      }
      case message_type::remove_secret_request: {
        std::string id;
        if (!protocol::decode_id_request(payload, id, diagnostic)) {
          throw std::invalid_argument(diagnostic);
        }
        if (!store_->remove(id)) {
          throw std::out_of_range("secret not found");
        }
        break;
      }
      case message_type::lock_request:
        if (!payload.empty()) {
          throw std::invalid_argument("lock request payload must be empty");
        }
        store_->lock();
        break;
      case message_type::list_secrets_request:
        if (!payload.empty()) {
          throw std::invalid_argument(
              "list-secrets request payload must be empty");
        }
        response_data = protocol::encode_id_list(store_->list());
        break;
      default:
        throw std::invalid_argument("unsupported request message type");
      }
    } catch (const std::exception &exception) {
      response_status = classify_exception(exception);
      response_diagnostic = exception.what();
    }

    const auto response_bytes = response_data.empty()
                                    ? response_secret.view()
                                    : std::span<const std::byte>{response_data};
    auto response_payload = protocol::encode_response(
        response_status, response_diagnostic, response_bytes);
    wipe_guard response_payload_guard{response_payload};
    auto response =
        protocol::encode_frame(reply_type, header.request_id, response_payload);
    wipe_guard response_guard{response};
    if (!io::write_all(client_fd, response, diagnostic)) {
      throw std::runtime_error(diagnostic);
    }
  }
}

bool server::authorize_peer(int client_fd,
                            std::string &diagnostic) const noexcept {
  ucred credentials{};
  socklen_t size = sizeof(credentials);
  if (::getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED, &credentials, &size) !=
      0) {
    diagnostic = std::string{"SO_PEERCRED: "} + std::strerror(errno);
    return false;
  }
  if (credentials.uid != ::geteuid()) {
    diagnostic = "client UID does not match server UID";
    return false;
  }
  diagnostic.clear();
  return true;
}

} // namespace z::vault
