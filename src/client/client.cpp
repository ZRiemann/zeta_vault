#include <zeta_vault/zeta_vault.h>

#include <array>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <sodium.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "common/io.h"
#include "common/secret_id.h"
#include "protocol/protocol.h"

/** Internal client state hidden behind the stable C ABI. */
struct zeta_vault_client {
  int socket{-1};
  std::uint64_t next_request_id{1};
  std::string last_error;
};

namespace {

using z::vault::protocol::message_type;

constexpr std::size_t unix_path_capacity =
    sizeof(((sockaddr_un *)nullptr)->sun_path);

thread_local std::string last_creation_error;

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

zeta_vault_status_t set_error(zeta_vault_client_t *client,
                              zeta_vault_status_t status,
                              std::string message) noexcept {
  if (client != nullptr) {
    try {
      client->last_error = std::move(message);
    } catch (...) {
      client->last_error.clear();
    }
  }
  return status;
}

zeta_vault_status_t set_creation_error(zeta_vault_status_t status,
                                       std::string_view message) noexcept {
  try {
    last_creation_error.assign(message);
  } catch (...) {
    last_creation_error.clear();
  }
  return status;
}

bool valid_id(const char *id, std::size_t size) noexcept {
  return id != nullptr &&
         z::vault::is_valid_secret_id(std::string_view{id, size});
}

void disconnect(zeta_vault_client_t *client) noexcept {
  if (client != nullptr && client->socket >= 0) {
    (void)::close(client->socket);
    client->socket = -1;
  }
}

zeta_vault_status_t fail_transaction(zeta_vault_client_t *client,
                                     zeta_vault_status_t status,
                                     std::string diagnostic) noexcept {
  disconnect(client);
  return set_error(client, status, std::move(diagnostic));
}

zeta_vault_status_t connect_socket(std::string_view endpoint,
                                   std::uint32_t timeout_ms,
                                   zeta_vault_client_t *client) noexcept {
  if (endpoint.empty() || endpoint.size() >= unix_path_capacity) {
    return set_error(client, ZETA_VAULT_STATUS_INVALID_ARGUMENT,
                     "Unix socket path is empty or too long");
  }
  client->socket = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (client->socket < 0) {
    return set_error(client, ZETA_VAULT_STATUS_IO_ERROR,
                     std::string{"socket: "} + std::strerror(errno));
  }
  std::string diagnostic;
  if (!z::vault::io::set_socket_timeout(
          client->socket, timeout_ms == 0 ? 5000U : timeout_ms, diagnostic)) {
    ::close(client->socket);
    client->socket = -1;
    return set_error(client, ZETA_VAULT_STATUS_IO_ERROR, std::move(diagnostic));
  }

  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  std::memcpy(address.sun_path, endpoint.data(), endpoint.size());
  address.sun_path[endpoint.size()] = '\0';
  if (::connect(client->socket, reinterpret_cast<sockaddr *>(&address),
                sizeof(address)) != 0) {
    const auto message = std::string{"connect: "} + std::strerror(errno);
    ::close(client->socket);
    client->socket = -1;
    return set_error(client, ZETA_VAULT_STATUS_IO_ERROR, message);
  }

  ucred credentials{};
  socklen_t credentials_size = sizeof(credentials);
  if (::getsockopt(client->socket, SOL_SOCKET, SO_PEERCRED, &credentials,
                   &credentials_size) != 0) {
    const auto message = std::string{"SO_PEERCRED: "} + std::strerror(errno);
    ::close(client->socket);
    client->socket = -1;
    return set_error(client, ZETA_VAULT_STATUS_IO_ERROR, message);
  }
  if (credentials.uid != ::geteuid()) {
    ::close(client->socket);
    client->socket = -1;
    return set_error(client, ZETA_VAULT_STATUS_ACCESS_DENIED,
                     "server UID does not match client UID");
  }
  return ZETA_VAULT_STATUS_OK;
}

zeta_vault_status_t transact(zeta_vault_client_t *client,
                             message_type request_type,
                             std::span<const std::byte> payload,
                             z::vault::protocol::response_payload &response) {
  if (client == nullptr || client->socket < 0) {
    return set_error(client, ZETA_VAULT_STATUS_INVALID_ARGUMENT,
                     "client is not connected");
  }
  client->last_error.clear();
  const auto request_id = client->next_request_id++;
  if (client->next_request_id == 0) {
    client->next_request_id = 1;
  }
  std::vector<std::byte> frame;
  wipe_guard frame_guard{frame};
  try {
    frame = z::vault::protocol::encode_frame(request_type, request_id, payload);
  } catch (const std::exception &exception) {
    return set_error(client, ZETA_VAULT_STATUS_INVALID_ARGUMENT,
                     exception.what());
  }

  std::string diagnostic;
  if (!z::vault::io::write_all(client->socket, frame, diagnostic)) {
    return fail_transaction(client, ZETA_VAULT_STATUS_IO_ERROR,
                            std::move(diagnostic));
  }
  std::array<std::byte, z::vault::protocol::header_size> encoded_header{};
  if (!z::vault::io::read_all(client->socket, encoded_header, diagnostic)) {
    return fail_transaction(client, ZETA_VAULT_STATUS_IO_ERROR,
                            std::move(diagnostic));
  }
  z::vault::protocol::frame_header header;
  if (!z::vault::protocol::decode_header(encoded_header, header, diagnostic) ||
      header.request_id != request_id ||
      !z::vault::protocol::is_matching_response(request_type, header.type)) {
    if (diagnostic.empty()) {
      diagnostic = "response header does not match request";
    }
    return fail_transaction(client, ZETA_VAULT_STATUS_PROTOCOL_ERROR,
                            std::move(diagnostic));
  }
  std::vector<std::byte> encoded_payload(header.payload_size);
  wipe_guard encoded_payload_guard{encoded_payload};
  if (!z::vault::io::read_all(client->socket, encoded_payload, diagnostic)) {
    return fail_transaction(client, ZETA_VAULT_STATUS_IO_ERROR,
                            std::move(diagnostic));
  }
  if (!z::vault::protocol::decode_response(encoded_payload, response,
                                           diagnostic)) {
    return fail_transaction(client, ZETA_VAULT_STATUS_PROTOCOL_ERROR,
                            std::move(diagnostic));
  }
  client->last_error = response.diagnostic;
  return response.status;
}

} // namespace

extern "C" {

zeta_vault_status_t
zeta_vault_client_create(const zeta_vault_client_options_t *options,
                         zeta_vault_client_t **out_client) {
  last_creation_error.clear();
  try {
    if (out_client == nullptr) {
      return set_creation_error(ZETA_VAULT_STATUS_INVALID_ARGUMENT,
                                "client output pointer must not be null");
    }
    *out_client = nullptr;
    if (options != nullptr &&
        options->struct_size < sizeof(zeta_vault_client_options_t)) {
      return set_creation_error(ZETA_VAULT_STATUS_INVALID_ARGUMENT,
                                "client options structure is too small");
    }
    if (sodium_init() < 0) {
      return set_creation_error(ZETA_VAULT_STATUS_CRYPTO_ERROR,
                                "libsodium initialization failed");
    }
    auto client = std::unique_ptr<zeta_vault_client_t>{
        new (std::nothrow) zeta_vault_client_t{}};
    if (!client) {
      return set_creation_error(ZETA_VAULT_STATUS_INTERNAL_ERROR,
                                "memory allocation failed");
    }
    const std::string endpoint =
        options != nullptr && options->endpoint != nullptr
            ? options->endpoint
            : z::vault::io::default_endpoint();
    const auto status = connect_socket(
        endpoint, options != nullptr ? options->timeout_ms : 0, client.get());
    if (status != ZETA_VAULT_STATUS_OK) {
      return set_creation_error(status, client->last_error);
    }
    *out_client = client.release();
    return ZETA_VAULT_STATUS_OK;
  } catch (const std::bad_alloc &) {
    return set_creation_error(ZETA_VAULT_STATUS_INTERNAL_ERROR,
                              "memory allocation failed");
  } catch (const std::exception &exception) {
    return set_creation_error(ZETA_VAULT_STATUS_INTERNAL_ERROR,
                              exception.what());
  } catch (...) {
    return set_creation_error(ZETA_VAULT_STATUS_INTERNAL_ERROR,
                              "unexpected client creation error");
  }
}

void zeta_vault_client_destroy(zeta_vault_client_t *client) {
  if (client == nullptr) {
    return;
  }
  disconnect(client);
  delete client;
}

zeta_vault_status_t zeta_vault_client_ping(zeta_vault_client_t *client) {
  try {
    z::vault::protocol::response_payload response;
    wipe_guard response_guard{response.data};
    return transact(client, message_type::ping_request, {}, response);
  } catch (const std::exception &exception) {
    return set_error(client, ZETA_VAULT_STATUS_INTERNAL_ERROR,
                     exception.what());
  } catch (...) {
    return set_error(client, ZETA_VAULT_STATUS_INTERNAL_ERROR,
                     "unexpected client error");
  }
}

zeta_vault_status_t zeta_vault_client_put_secret(zeta_vault_client_t *client,
                                                 const char *secret_id,
                                                 size_t secret_id_size,
                                                 const uint8_t *secret,
                                                 size_t secret_size) {
  if (!valid_id(secret_id, secret_id_size) ||
      (secret == nullptr && secret_size != 0)) {
    return set_error(client, ZETA_VAULT_STATUS_INVALID_ARGUMENT,
                     "invalid secret identifier or buffer");
  }
  try {
    const std::span<const std::byte> value{
        reinterpret_cast<const std::byte *>(secret), secret_size};
    auto payload = z::vault::protocol::encode_put_request(
        std::string_view{secret_id, secret_id_size}, value);
    wipe_guard payload_guard{payload};
    z::vault::protocol::response_payload response;
    wipe_guard response_guard{response.data};
    return transact(client, message_type::put_secret_request, payload,
                    response);
  } catch (const std::bad_alloc &) {
    return set_error(client, ZETA_VAULT_STATUS_INTERNAL_ERROR,
                     "memory allocation failed");
  } catch (const std::exception &exception) {
    return set_error(client, ZETA_VAULT_STATUS_INVALID_ARGUMENT,
                     exception.what());
  } catch (...) {
    return set_error(client, ZETA_VAULT_STATUS_INTERNAL_ERROR,
                     "unexpected client error");
  }
}

zeta_vault_status_t
zeta_vault_client_get_secret(zeta_vault_client_t *client, const char *secret_id,
                             size_t secret_id_size,
                             zeta_vault_secret_t *out_secret) {
  if (out_secret == nullptr || !valid_id(secret_id, secret_id_size)) {
    return set_error(client, ZETA_VAULT_STATUS_INVALID_ARGUMENT,
                     "invalid secret identifier or output buffer");
  }
  *out_secret = {};
  try {
    const auto payload = z::vault::protocol::encode_id_request(
        std::string_view{secret_id, secret_id_size});
    z::vault::protocol::response_payload response;
    wipe_guard response_guard{response.data};
    const auto status =
        transact(client, message_type::get_secret_request, payload, response);
    if (status != ZETA_VAULT_STATUS_OK) {
      return status;
    }
    if (response.data.empty()) {
      return ZETA_VAULT_STATUS_OK;
    }
    void *buffer = sodium_malloc(response.data.size());
    if (buffer == nullptr) {
      return set_error(client, ZETA_VAULT_STATUS_INTERNAL_ERROR,
                       "secure allocation failed");
    }
    std::memcpy(buffer, response.data.data(), response.data.size());
    sodium_memzero(response.data.data(), response.data.size());
    out_secret->data = static_cast<std::uint8_t *>(buffer);
    out_secret->size = response.data.size();
    return ZETA_VAULT_STATUS_OK;
  } catch (const std::bad_alloc &) {
    return set_error(client, ZETA_VAULT_STATUS_INTERNAL_ERROR,
                     "memory allocation failed");
  } catch (const std::exception &exception) {
    return set_error(client, ZETA_VAULT_STATUS_INVALID_ARGUMENT,
                     exception.what());
  } catch (...) {
    return set_error(client, ZETA_VAULT_STATUS_INTERNAL_ERROR,
                     "unexpected client error");
  }
}

zeta_vault_status_t zeta_vault_client_remove_secret(zeta_vault_client_t *client,
                                                    const char *secret_id,
                                                    size_t secret_id_size) {
  if (!valid_id(secret_id, secret_id_size)) {
    return set_error(client, ZETA_VAULT_STATUS_INVALID_ARGUMENT,
                     "invalid secret identifier");
  }
  try {
    const auto payload = z::vault::protocol::encode_id_request(
        std::string_view{secret_id, secret_id_size});
    z::vault::protocol::response_payload response;
    wipe_guard response_guard{response.data};
    return transact(client, message_type::remove_secret_request, payload,
                    response);
  } catch (const std::bad_alloc &) {
    return set_error(client, ZETA_VAULT_STATUS_INTERNAL_ERROR,
                     "memory allocation failed");
  } catch (const std::exception &exception) {
    return set_error(client, ZETA_VAULT_STATUS_INVALID_ARGUMENT,
                     exception.what());
  } catch (...) {
    return set_error(client, ZETA_VAULT_STATUS_INTERNAL_ERROR,
                     "unexpected client error");
  }
}

zeta_vault_status_t
zeta_vault_client_list_secrets(zeta_vault_client_t *client,
                               zeta_vault_secret_id_list_t *out_list) {
  if (out_list == nullptr) {
    return set_error(client, ZETA_VAULT_STATUS_INVALID_ARGUMENT,
                     "invalid secret identifier list output");
  }
  *out_list = {};
  try {
    z::vault::protocol::response_payload response;
    wipe_guard response_guard{response.data};
    const auto status =
        transact(client, message_type::list_secrets_request, {}, response);
    if (status != ZETA_VAULT_STATUS_OK) {
      return status;
    }
    std::vector<std::string> identifiers;
    std::string diagnostic;
    if (!z::vault::protocol::decode_id_list(response.data, identifiers,
                                            diagnostic)) {
      return fail_transaction(client, ZETA_VAULT_STATUS_PROTOCOL_ERROR,
                              std::move(diagnostic));
    }
    if (identifiers.empty()) {
      return ZETA_VAULT_STATUS_OK;
    }
    auto *items = static_cast<zeta_vault_secret_id_t *>(
        std::calloc(identifiers.size(), sizeof(zeta_vault_secret_id_t)));
    if (items == nullptr) {
      return set_error(client, ZETA_VAULT_STATUS_INTERNAL_ERROR,
                       "memory allocation failed");
    }
    out_list->items = items;
    out_list->count = identifiers.size();
    for (std::size_t index = 0; index < identifiers.size(); ++index) {
      const auto &identifier = identifiers[index];
      items[index].data =
          static_cast<char *>(std::malloc(identifier.size() + 1));
      if (items[index].data == nullptr) {
        zeta_vault_secret_id_list_free(out_list);
        return set_error(client, ZETA_VAULT_STATUS_INTERNAL_ERROR,
                         "memory allocation failed");
      }
      std::memcpy(items[index].data, identifier.data(), identifier.size());
      items[index].data[identifier.size()] = '\0';
      items[index].size = identifier.size();
    }
    return ZETA_VAULT_STATUS_OK;
  } catch (const std::bad_alloc &) {
    zeta_vault_secret_id_list_free(out_list);
    return set_error(client, ZETA_VAULT_STATUS_INTERNAL_ERROR,
                     "memory allocation failed");
  } catch (const std::exception &exception) {
    zeta_vault_secret_id_list_free(out_list);
    return set_error(client, ZETA_VAULT_STATUS_INTERNAL_ERROR,
                     exception.what());
  } catch (...) {
    zeta_vault_secret_id_list_free(out_list);
    return set_error(client, ZETA_VAULT_STATUS_INTERNAL_ERROR,
                     "unexpected client error");
  }
}

zeta_vault_status_t zeta_vault_client_lock(zeta_vault_client_t *client) {
  try {
    z::vault::protocol::response_payload response;
    wipe_guard response_guard{response.data};
    return transact(client, message_type::lock_request, {}, response);
  } catch (const std::exception &exception) {
    return set_error(client, ZETA_VAULT_STATUS_INTERNAL_ERROR,
                     exception.what());
  } catch (...) {
    return set_error(client, ZETA_VAULT_STATUS_INTERNAL_ERROR,
                     "unexpected client error");
  }
}

const char *zeta_vault_client_last_error(const zeta_vault_client_t *client) {
  return client == nullptr ? last_creation_error.c_str()
                           : client->last_error.c_str();
}

void zeta_vault_secret_free(zeta_vault_secret_t *secret) {
  if (secret == nullptr) {
    return;
  }
  if (secret->data != nullptr) {
    sodium_memzero(secret->data, secret->size);
    sodium_free(secret->data);
  }
  secret->data = nullptr;
  secret->size = 0;
}

void zeta_vault_secret_id_list_free(zeta_vault_secret_id_list_t *list) {
  if (list == nullptr) {
    return;
  }
  for (std::size_t index = 0; index < list->count; ++index) {
    std::free(list->items[index].data);
  }
  std::free(list->items);
  list->items = nullptr;
  list->count = 0;
}

const char *zeta_vault_status_name(zeta_vault_status_t status) {
  switch (status) {
  case ZETA_VAULT_STATUS_OK:
    return "ok";
  case ZETA_VAULT_STATUS_INVALID_ARGUMENT:
    return "invalid argument";
  case ZETA_VAULT_STATUS_NOT_FOUND:
    return "not found";
  case ZETA_VAULT_STATUS_LOCKED:
    return "locked";
  case ZETA_VAULT_STATUS_ACCESS_DENIED:
    return "access denied";
  case ZETA_VAULT_STATUS_IO_ERROR:
    return "I/O error";
  case ZETA_VAULT_STATUS_PROTOCOL_ERROR:
    return "protocol error";
  case ZETA_VAULT_STATUS_CRYPTO_ERROR:
    return "cryptographic error";
  case ZETA_VAULT_STATUS_UNSUPPORTED:
    return "unsupported";
  case ZETA_VAULT_STATUS_INTERNAL_ERROR:
    return "internal error";
  }
  return "unknown status";
}

} // extern "C"
