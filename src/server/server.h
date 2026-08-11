#pragma once

#include <csignal>
#include <filesystem>
#include <memory>
#include <string>

#include "storage/vault_store.h"

namespace z::vault {

/** Configuration for the local zeta_vault server. */
struct server_config {
  std::filesystem::path vault_path;
  std::string endpoint;
};

/** Single-process local secret service. */
class server {
public:
  /** Creates a server around an unlocked store. */
  server(server_config config, std::unique_ptr<vault_store> store);

  /** Server instances are not copyable. */
  server(const server &) = delete;

  /** Server instances are not copy assignable. */
  server &operator=(const server &) = delete;

  /** Closes the listening socket and removes its filesystem entry. */
  ~server() noexcept;

  /** Runs the accept loop until stop is requested. */
  int run(const volatile std::sig_atomic_t &stop_requested);

private:
  void open_listener();
  void close_listener() noexcept;
  void handle_client(int client_fd);
  [[nodiscard]] bool authorize_peer(int client_fd,
                                    std::string &diagnostic) const noexcept;

  server_config config_;
  std::unique_ptr<vault_store> store_;
  int listener_{-1};
  bool owns_endpoint_{false};
};

} // namespace z::vault
