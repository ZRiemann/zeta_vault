#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>

#include <sodium.h>

#include "common/io.h"
#include "server/password_prompt.h"
#include "server/server.h"
#include "storage/vault_store.h"

namespace {

volatile std::sig_atomic_t stop_requested = 0;

void handle_signal(int) noexcept { stop_requested = 1; }

/** Parsed command-line paths for the server process. */
struct command_line {
  std::string vault_path;
  std::string endpoint;
};

/** Erases a master-password string when leaving scope. */
class password_guard {
public:
  /** Starts guarding a master-password string. */
  explicit password_guard(std::string &password) noexcept
      : password_(password) {}

  /** Password guards are not copyable. */
  password_guard(const password_guard &) = delete;

  /** Password guards are not copy assignable. */
  password_guard &operator=(const password_guard &) = delete;

  /** Erases the guarded password. */
  ~password_guard() noexcept {
    if (!password_.empty()) {
      sodium_memzero(password_.data(), password_.size());
    }
  }

private:
  std::string &password_;
};

void print_usage(std::string_view executable) {
  std::cout << "Usage: " << executable
            << " [--vault PATH] [--socket PATH] [--help]\n";
}

command_line parse_arguments(int argc, char **argv) {
  command_line result{z::vault::io::default_vault_path(),
                      z::vault::io::default_endpoint()};
  for (int index = 1; index < argc; ++index) {
    const std::string_view argument{argv[index]};
    if (argument == "--help") {
      print_usage(argv[0]);
      std::exit(0);
    }
    if (argument == "--vault" || argument == "--socket") {
      if (++index >= argc) {
        throw std::invalid_argument(std::string{argument} +
                                    " requires a value");
      }
      if (argument == "--vault") {
        result.vault_path = argv[index];
      } else {
        result.endpoint = argv[index];
      }
      continue;
    }
    throw std::invalid_argument("unknown argument: " + std::string{argument});
  }
  return result;
}

} // namespace

int main(int argc, char **argv) {
  try {
    if (sodium_init() < 0) {
      throw std::runtime_error("libsodium initialization failed");
    }
    const auto options = parse_arguments(argc, argv);
    const bool creating = !std::filesystem::exists(options.vault_path);

    std::unique_ptr<z::vault::vault_store> store;
    {
      auto password = z::vault::prompt_password(
          creating ? "Create vault master password: "
                   : "Vault master password: ");
      password_guard password_cleanup{password};
      if (creating) {
        auto confirmation =
            z::vault::prompt_password("Confirm vault master password: ");
        password_guard confirmation_cleanup{confirmation};
        if (password != confirmation) {
          throw std::runtime_error(
              "master password confirmation does not match");
        }
      }
      store =
          std::make_unique<z::vault::vault_store>(options.vault_path, password);
    }

    if (std::signal(SIGINT, handle_signal) == SIG_ERR ||
        std::signal(SIGTERM, handle_signal) == SIG_ERR) {
      throw std::runtime_error("unable to install signal handlers");
    }
    z::vault::server service{
        z::vault::server_config{options.vault_path, options.endpoint},
        std::move(store)};
    return service.run(stop_requested);
  } catch (const std::exception &exception) {
    std::cerr << "zeta_vault_server: " << exception.what() << '\n';
    return 1;
  }
}
