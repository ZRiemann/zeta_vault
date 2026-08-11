#pragma once

#include <cstddef>
#include <span>
#include <string>
#include <string_view>

namespace z::vault::io {

/** Writes all bytes unless an error occurs. */
[[nodiscard]] bool write_all(int fd, std::span<const std::byte> data,
                             std::string &diagnostic) noexcept;

/** Reads exactly the supplied number of bytes unless EOF or an error occurs. */
[[nodiscard]] bool read_all(int fd, std::span<std::byte> data,
                            std::string &diagnostic) noexcept;

/** Applies send and receive socket timeouts. */
[[nodiscard]] bool set_socket_timeout(int fd, unsigned timeout_ms,
                                      std::string &diagnostic) noexcept;

/** Returns the default per-user Unix socket path. */
[[nodiscard]] std::string default_endpoint();

/** Returns the default encrypted vault file path. */
[[nodiscard]] std::string default_vault_path();

/** Creates a private parent directory for a path when necessary. */
void ensure_private_parent(std::string_view path);

} // namespace z::vault::io
