#pragma once

#include <cstddef>
#include <string_view>

namespace z::vault {

/** Maximum number of bytes in a valid secret identifier. */
inline constexpr std::size_t maximum_secret_id_size = 63;

/** Returns whether a secret identifier uses lowercase C-style syntax. */
[[nodiscard]] inline bool
is_valid_secret_id(std::string_view identifier) noexcept {
  if (identifier.empty() || identifier.size() > maximum_secret_id_size ||
      identifier.front() < 'a' || identifier.front() > 'z') {
    return false;
  }
  for (const char value : identifier) {
    if ((value < 'a' || value > 'z') && (value < '0' || value > '9') &&
        value != '_') {
      return false;
    }
  }
  return true;
}

} // namespace z::vault
