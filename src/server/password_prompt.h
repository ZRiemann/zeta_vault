#pragma once

#include <string>
#include <string_view>

namespace z::vault {

/** Reads one password from /dev/tty with terminal echo disabled. */
[[nodiscard]] std::string prompt_password(std::string_view prompt);

} // namespace z::vault
