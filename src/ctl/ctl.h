#pragma once

#include <cstddef>
#include <functional>
#include <iosfwd>
#include <string_view>

#include "common/hidden_input.h"

namespace z::vault::ctl {

/** Supplies hidden terminal input to the CLI. */
using hidden_input_reader = std::function<secret_input(
    std::string_view, std::size_t, std::string_view)>;

/** Runs the zeta_vault_ctl command with injectable output streams. */
int run(int argc, char **argv, std::ostream &output, std::ostream &error);

/** Runs the CLI with an injectable hidden-input reader for testing. */
int run_with_hidden_input(int argc, char **argv, std::ostream &output,
                          std::ostream &error,
                          const hidden_input_reader &read_hidden_input);

} // namespace z::vault::ctl
