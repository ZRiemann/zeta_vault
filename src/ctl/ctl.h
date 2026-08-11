#pragma once

#include <iosfwd>

namespace z::vault::ctl {

/** Runs the zeta_vault_ctl command with injectable output streams. */
int run(int argc, char **argv, std::ostream &output, std::ostream &error);

} // namespace z::vault::ctl
