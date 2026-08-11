#include <type_traits>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <zeta_vault/zeta_vault.hpp>

namespace z::vault {
namespace {

TEST(cpp_wrapper, secret_is_move_only) {
  static_assert(!std::is_copy_constructible_v<secret>);
  static_assert(!std::is_copy_assignable_v<secret>);
  static_assert(std::is_nothrow_move_constructible_v<secret>);
  static_assert(std::is_nothrow_move_assignable_v<secret>);
  secret value;
  EXPECT_TRUE(value.empty());
}

TEST(cpp_wrapper, client_is_move_only) {
  static_assert(!std::is_copy_constructible_v<client>);
  static_assert(!std::is_copy_assignable_v<client>);
  static_assert(std::is_nothrow_move_constructible_v<client>);
  static_assert(std::is_nothrow_move_assignable_v<client>);
}

TEST(cpp_wrapper, list_returns_owned_strings) {
  static_assert(std::is_same_v<decltype(std::declval<client &>().list()),
                               std::vector<std::string>>);
}

} // namespace
} // namespace z::vault
