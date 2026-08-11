#pragma once

#include <cstddef>
#include <span>
#include <string_view>
#include <vector>

namespace z::vault {

/** Move-only hidden input whose bytes are erased before release. */
class secret_input {
public:
  /** Reserves capacity for one hidden input. */
  explicit secret_input(std::size_t capacity = 0);

  /** Copies existing bytes into an erasable hidden input. */
  explicit secret_input(std::span<const std::byte> value);

  /** Hidden inputs are not copyable. */
  secret_input(const secret_input &) = delete;

  /** Hidden inputs are not copy assignable. */
  secret_input &operator=(const secret_input &) = delete;

  /** Moves a hidden input without copying its bytes. */
  secret_input(secret_input &&other) noexcept;

  /** Replaces this input by moving another hidden input. */
  secret_input &operator=(secret_input &&other) noexcept;

  /** Erases the hidden input before releasing its storage. */
  ~secret_input() noexcept;

  /** Appends one byte to the hidden input. */
  void push_back(std::byte value);

  /** Returns a read-only view of the hidden bytes. */
  [[nodiscard]] std::span<const std::byte> bytes() const noexcept;

  /** Returns a read-only text view of the hidden bytes. */
  [[nodiscard]] std::string_view text() const noexcept;

  /** Returns whether the hidden input is empty. */
  [[nodiscard]] bool empty() const noexcept;

  /** Returns the hidden input size in bytes. */
  [[nodiscard]] std::size_t size() const noexcept;

private:
  void clear() noexcept;

  std::vector<std::byte> bytes_;
};

/** Reads one bounded line from /dev/tty with terminal echo disabled. */
[[nodiscard]] secret_input prompt_hidden_input(std::string_view prompt,
                                               std::size_t maximum_size,
                                               std::string_view value_name);

} // namespace z::vault
