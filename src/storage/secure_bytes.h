#pragma once

#include <cstddef>
#include <cstring>
#include <new>
#include <span>
#include <utility>

#include <sodium.h>

namespace z::vault {

/** Move-only byte buffer backed by libsodium secure allocation. */
class secure_bytes {
public:
  /** Creates an empty secure byte buffer. */
  secure_bytes() noexcept = default;

  /** Copies bytes into guarded, erasable storage. */
  explicit secure_bytes(std::span<const std::byte> source) {
    if (source.empty()) {
      return;
    }
    if (sodium_init() < 0) {
      throw std::bad_alloc{};
    }
    data_ = static_cast<std::byte *>(sodium_malloc(source.size()));
    if (data_ == nullptr) {
      throw std::bad_alloc{};
    }
    size_ = source.size();
    std::memcpy(data_, source.data(), source.size());
  }

  /** Secure buffers are not copyable. */
  secure_bytes(const secure_bytes &) = delete;

  /** Secure buffers are not copy assignable. */
  secure_bytes &operator=(const secure_bytes &) = delete;

  /** Moves a secure buffer without copying its contents. */
  secure_bytes(secure_bytes &&other) noexcept
      : data_(std::exchange(other.data_, nullptr)),
        size_(std::exchange(other.size_, 0)) {}

  /** Replaces this buffer by moving another buffer. */
  secure_bytes &operator=(secure_bytes &&other) noexcept {
    if (this != &other) {
      clear();
      data_ = std::exchange(other.data_, nullptr);
      size_ = std::exchange(other.size_, 0);
    }
    return *this;
  }

  /** Erases the buffer before releasing storage. */
  ~secure_bytes() noexcept { clear(); }

  /** Returns a read-only view of the bytes. */
  [[nodiscard]] std::span<const std::byte> view() const noexcept {
    return {data_, size_};
  }

  /** Returns an independent secure copy. */
  [[nodiscard]] secure_bytes clone() const { return secure_bytes{view()}; }

  /** Returns whether the buffer is empty. */
  [[nodiscard]] bool empty() const noexcept { return size_ == 0; }

  /** Returns the number of bytes. */
  [[nodiscard]] std::size_t size() const noexcept { return size_; }

  /** Erases and releases all bytes. */
  void clear() noexcept {
    if (data_ != nullptr) {
      sodium_memzero(data_, size_);
      sodium_free(data_);
      data_ = nullptr;
      size_ = 0;
    }
  }

private:
  std::byte *data_{nullptr};
  std::size_t size_{0};
};

} // namespace z::vault
