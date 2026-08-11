#include "storage/vault_store.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <zpp/wire/reader.h>
#include <zpp/wire/size_counter.h>
#include <zpp/wire/writer.h>

#include "common/io.h"
#include "common/secret_id.h"

namespace z::vault {
namespace {

constexpr std::array<std::byte, 8> file_magic{
    std::byte{'Z'}, std::byte{'V'}, std::byte{'L'}, std::byte{'T'},
    std::byte{'D'}, std::byte{'B'}, std::byte{'0'}, std::byte{'1'}};
constexpr std::uint32_t file_version = 1;
constexpr std::array<unsigned char, 13> associated_data{
    'z', 'e', 't', 'a', '_', 'v', 'a', 'u', 'l', 't', ':', 'v', '1'};
constexpr std::size_t file_header_size =
    file_magic.size() + sizeof(std::uint32_t) + 2 * sizeof(std::uint64_t) +
    crypto_pwhash_SALTBYTES + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES +
    sizeof(std::uint64_t);
constexpr std::size_t maximum_file_size = 64U * 1024U * 1024U;
constexpr std::size_t maximum_secret_count = 10000;
constexpr std::size_t maximum_legacy_secret_id_size = 4096;
constexpr std::size_t maximum_secret_size = 1024U * 1024U;
constexpr std::uint64_t minimum_opslimit = 1;
constexpr std::uint64_t maximum_opslimit = 10;
constexpr std::uint64_t minimum_memlimit = 8U * 1024U * 1024U;
constexpr std::uint64_t maximum_memlimit = 1024ULL * 1024ULL * 1024ULL;
constexpr std::size_t maximum_plaintext_size =
    maximum_file_size - file_header_size -
    crypto_aead_xchacha20poly1305_ietf_ABYTES;

/** Erases a plaintext byte vector when leaving scope. */
class vector_wipe_guard {
public:
  explicit vector_wipe_guard(std::vector<std::byte> &value) noexcept
      : value_(value) {}
  vector_wipe_guard(const vector_wipe_guard &) = delete;
  vector_wipe_guard &operator=(const vector_wipe_guard &) = delete;
  ~vector_wipe_guard() noexcept {
    if (active_ && !value_.empty()) {
      sodium_memzero(value_.data(), value_.size());
    }
  }
  void release() noexcept { active_ = false; }

private:
  std::vector<std::byte> &value_;
  bool active_{true};
};

std::runtime_error system_error(std::string_view operation) {
  return std::runtime_error(std::string{operation} + ": " +
                            std::strerror(errno));
}

std::span<const std::byte> as_bytes(std::string_view value) noexcept {
  return {reinterpret_cast<const std::byte *>(value.data()), value.size()};
}

template <typename Writer>
bool write_sized_bytes(Writer &writer, std::span<const std::byte> value) {
  if (value.size() > std::numeric_limits<std::uint32_t>::max()) {
    return false;
  }
  return writer.write_u32(static_cast<std::uint32_t>(value.size())) &&
         writer.write_bytes(value);
}

bool read_sized_bytes(z::wire::reader &reader, std::vector<std::byte> &value,
                      std::size_t maximum_size) {
  std::uint32_t size{0};
  if (!reader.read_u32(size) || size > maximum_size ||
      size > reader.remaining()) {
    return false;
  }
  value.resize(size);
  return reader.read_bytes(value);
}

std::string random_suffix() {
  std::array<unsigned char, 8> random{};
  randombytes_buf(random.data(), random.size());
  constexpr char hexadecimal[] = "0123456789abcdef";
  std::string result;
  result.reserve(random.size() * 2);
  for (const auto value : random) {
    result.push_back(hexadecimal[value >> 4U]);
    result.push_back(hexadecimal[value & 0x0fU]);
  }
  return result;
}

void write_file_atomically(const std::filesystem::path &path,
                           std::span<const std::byte> data) {
  io::ensure_private_parent(path.string());
  const auto temporary = path.string() + ".tmp." + random_suffix();
  int fd = ::open(temporary.c_str(),
                  O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                  S_IRUSR | S_IWUSR);
  if (fd < 0) {
    throw system_error("open temporary vault file");
  }

  try {
    std::size_t offset{0};
    while (offset < data.size()) {
      const auto written =
          ::write(fd, data.data() + offset, data.size() - offset);
      if (written < 0) {
        if (errno == EINTR) {
          continue;
        }
        throw system_error("write temporary vault file");
      }
      if (written == 0) {
        throw std::runtime_error("write temporary vault file returned zero");
      }
      offset += static_cast<std::size_t>(written);
    }
    if (::fsync(fd) != 0) {
      throw system_error("fsync temporary vault file");
    }
    if (::close(fd) != 0) {
      fd = -1;
      throw system_error("close temporary vault file");
    }
    fd = -1;
    if (::rename(temporary.c_str(), path.c_str()) != 0) {
      throw system_error("rename vault file");
    }

    const auto parent = path.parent_path();
    const int parent_fd =
        ::open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (parent_fd >= 0) {
      (void)::fsync(parent_fd);
      (void)::close(parent_fd);
    }
  } catch (...) {
    if (fd >= 0) {
      (void)::close(fd);
    }
    (void)::unlink(temporary.c_str());
    throw;
  }
}

std::vector<std::byte> read_file(const std::filesystem::path &path) {
  const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) {
    throw system_error("open vault file");
  }

  try {
    struct stat metadata{};
    if (::fstat(fd, &metadata) != 0) {
      throw system_error("fstat vault file");
    }
    if (!S_ISREG(metadata.st_mode) || metadata.st_uid != ::geteuid()) {
      throw std::runtime_error(
          "vault file must be a regular file owned by the effective user");
    }
    if ((metadata.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
      throw std::runtime_error(
          "vault file permissions must deny group and other access");
    }
    if (metadata.st_size < 0 ||
        static_cast<std::uint64_t>(metadata.st_size) > maximum_file_size) {
      throw std::runtime_error("vault file size exceeds the limit");
    }

    std::vector<std::byte> data(static_cast<std::size_t>(metadata.st_size));
    std::size_t offset{0};
    while (offset < data.size()) {
      const auto received =
          ::read(fd, data.data() + offset, data.size() - offset);
      if (received < 0) {
        if (errno == EINTR) {
          continue;
        }
        throw system_error("read vault file");
      }
      if (received == 0) {
        throw std::runtime_error("vault file is truncated");
      }
      offset += static_cast<std::size_t>(received);
    }
    (void)::close(fd);
    return data;
  } catch (...) {
    (void)::close(fd);
    throw;
  }
}

} // namespace

vault_store::vault_store(std::filesystem::path path, std::string_view password)
    : path_(std::move(path)) {
  if (sodium_init() < 0) {
    throw std::runtime_error("libsodium initialization failed");
  }
  if (password.empty()) {
    throw std::invalid_argument("master password must not be empty");
  }

  acquire_file_lock();
  try {
    if (std::filesystem::exists(path_)) {
      load_existing(password);
    } else {
      create_new(password);
    }
  } catch (...) {
    secrets_.clear();
    sodium_memzero(key_.data(), key_.size());
    release_file_lock();
    throw;
  }
}

vault_store::~vault_store() noexcept {
  lock();
  release_file_lock();
}

void vault_store::put(std::string_view id, std::span<const std::byte> value) {
  require_unlocked();
  if (!is_valid_secret_id(id) || value.size() > maximum_secret_size) {
    throw std::invalid_argument("invalid secret identifier or value size");
  }
  if (!secrets_.contains(std::string{id}) &&
      secrets_.size() >= maximum_secret_count) {
    throw std::length_error("secret count exceeds the limit");
  }

  auto candidate = clone_secrets(secrets_);
  candidate.insert_or_assign(std::string{id}, secure_bytes{value});
  persist(candidate);
  secrets_ = std::move(candidate);
}

secure_bytes vault_store::get(std::string_view id) const {
  require_unlocked();
  if (!is_valid_secret_id(id)) {
    throw std::invalid_argument("invalid secret identifier");
  }
  const auto found = secrets_.find(std::string{id});
  if (found == secrets_.end()) {
    throw std::out_of_range("secret not found");
  }
  return found->second.clone();
}

bool vault_store::remove(std::string_view id) {
  require_unlocked();
  if (!is_valid_secret_id(id)) {
    throw std::invalid_argument("invalid secret identifier");
  }
  if (!secrets_.contains(std::string{id})) {
    return false;
  }

  auto candidate = clone_secrets(secrets_);
  candidate.erase(std::string{id});
  persist(candidate);
  secrets_ = std::move(candidate);
  return true;
}

std::vector<std::string> vault_store::list() const {
  require_unlocked();
  std::vector<std::string> identifiers;
  identifiers.reserve(secrets_.size());
  for (const auto &[identifier, value] : secrets_) {
    (void)value;
    identifiers.push_back(identifier);
  }
  std::sort(identifiers.begin(), identifiers.end());
  return identifiers;
}

void vault_store::lock() noexcept {
  secrets_.clear();
  sodium_memzero(key_.data(), key_.size());
  locked_ = true;
}

void vault_store::acquire_file_lock() {
  io::ensure_private_parent(path_.string());
  const auto lock_path = path_.string() + ".lock";
  lock_fd_ =
      ::open(lock_path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW,
             S_IRUSR | S_IWUSR);
  if (lock_fd_ < 0) {
    throw system_error("open vault lock file");
  }

  struct stat metadata{};
  if (::fstat(lock_fd_, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
      metadata.st_uid != ::geteuid()) {
    release_file_lock();
    throw std::runtime_error(
        "vault lock file must be regular and owned by the effective user");
  }
  if ((metadata.st_mode & (S_IRWXG | S_IRWXO)) != 0 &&
      ::fchmod(lock_fd_, S_IRUSR | S_IWUSR) != 0) {
    const auto error = system_error("harden vault lock file");
    release_file_lock();
    throw error;
  }
  if (::flock(lock_fd_, LOCK_EX | LOCK_NB) != 0) {
    const auto message = errno == EWOULDBLOCK
                             ? std::runtime_error("vault is already open")
                             : system_error("lock vault file");
    release_file_lock();
    throw message;
  }
}

void vault_store::release_file_lock() noexcept {
  if (lock_fd_ >= 0) {
    (void)::flock(lock_fd_, LOCK_UN);
    (void)::close(lock_fd_);
    lock_fd_ = -1;
  }
}

void vault_store::create_new(std::string_view password) {
  randombytes_buf(salt_.data(), salt_.size());
  derive_key(password);
  locked_ = false;
  persist(secrets_);
}

void vault_store::load_existing(std::string_view password) {
  auto encoded = read_file(path_);
  if (encoded.size() < file_header_size) {
    throw std::runtime_error("vault file is truncated");
  }

  z::wire::reader reader{encoded};
  std::array<std::byte, file_magic.size()> decoded_magic{};
  std::uint32_t decoded_version{0};
  std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>
      nonce{};
  std::uint64_t ciphertext_size{0};
  if (!reader.read_bytes(decoded_magic) || !reader.read_u32(decoded_version) ||
      !reader.read_u64(opslimit_) || !reader.read_u64(memlimit_) ||
      !reader.read_bytes(std::as_writable_bytes(std::span{salt_})) ||
      !reader.read_bytes(std::as_writable_bytes(std::span{nonce})) ||
      !reader.read_u64(ciphertext_size)) {
    throw std::runtime_error("vault file header is truncated");
  }
  if (decoded_magic != file_magic || decoded_version != file_version) {
    throw std::runtime_error("unsupported vault file format");
  }
  if (opslimit_ < minimum_opslimit || opslimit_ > maximum_opslimit ||
      memlimit_ < minimum_memlimit || memlimit_ > maximum_memlimit) {
    throw std::runtime_error("vault KDF parameters exceed safety limits");
  }
  if (ciphertext_size != reader.remaining() ||
      ciphertext_size < crypto_aead_xchacha20poly1305_ietf_ABYTES) {
    throw std::runtime_error("invalid vault ciphertext size");
  }

  derive_key(password);
  std::vector<std::byte> ciphertext(reader.remaining());
  if (!reader.read_bytes(ciphertext) || !reader.complete()) {
    throw std::runtime_error("vault ciphertext is truncated");
  }
  std::vector<std::byte> plaintext(ciphertext.size() -
                                   crypto_aead_xchacha20poly1305_ietf_ABYTES);
  vector_wipe_guard plaintext_guard{plaintext};
  unsigned long long plaintext_size{0};
  if (crypto_aead_xchacha20poly1305_ietf_decrypt(
          reinterpret_cast<unsigned char *>(plaintext.data()), &plaintext_size,
          nullptr, reinterpret_cast<const unsigned char *>(ciphertext.data()),
          static_cast<unsigned long long>(ciphertext.size()),
          associated_data.data(),
          static_cast<unsigned long long>(associated_data.size()), nonce.data(),
          key_.data()) != 0) {
    sodium_memzero(key_.data(), key_.size());
    throw std::runtime_error("invalid password or corrupted vault file");
  }
  plaintext.resize(static_cast<std::size_t>(plaintext_size));
  try {
    deserialize_plaintext(plaintext);
    locked_ = false;
  } catch (...) {
    sodium_memzero(key_.data(), key_.size());
    throw;
  }
}

void vault_store::derive_key(std::string_view password) {
  if (crypto_pwhash(key_.data(), static_cast<unsigned long long>(key_.size()),
                    password.data(),
                    static_cast<unsigned long long>(password.size()),
                    salt_.data(), static_cast<unsigned long long>(opslimit_),
                    static_cast<std::size_t>(memlimit_),
                    crypto_pwhash_ALG_ARGON2ID13) != 0) {
    throw std::runtime_error("Argon2id key derivation failed");
  }
}

void vault_store::persist(const secret_map &secrets) const {
  require_unlocked();
  auto plaintext = serialize_plaintext(secrets);
  vector_wipe_guard plaintext_guard{plaintext};
  std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>
      nonce{};
  randombytes_buf(nonce.data(), nonce.size());
  std::vector<std::byte> ciphertext(plaintext.size() +
                                    crypto_aead_xchacha20poly1305_ietf_ABYTES);
  unsigned long long ciphertext_size{0};
  if (crypto_aead_xchacha20poly1305_ietf_encrypt(
          reinterpret_cast<unsigned char *>(ciphertext.data()),
          &ciphertext_size,
          reinterpret_cast<const unsigned char *>(plaintext.data()),
          static_cast<unsigned long long>(plaintext.size()),
          associated_data.data(),
          static_cast<unsigned long long>(associated_data.size()), nullptr,
          nonce.data(), key_.data()) != 0) {
    throw std::runtime_error("vault encryption failed");
  }
  ciphertext.resize(static_cast<std::size_t>(ciphertext_size));

  std::vector<std::byte> encoded(file_header_size + ciphertext.size());
  z::wire::writer writer{encoded};
  if (!writer.write_bytes(file_magic) || !writer.write_u32(file_version) ||
      !writer.write_u64(opslimit_) || !writer.write_u64(memlimit_) ||
      !writer.write_bytes(std::as_bytes(std::span{salt_})) ||
      !writer.write_bytes(std::as_bytes(std::span{nonce})) ||
      !writer.write_u64(static_cast<std::uint64_t>(ciphertext.size())) ||
      !writer.write_bytes(ciphertext) || !writer.complete()) {
    throw std::runtime_error("vault file encoding failed");
  }
  write_file_atomically(path_, encoded);
}

std::vector<std::byte>
vault_store::serialize_plaintext(const secret_map &secrets) const {
  if (secrets.size() > maximum_secret_count) {
    throw std::runtime_error("vault secret count exceeds the limit");
  }
  std::vector<std::string_view> ids;
  ids.reserve(secrets.size());
  for (const auto &[id, value] : secrets) {
    (void)value;
    if (!is_valid_secret_id(id)) {
      throw std::runtime_error("vault contains an invalid secret identifier");
    }
    ids.emplace_back(id);
  }
  std::sort(ids.begin(), ids.end());

  const auto encode = [&](auto &writer) {
    if (!writer.write_u32(static_cast<std::uint32_t>(ids.size()))) {
      return false;
    }
    for (const auto id : ids) {
      const auto found = secrets.find(std::string{id});
      if (found == secrets.end() || !write_sized_bytes(writer, as_bytes(id)) ||
          !write_sized_bytes(writer, found->second.view())) {
        return false;
      }
    }
    return true;
  };

  z::wire::size_counter counter;
  if (!encode(counter) || !counter.ok() ||
      counter.size() > maximum_plaintext_size) {
    throw std::runtime_error("vault plaintext size exceeds the limit");
  }
  std::vector<std::byte> plaintext(counter.size());
  vector_wipe_guard plaintext_guard{plaintext};
  z::wire::writer writer{plaintext};
  if (!encode(writer) || !writer.complete()) {
    throw std::runtime_error("vault plaintext encoding failed");
  }
  plaintext_guard.release();
  return plaintext;
}

void vault_store::deserialize_plaintext(std::span<const std::byte> plaintext) {
  z::wire::reader reader{plaintext};
  std::uint32_t count{0};
  if (!reader.read_u32(count) || count > maximum_secret_count) {
    throw std::runtime_error("invalid vault secret count");
  }
  secret_map decoded;
  decoded.reserve(count);
  for (std::uint32_t index = 0; index < count; ++index) {
    std::vector<std::byte> id_bytes;
    std::vector<std::byte> value;
    vector_wipe_guard value_guard{value};
    if (!read_sized_bytes(reader, id_bytes, maximum_legacy_secret_id_size) ||
        id_bytes.empty() ||
        !read_sized_bytes(reader, value, maximum_secret_size)) {
      throw std::runtime_error("invalid vault plaintext entry");
    }
    std::string id{reinterpret_cast<const char *>(id_bytes.data()),
                   id_bytes.size()};
    if (!is_valid_secret_id(id)) {
      throw std::runtime_error(
          "vault contains a secret identifier not permitted by v0.3.0; "
          "use v0.2.0 to migrate it before upgrading");
    }
    const auto [position, inserted] =
        decoded.emplace(std::move(id), secure_bytes{value});
    (void)position;
    if (!inserted) {
      throw std::runtime_error("duplicate secret identifier in vault");
    }
  }
  if (!reader.complete()) {
    throw std::runtime_error("trailing bytes in vault plaintext");
  }
  secrets_ = std::move(decoded);
}

vault_store::secret_map vault_store::clone_secrets(const secret_map &source) {
  secret_map result;
  result.reserve(source.size());
  for (const auto &[id, value] : source) {
    result.emplace(id, value.clone());
  }
  return result;
}

void vault_store::require_unlocked() const {
  if (locked_) {
    throw std::logic_error("vault is locked");
  }
}

} // namespace z::vault
