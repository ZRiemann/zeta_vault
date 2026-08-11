#pragma once

#include <stddef.h>
#include <stdint.h>

#include <zeta_vault/export.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZETA_VAULT_API_VERSION_MAJOR 0
#define ZETA_VAULT_API_VERSION_MINOR 2
#define ZETA_VAULT_API_VERSION_PATCH 0

/**
 * Opaque zeta_vault client handle.
 *
 * A handle must not be used concurrently. Create one handle per thread or
 * provide external synchronization.
 */
typedef struct zeta_vault_client zeta_vault_client_t;

/** Stable status values returned by the zeta_vault C ABI. */
typedef enum zeta_vault_status {
  ZETA_VAULT_STATUS_OK = 0,
  ZETA_VAULT_STATUS_INVALID_ARGUMENT = 1,
  ZETA_VAULT_STATUS_NOT_FOUND = 2,
  ZETA_VAULT_STATUS_LOCKED = 3,
  ZETA_VAULT_STATUS_ACCESS_DENIED = 4,
  ZETA_VAULT_STATUS_IO_ERROR = 5,
  ZETA_VAULT_STATUS_PROTOCOL_ERROR = 6,
  ZETA_VAULT_STATUS_CRYPTO_ERROR = 7,
  ZETA_VAULT_STATUS_UNSUPPORTED = 8,
  ZETA_VAULT_STATUS_INTERNAL_ERROR = 9
} zeta_vault_status_t;

/** Client creation options. */
typedef struct zeta_vault_client_options {
  /** Size of this structure for forward-compatible extension. */
  size_t struct_size;
  /** Unix socket path, or NULL to use the platform default. */
  const char *endpoint;
  /** Send and receive timeout in milliseconds; zero selects 5000 ms. */
  uint32_t timeout_ms;
} zeta_vault_client_options_t;

/** Secret buffer owned by the zeta_vault client library. */
typedef struct zeta_vault_secret {
  /** Secret bytes; not NUL-terminated unless the stored value contains NUL. */
  uint8_t *data;
  /** Number of valid secret bytes. */
  size_t size;
} zeta_vault_secret_t;

/** One lowercase C-style secret identifier owned by an identifier list. */
typedef struct zeta_vault_secret_id {
  /** NUL-terminated identifier bytes. */
  char *data;
  /** Number of identifier bytes, excluding the NUL terminator. */
  size_t size;
} zeta_vault_secret_id_t;

/** Library-owned list returned by zeta_vault_client_list_secrets. */
typedef struct zeta_vault_secret_id_list {
  /** Identifier elements, or NULL when the list is empty. */
  zeta_vault_secret_id_t *items;
  /** Number of identifier elements. */
  size_t count;
} zeta_vault_secret_id_list_t;

/**
 * Creates a connected client.
 *
 * @param options Optional client options. NULL selects defaults.
 * @param out_client Receives the newly allocated client handle.
 * @return A zeta_vault status code.
 */
ZETA_VAULT_API zeta_vault_status_t
zeta_vault_client_create(const zeta_vault_client_options_t *options,
                         zeta_vault_client_t **out_client);

/** Destroys a client and closes its socket. */
ZETA_VAULT_API void zeta_vault_client_destroy(zeta_vault_client_t *client);

/** Checks that the server is reachable and speaks the expected protocol. */
ZETA_VAULT_API zeta_vault_status_t
zeta_vault_client_ping(zeta_vault_client_t *client);

/** Stores or replaces an exportable secret. */
ZETA_VAULT_API zeta_vault_status_t zeta_vault_client_put_secret(
    zeta_vault_client_t *client, const char *secret_id, size_t secret_id_size,
    const uint8_t *secret, size_t secret_size);

/** Retrieves an exportable secret into a library-owned secure buffer. */
ZETA_VAULT_API zeta_vault_status_t zeta_vault_client_get_secret(
    zeta_vault_client_t *client, const char *secret_id, size_t secret_id_size,
    zeta_vault_secret_t *out_secret);

/** Removes a secret by identifier. */
ZETA_VAULT_API zeta_vault_status_t zeta_vault_client_remove_secret(
    zeta_vault_client_t *client, const char *secret_id, size_t secret_id_size);

/** Lists all secret identifiers in lexical order. */
ZETA_VAULT_API zeta_vault_status_t zeta_vault_client_list_secrets(
    zeta_vault_client_t *client, zeta_vault_secret_id_list_t *out_list);

/** Locks the server until it is restarted and interactively unlocked. */
ZETA_VAULT_API zeta_vault_status_t
zeta_vault_client_lock(zeta_vault_client_t *client);

/**
 * Returns the most recent client-side diagnostic string.
 *
 * The returned pointer remains valid until the next operation on the same
 * handle or until the handle is destroyed.
 */
ZETA_VAULT_API const char *
zeta_vault_client_last_error(const zeta_vault_client_t *client);

/** Securely erases and releases a secret returned by get_secret. */
ZETA_VAULT_API void zeta_vault_secret_free(zeta_vault_secret_t *secret);

/** Releases an identifier list returned by list_secrets. */
ZETA_VAULT_API void
zeta_vault_secret_id_list_free(zeta_vault_secret_id_list_t *list);

/** Returns a stable English name for a status value. */
ZETA_VAULT_API const char *zeta_vault_status_name(zeta_vault_status_t status);

#ifdef __cplusplus
}
#endif
