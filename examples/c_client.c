#include <stdio.h>
#include <string.h>

#include <zeta_vault/zeta_vault.h>

int main(int argc, char **argv) {
  zeta_vault_client_t *client = NULL;
  zeta_vault_client_options_t options = {sizeof(zeta_vault_client_options_t),
                                         NULL, 5000};
  const zeta_vault_status_t created =
      zeta_vault_client_create(&options, &client);
  if (created != ZETA_VAULT_STATUS_OK) {
    fprintf(stderr, "connect failed: %s\n", zeta_vault_status_name(created));
    return 1;
  }

  if (argc == 1) {
    zeta_vault_secret_id_list_t identifiers = {0};
    const zeta_vault_status_t status =
        zeta_vault_client_list_secrets(client, &identifiers);
    if (status == ZETA_VAULT_STATUS_OK) {
      for (size_t index = 0; index < identifiers.count; ++index) {
        printf("%s\n", identifiers.items[index].data);
      }
    } else {
      fprintf(stderr, "list failed: %s: %s\n", zeta_vault_status_name(status),
              zeta_vault_client_last_error(client));
    }
    zeta_vault_secret_id_list_free(&identifiers);
    zeta_vault_client_destroy(client);
    return status == ZETA_VAULT_STATUS_OK ? 0 : 1;
  }

  zeta_vault_secret_t secret = {0};
  const zeta_vault_status_t status =
      zeta_vault_client_get_secret(client, argv[1], strlen(argv[1]), &secret);
  if (status != ZETA_VAULT_STATUS_OK) {
    fprintf(stderr, "get failed: %s: %s\n", zeta_vault_status_name(status),
            zeta_vault_client_last_error(client));
    zeta_vault_client_destroy(client);
    return 1;
  }

  printf("secret '%s' contains %zu bytes\n", argv[1], secret.size);
  zeta_vault_secret_free(&secret);
  zeta_vault_client_destroy(client);
  return 0;
}
