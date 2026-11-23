#include <stddef.h>

#include "passman/vault.h"

int pm_vault_create(const char *path, const char *password) {
    (void)path; (void)password;
    return -1;
}

int pm_vault_open(const char *path, const char *password, uint8_t key[PM_KEY_BYTES]) {
    (void)path; (void)password; (void)key;
    return -1;
}

int pm_vault_put(const char *path, const uint8_t key[PM_KEY_BYTES],
                 const char *name, const char *secret) {
    (void)path; (void)key; (void)name; (void)secret;
    return -1;
}

int pm_vault_get(const char *path, const uint8_t key[PM_KEY_BYTES],
                 const char *name, char *out, size_t out_size) {
    (void)path; (void)key; (void)name; (void)out; (void)out_size;
    return -1;
}
