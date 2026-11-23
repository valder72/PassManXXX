#ifndef PASSMAN_VAULT_H
#define PASSMAN_VAULT_H

/*
 * Vault container: the on-disk format.
 *   header (magic, version, kdf params, salt)
 *   records, each encrypted separately with XChaCha20-Poly1305
 */

#include <stddef.h>
#include <stdint.h>

#include "passman/crypto.h"

#define PM_MAGIC "PASSMANX"
#define PM_VERSION 1u

typedef struct {
    uint8_t  salt[PM_SALT_BYTES];
    pm_kdf_params kdf;
} pm_vault_header;

/* Create a new empty vault file. Returns 0 on success. */
int pm_vault_create(const char *path, const char *password);

/* Open an existing vault and derive its key into `key`. */
int pm_vault_open(const char *path, const char *password, uint8_t key[PM_KEY_BYTES]);

/* Add or replace one record. */
int pm_vault_put(const char *path, const uint8_t key[PM_KEY_BYTES],
                 const char *name, const char *secret);

/* Fetch one record into `out` (NUL-terminated). Caller wipes it afterwards. */
int pm_vault_get(const char *path, const uint8_t key[PM_KEY_BYTES],
                 const char *name, char *out, size_t out_size);

#endif /* PASSMAN_VAULT_H */
