#ifndef PASSMAN_VAULT_H
#define PASSMAN_VAULT_H

/*
    vault container on-disk format (integers are little-endian)

       offset  size  field
            0     8  magic "PASSMANX"
            8     4  version (1)
           12     8  Argon2id opslimit
           20     8  Argon2id memlimit, bytes
           28    16  salt
           44    32  key check = BLAKE2b(check_key, bytes 0..43)
           76     -  body = pm_seal(record_key, plain body, AD = bytes 0..75)

    plain body: u32 count, then count records of u16 name_len, name (no '\0'), u16 secret_len, secret (no '\0')
    The whole body is one AEAD message, so names, the number of records, deleting or reordering records are all hidden or detected. Rolling the whole file back to an older copy is NOT detected.
    key[] in every function below is the master key returned by pm_vault_open; subkeys are derived from it on each call.
 */

#include <stddef.h>
#include <stdint.h>

#include "passman/crypto.h"

#define PM_MAGIC "PASSMANX"
#define PM_VERSION 1u   

#define PM_MAX_NAME_LEN 256u                       // including \0
#define PM_VAULT_MAX_FILE (4u * 1024u * 1024u)     // refuse to load bigger files
#define PM_VAULT_DEFAULT_MEMLIMIT (256ull * 1024u * 1024u)
#define PM_VAULT_DEFAULT_TARGET_MS 1000u

typedef struct {
    uint8_t  salt[PM_SALT_BYTES];
    pm_kdf_params kdf;
} pm_vault_header;

// Create a new empty vault. fails with PM_ERR_IO if path already exists; params == NULL: calibrate Argon2id on this machine (~1s); caller enforces password policy (like no empty password)
pm_status pm_vault_create(const char *path, const char *password, const pm_kdf_params *params);

// Derive the master key, check it and authenticate the whole file; returns PM_OK, PM_ERR_WRONG_PASS, PM_ERR_FORMAT, PM_ERR_CORRUPT, PM_ERR_IO, PM_ERR_TOO_BIG, PM_ERR_NOMEM. On failure key is zeroed
pm_status pm_vault_open(const char *path, const char *password, uint8_t key[PM_KEY_BYTES]);

// Add or replace one record, the file is replaced atomically (so if it crashes it is new or old, no in between)
pm_status pm_vault_put(const char *path, const uint8_t key[PM_KEY_BYTES], const char *name, const char *secret);

// Fetch one record into out (with \0), caller wipes it afterwards; PM_ERR_NOT_FOUND if there is no such name, PM_ERR_TOO_BIG if out is small
pm_status pm_vault_get(const char *path, const uint8_t key[PM_KEY_BYTES], const char *name, char *out, size_t out_size);

// Callback invoked for each record name in the vault. Return non-zero to stop
typedef int (*pm_vault_list_cb)(const char *name, void *user_data);

// Enumerate all record names in the vault without exposing secrets
pm_status pm_vault_list(const char *path, const uint8_t key[PM_KEY_BYTES], pm_vault_list_cb cb, void *user_data); // changed after agent implementation is ok, because PM_OK is 0

#endif /* PASSMAN_VAULT_H */
