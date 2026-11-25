#include <sodium.h>

#include "passman/crypto.h"
#include "passman/error.h"
#include "internal.h"

// These settings are fixed forever, because changing context or key ids changes every subkey of every vault
#define PM_KDF_CONTEXT "PMXVAULT" // it's okay that is it viewable in source code as this is not a secret
_Static_assert(sizeof PM_KDF_CONTEXT - 1 == crypto_kdf_CONTEXTBYTES, "context is 8 bytes");

enum {
    PM_SUBKEY_CHECK  = 1,
    PM_SUBKEY_RECORD = 2
};

pm_status pm_derive_subkeys(const uint8_t master_key[PM_KEY_BYTES], uint8_t check_key[PM_KEY_BYTES], uint8_t record_key[PM_KEY_BYTES]) {
    if (!master_key || !check_key || !record_key) return PM_ERR_ARG;

    if (pm_overlaps(master_key, PM_KEY_BYTES, check_key, PM_KEY_BYTES) ||
    pm_overlaps(master_key, PM_KEY_BYTES, record_key, PM_KEY_BYTES) ||
    pm_overlaps(check_key, PM_KEY_BYTES, record_key, PM_KEY_BYTES)) return PM_ERR_ARG;

    if (crypto_kdf_derive_from_key(check_key, PM_KEY_BYTES, PM_SUBKEY_CHECK, PM_KDF_CONTEXT, master_key) != 0 || crypto_kdf_derive_from_key(record_key, PM_KEY_BYTES, PM_SUBKEY_RECORD, PM_KDF_CONTEXT, master_key) != 0) {
        pm_wipe(check_key, PM_KEY_BYTES);
        pm_wipe(record_key, PM_KEY_BYTES);

        return PM_ERR_CRYPTO;
    }

    return PM_OK;
}

pm_status pm_key_check_compute(const uint8_t check_key[PM_KEY_BYTES], const uint8_t *header, size_t header_len, uint8_t out[PM_CHECK_BYTES]) {
    if (!check_key || !header || header_len == 0 || !out) return PM_ERR_ARG;

    if (crypto_generichash(out, PM_CHECK_BYTES, header, header_len, check_key, PM_KEY_BYTES) != 0) return PM_ERR_CRYPTO;

    return PM_OK;
}

pm_status pm_key_check_verify(const uint8_t check_key[PM_KEY_BYTES], const uint8_t *header, size_t header_len, const uint8_t expected[PM_CHECK_BYTES]) {
    if (!expected) return PM_ERR_ARG;

    uint8_t actual[PM_CHECK_BYTES];
    pm_status st = pm_key_check_compute(check_key, header, header_len, actual);

    if (st != PM_OK) return st;

    st = sodium_memcmp(actual, expected, PM_CHECK_BYTES) == 0 ? PM_OK : PM_ERR_WRONG_PASS;
    pm_wipe(actual, PM_CHECK_BYTES);
    
    return st;
}
