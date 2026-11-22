#include "passman/crypto.h"

/* TODO(crypto): argon2id via crypto_pwhash_argon2id() */
int pm_kdf_derive(const char *password, const uint8_t salt[PM_SALT_LEN],
                  const pm_kdf_params *params, uint8_t key[PM_KEY_LEN]) {
    (void)password; (void)salt; (void)params; (void)key;
    return -1;
}
