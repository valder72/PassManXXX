#ifndef PASSMAN_CRYPTO_H
#define PASSMAN_CRYPTO_H

/*
 * Crypto core: everything that touches keys, nonces and ciphertext.
 * Owned by the crypto role. No I/O, no sockets, no terminal code here.
 */

#include <stddef.h>
#include <stdint.h>

/* Sizes are fixed by the format, not by whatever libsodium defaults to today. */
#define PM_KEY_LEN        32u   /* master key, XChaCha20-Poly1305 key */
#define PM_SALT_LEN       16u
#define PM_NONCE_LEN      24u   /* XChaCha20 uses a 24-byte nonce */
#define PM_TAG_LEN        16u
#define PM_MAX_SECRET_LEN 1024u

/* Argon2id parameters; stored in the vault header so old vaults stay readable. */
typedef struct {
    uint32_t opslimit;   /* time cost */
    uint32_t memlimit_kb;/* memory cost, KiB */
} pm_kdf_params;

/* Derive the master key from a password and a salt. */
int pm_kdf_derive(const char *password, const uint8_t salt[PM_SALT_LEN],
                  const pm_kdf_params *params, uint8_t key[PM_KEY_LEN]);

/* Wipe memory in a way the compiler cannot optimise away. */
void pm_wipe(void *buf, size_t len);

#endif /* PASSMAN_CRYPTO_H */
