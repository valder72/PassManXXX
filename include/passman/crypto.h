#ifndef PASSMAN_CRYPTO_H
#define PASSMAN_CRYPTO_H

// Crypto core. key derivation, key separation, key check and record

// Thread safe, because libsodium is thread safe (*after calling pm_crypto_init() and module keeps no global state vars)
// Memory: CALLER OWNS EVERY KEY BUFFER
// Temp secrets are wiped before function returns

#include "passman/error.h"
#include <stddef.h>
#include <stdint.h>

#define PM_KEY_BYTES 32u  // master key and every subkey
#define PM_SALT_BYTES 16u  // Argon2id salt, random per vault
#define PM_NONCE_BYTES 24u  // XChaCha20-Poly1305 nonce, random per record
#define PM_TAG_BYTES 16u  // Poly1305 authentication tag 
#define PM_CHECK_BYTES 32u  // key check value stored in the vault header
#define PM_MAX_SECRET_LEN 1024u // max user password len

// size of one sealed record
#define PM_SEALED_SIZE(plain_len) ((plain_len) + PM_NONCE_BYTES + PM_TAG_BYTES)

// argon2id cost. Stored in vault header, so with what parameters vault was created, with that it will live on, even if defaults change in future versions
typedef struct {
    uint64_t opslimit;
    uint64_t memlimit;
} pm_kdf_params;

// initialise libsodium. Call once at startup before using any pm_ function. Safe to call more than once. Returns PM_OK is ok or PM_ERR_CRYPTO if failed to initialise
pm_status pm_crypto_init(void);

// choose Argon2id parameters for a new vault: memory is fixed to memlimit, the number of passes is raised until one derivation takes about target_ms milliseconds on this machine.
// returns PM_OK, PM_ERR_ARG, or PM_ERR_NOMEM if memlimit cannot be allocated.
pm_status pm_kdf_calibrate(uint64_t memlimit, unsigned target_ms, pm_kdf_params *out);


// derive the 32-byte master key from a password with Argon2id.
// password does not have to have '\0' at the end as its length is given explicitly
// master_key is owned by the caller and must hold PM_KEY_BYTES
// blocks for about the calibrated time; may be run on a worker thread
// returns PM_OK, PM_ERR_ARG, or PM_ERR_NOMEM

pm_status pm_kdf_derive(const char *password, size_t password_len,
                        const uint8_t salt[PM_SALT_BYTES],
                        const pm_kdf_params *params,
                        uint8_t master_key[PM_KEY_BYTES]);


// split the master key into independent subkeys with BLAKE2b
// (crypto_kdf_derive_from_key). The master key is not used directly for
// anything else, so the check value and record encryption never share a key, master_key should be erased after splitting keys by caller
// all three buffers are owned by the caller
// returns PM_OK or PM_ERR_ARG

pm_status pm_derive_subkeys(const uint8_t master_key[PM_KEY_BYTES],
                            uint8_t check_key[PM_KEY_BYTES],
                            uint8_t record_key[PM_KEY_BYTES]);


//  compute the key check value: a keyed BLAKE2b hash of the vault header
//  bytes. Stored in the header when the vault is created
//  header must not include the check value field itself
//  returns PM_OK or PM_ERR_ARG
pm_status pm_key_check_compute(const uint8_t check_key[PM_KEY_BYTES],
                               const uint8_t *header, size_t header_len,
                               uint8_t out[PM_CHECK_BYTES]);


// recompute the check value and compare it with expected in constant time
// returns PM_OK if the password was right, PM_ERR_WRONG_PASS otherwise
pm_status pm_key_check_verify(const uint8_t check_key[PM_KEY_BYTES],
                              const uint8_t *header, size_t header_len,
                              const uint8_t expected[PM_CHECK_BYTES]);


// encrypt one record with XChaCha20-Poly1305 and a fresh random nonce
// output layout: nonce || ciphertext || tag, PM_SEALED_SIZE(plain_len) bytes
// associated data is authenticated but not encrypted: pass the
// record name, so an encrypted secret cannot be moved under another name
// returns PM_OK, PM_ERR_ARG, or PM_ERR_TOO_BIG if out_size is too small
pm_status pm_seal(const uint8_t record_key[PM_KEY_BYTES],
                  const uint8_t *plain, size_t plain_len,
                  const uint8_t *ad, size_t ad_len,
                  uint8_t *out, size_t out_size, size_t *out_len);


// decrypt and authenticate a record produced by pm_seal with the same associated data
// on failure plain is zeroed
// the caller must wipe plain with pm_wipe as soon as it is no longer needed
// returns PM_OK, PM_ERR_ARG, PM_ERR_FORMAT (shorter than nonce + tag), PM_ERR_TOO_BIG (plain_size too small), or PM_ERR_CORRUPT (tag mismatch)
pm_status pm_open(const uint8_t record_key[PM_KEY_BYTES],
                  const uint8_t *sealed, size_t sealed_len,
                  const uint8_t *ad, size_t ad_len,
                  uint8_t *plain, size_t plain_size, size_t *plain_len);



// fill buf with cryptographically secure random bytes
void pm_random(uint8_t *buf, size_t len);

// wipe memory in a way the compiler cannot optimise away. Safe to call with NULL ptr
void pm_wipe(void *buf, size_t len);

#endif /* PASSMAN_CRYPTO_H */
