#include <sodium.h>

#include "passman/crypto.h"


// This is checks for the changes in library, so if anything caught we fall instead of silently breaking vaults
_Static_assert(PM_KEY_BYTES   == crypto_aead_xchacha20poly1305_ietf_KEYBYTES, "AEAD key size");
_Static_assert(PM_NONCE_BYTES == crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, "AEAD nonce size");
_Static_assert(PM_TAG_BYTES   == crypto_aead_xchacha20poly1305_ietf_ABYTES, "AEAD tag size");
_Static_assert(PM_SALT_BYTES  == crypto_pwhash_SALTBYTES, "Argon2 salt size");
_Static_assert(PM_KEY_BYTES   == crypto_kdf_KEYBYTES, "KDF master key size");
_Static_assert(PM_KEY_BYTES   >= crypto_kdf_BYTES_MIN && PM_KEY_BYTES <= crypto_kdf_BYTES_MAX, "subkey size");
_Static_assert(PM_KEY_BYTES   >= crypto_generichash_KEYBYTES_MIN && PM_KEY_BYTES <= crypto_generichash_KEYBYTES_MAX, "check key size");
_Static_assert(PM_CHECK_BYTES >= crypto_generichash_BYTES_MIN && PM_CHECK_BYTES <= crypto_generichash_BYTES_MAX, "check value size");


pm_status pm_crypto_init(void) {
    if (sodium_init() < 0) {
        return PM_ERR_CRYPTO;
    }
    return PM_OK;
}

