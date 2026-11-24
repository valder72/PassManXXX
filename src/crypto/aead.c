#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <stdint.h>

#include <sodium.h>

#include "passman/crypto.h"
#include "passman/error.h"

// Largest plaintext for which PM_SEALED_SIZE() cannot overflow size_t and libsodium still accepts the message
static size_t max_plain_len(void) {
    size_t by_size_t = SIZE_MAX - PM_NONCE_BYTES - PM_TAG_BYTES;
    size_t by_sodium = crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX;
    return by_size_t < by_sodium ? by_size_t : by_sodium;
}

pm_status pm_seal(const uint8_t record_key[PM_KEY_BYTES], const uint8_t *plain, size_t plain_len, const uint8_t *ad, size_t ad_len, uint8_t *out, size_t out_size, size_t *out_len) {
    if (!record_key || !out || !out_len) return PM_ERR_ARG;
    if ((!plain && plain_len != 0) || (!ad && ad_len != 0)) return PM_ERR_ARG;

    if (plain_len > max_plain_len()) return PM_ERR_TOO_BIG;
    if (out_size < PM_SEALED_SIZE(plain_len)) return PM_ERR_TOO_BIG;

    uint8_t *nonce = out; // first 24 bytes
    pm_random(nonce, PM_NONCE_BYTES); // I forgot this line and this was like critical vulnerability, tests didn't even catch that
    uint8_t *ct = out + PM_NONCE_BYTES; // rest (ciphertext and tag)

    unsigned long long ct_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(ct, &ct_len, plain, plain_len, ad, ad_len, NULL, nonce, record_key) != 0) {
        pm_wipe(out, out_size);
        return PM_ERR_CRYPTO;
    }

    *out_len = PM_NONCE_BYTES + (size_t)ct_len;
    return PM_OK;
}

pm_status pm_open(const uint8_t record_key[PM_KEY_BYTES], const uint8_t *sealed, size_t sealed_len, const uint8_t *ad, size_t ad_len, uint8_t *plain, size_t plain_size, size_t *plain_len) {
    if (!record_key || !sealed || !plain_len) return PM_ERR_ARG;
    if (!ad && ad_len != 0) return PM_ERR_ARG;

    if (sealed_len < PM_NONCE_BYTES + PM_TAG_BYTES) return PM_ERR_FORMAT; // shortie

    size_t need = sealed_len - PM_NONCE_BYTES - PM_TAG_BYTES;
    if (plain_size < need || (need != 0 && !plain)) return PM_ERR_TOO_BIG; // big

    const uint8_t *nonce = sealed;
    const uint8_t *ct = sealed + PM_NONCE_BYTES;

    unsigned long long m_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(plain, &m_len, NULL, ct, sealed_len - PM_NONCE_BYTES, ad, ad_len, nonce, record_key) != 0) return PM_ERR_CORRUPT; // zeroed plain by lib
    
    *plain_len = (size_t)m_len;
    return PM_OK;
}
