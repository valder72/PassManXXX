#ifndef PASSMAN_TOTP_H
#define PASSMAN_TOTP_H

// One-time passwords for two-factor authentication.
//   HOTP: RFC 4226 (counter based)
//   TOTP: RFC 6238 (time based, counter = (unix_time - 0) / period)
//   secrets are base32 (RFC 4648) or an otpauth://totp/... URI, the format
//   authenticator apps put into their QR codes.
//
// Pure computation: no I/O, no global state. Every function that touches
// the secret wipes its temporary buffers before returning.

#include <stddef.h>
#include <stdint.h>

#include "passman/error.h"

#define PM_TOTP_MAX_KEY 128u          // longest decoded secret we accept, bytes
#define PM_TOTP_DEFAULT_DIGITS 6u
#define PM_TOTP_DEFAULT_PERIOD 30u
#define PM_TOTP_MIN_DIGITS 6u          // RFC 4226: at least 6 digits
#define PM_TOTP_MAX_DIGITS 8u          // 10^8 still fits in 31 bits
#define PM_TOTP_MAX_PERIOD 3600u

#define PM_HMAC_MAX_BYTES 64u          // SHA-512 output, the biggest one

typedef enum {
    PM_TOTP_SHA1 = 0, // default, the only one Google Authenticator really supports
    PM_TOTP_SHA256 = 1,
    PM_TOTP_SHA512 = 2
} pm_totp_algo;

typedef struct {
    uint8_t key[PM_TOTP_MAX_KEY];
    size_t key_len;
    pm_totp_algo algo;
    unsigned digits;
    unsigned period;
} pm_totp_cfg;

// Decode RFC 4648 base32. Case-insensitive; spaces, '-' and trailing '='
// are ignored (people copy secrets as "JBSW Y3DP EHPK 3PXP").
// Returns PM_OK, PM_ERR_ARG (bad character / NULL), PM_ERR_TOO_BIG (out too small).
// On failure out is wiped.
pm_status pm_base32_decode(const char *in, uint8_t *out, size_t out_size, size_t *out_len);

// HMAC with the hash chosen by algo. out must hold pm_hmac_len(algo) bytes.
// SHA-256 and SHA-512 come from libsodium; SHA-1 is not in libsodium, so it
// is implemented in totp.c (HMAC-SHA1 is still safe: HMAC does not need
// collision resistance, RFC 6234 / RFC 2104).
pm_status pm_hmac(pm_totp_algo algo, const uint8_t *key, size_t key_len,
                  const uint8_t *msg, size_t msg_len, uint8_t *out);
size_t pm_hmac_len(pm_totp_algo algo);

// Parse a stored secret: either plain base32 (defaults: SHA1, 6 digits, 30 s)
// or "otpauth://totp/Label?secret=...&algorithm=SHA256&digits=8&period=60".
// Returns PM_OK, PM_ERR_ARG (unknown parameter value, hotp type, no secret),
// or PM_ERR_TOO_BIG. On failure cfg is wiped. The caller wipes cfg when done.
pm_status pm_totp_parse(const char *text, pm_totp_cfg *cfg);

// RFC 4226 HOTP value for one counter: dynamic truncation, then mod 10^digits.
pm_status pm_hotp(const pm_totp_cfg *cfg, uint64_t counter, uint32_t *code);

// RFC 6238 TOTP value at unix_time (seconds). remaining (may be NULL) gets the
// number of seconds the code is still valid for, 1..period.
pm_status pm_totp_at(const pm_totp_cfg *cfg, int64_t unix_time, uint32_t *code,
                     unsigned *remaining);

// Write code with leading zeros ("007081"). out_size must be > cfg digits.
pm_status pm_totp_format(uint32_t code, unsigned digits, char *out, size_t out_size);

#endif /* PASSMAN_TOTP_H */
