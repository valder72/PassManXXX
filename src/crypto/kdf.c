#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#include <sodium.h>

#include "passman/crypto.h"
#include "passman/error.h"
#include "internal.h"

// RFC 9106, Argon2id with t=3. We do not go below this, and vaults with weaker parameters are refused to open
#define PM_KDF_MIN_OPS 3u

static pm_status check_params(const pm_kdf_params *p) {
    if (p == NULL) return PM_ERR_ARG;
    if (p->opslimit < PM_KDF_MIN_OPS || p->opslimit > crypto_pwhash_argon2id_OPSLIMIT_MAX) return PM_ERR_ARG;

    // MEMLIMIT_MAX is defined via SIZE_MAX, so this also guarantees that the value fits into size_t
    if (p->memlimit < crypto_pwhash_argon2id_MEMLIMIT_MIN || p->memlimit > crypto_pwhash_argon2id_MEMLIMIT_MAX) return PM_ERR_ARG;

    return PM_OK;
}

pm_status pm_kdf_derive(const char *password, size_t password_len, const uint8_t salt[PM_SALT_BYTES], const pm_kdf_params *params, uint8_t master_key[PM_KEY_BYTES]) {
    if (password == NULL || !salt || !master_key) return PM_ERR_ARG;

    pm_status st = check_params(params);
    if (st != PM_OK) return st;

    if (pm_overlaps(master_key, PM_KEY_BYTES, salt, PM_SALT_BYTES) ||
    pm_overlaps(master_key, PM_KEY_BYTES, password, password_len)) return PM_ERR_ARG;

    // on fail, libsodioum fills masterkey with zero, so we don't need to do much
    if (crypto_pwhash(master_key, PM_KEY_BYTES, password, password_len, salt, params->opslimit, (size_t)params->memlimit, crypto_pwhash_ALG_ARGON2ID13) != 0) return PM_ERR_NOMEM;

    return PM_OK;
}

static double now_seconds(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec/1e9;
}

// one trial derivation with a throwaway password and salt, these values are not secret, so a plain stack buffer is fine. Returns elapsed seconds, or a negative value if the memory could not be allocated
static double time_one_derivation(const pm_kdf_params *p) {
    static const char dummy[] = "calibrationlol";
    uint8_t salt[PM_SALT_BYTES] = {0};
    uint8_t key[PM_KEY_BYTES];

    double t0 = now_seconds();
    if (pm_kdf_derive(dummy, sizeof dummy - 1, salt, p, key) != PM_OK) return -1.0;

    return now_seconds() - t0;
}

pm_status pm_kdf_calibrate(uint64_t memlimit, unsigned int target_ms, pm_kdf_params *out) {
    if (!out || target_ms == 0) return PM_ERR_ARG;

    pm_kdf_params p = {.opslimit = PM_KDF_MIN_OPS, .memlimit = memlimit};
    pm_status st = check_params(&p);
    if (st != PM_OK) return st;

    // two runs, and keep faster one. The first will also pay for mapping memory
    double a = time_one_derivation(&p);
    double b = time_one_derivation(&p);

    if (a < 0 || b < 0) return PM_ERR_NOMEM;

    double elapsed = a < b ? a : b;
    if (elapsed <= 0.0) return PM_ERR_ARG;

    // time scales linearly with number of passes, so scaling is according. We do not go below the minimum. We do not need perfect 1 second, vault creating can't be an hour waiting

    double target = (double)target_ms / 1000.0;
    double ops = (double)PM_KDF_MIN_OPS * target / elapsed;

    if (ops > (double)crypto_pwhash_argon2id_OPSLIMIT_MAX) ops = (double)crypto_pwhash_argon2id_OPSLIMIT_MAX;
    if (ops > (double)PM_KDF_MIN_OPS) p.opslimit = (uint64_t)ops;

    *out = p;
    return PM_OK;
}



