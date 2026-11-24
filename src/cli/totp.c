#include <ctype.h>
#include <strings.h>
#include <string.h>

#include <sodium.h>

#include "passman/crypto.h"
#include "passman/totp.h"

/* ------------------------------------------------------------------------ */
/* SHA-1 (FIPS 180-4). Only used inside HMAC for TOTP, never for hashing    */
/* passwords or for integrity.                                              */
/* ------------------------------------------------------------------------ */

#define SHA1_BLOCK 64u
#define SHA1_DIGEST 20u

typedef struct {
    uint32_t h[5];
    uint64_t total_len; // bytes hashed so far
    uint8_t block[SHA1_BLOCK];
    size_t block_len;
} sha1_ctx;

static uint32_t rol32(uint32_t x, unsigned n) { return (x << n) | (x >> (32u - n)); }

static void sha1_compress(uint32_t h[5], const uint8_t block[SHA1_BLOCK]) {
    uint32_t w[80];
    for (unsigned i = 0; i < 16; i++) {
        w[i] = (uint32_t)block[4 * i] << 24 | (uint32_t)block[4 * i + 1] << 16 |
               (uint32_t)block[4 * i + 2] << 8 | (uint32_t)block[4 * i + 3];
    }
    for (unsigned i = 16; i < 80; i++) {
        w[i] = rol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
    for (unsigned i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & c) | (~b & d);
            k = 0x5a827999u;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ed9eba1u;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8f1bbcdcu;
        } else {
            f = b ^ c ^ d;
            k = 0xca62c1d6u;
        }
        uint32_t t = rol32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rol32(b, 30);
        b = a;
        a = t;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    pm_wipe(w, sizeof w);
}

static void sha1_init(sha1_ctx *ctx) {
    static const uint32_t iv[5] = {0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u,
                                   0xc3d2e1f0u};
    memcpy(ctx->h, iv, sizeof iv);
    ctx->total_len = 0;
    ctx->block_len = 0;
}

static void sha1_update(sha1_ctx *ctx, const uint8_t *data, size_t len) {
    ctx->total_len += len;
    while (len > 0) {
        size_t take = SHA1_BLOCK - ctx->block_len;
        if (take > len) {
            take = len;
        }
        memcpy(ctx->block + ctx->block_len, data, take);
        ctx->block_len += take;
        data += take;
        len -= take;
        if (ctx->block_len == SHA1_BLOCK) {
            sha1_compress(ctx->h, ctx->block);
            ctx->block_len = 0;
        }
    }
}

static void sha1_final(sha1_ctx *ctx, uint8_t out[SHA1_DIGEST]) {
    uint64_t bits = ctx->total_len * 8u;
    static const uint8_t pad80 = 0x80, zero = 0x00;
    sha1_update(ctx, &pad80, 1);
    while (ctx->block_len != SHA1_BLOCK - 8u) {
        sha1_update(ctx, &zero, 1);
    }
    uint8_t len_be[8];
    for (unsigned i = 0; i < 8; i++) {
        len_be[i] = (uint8_t)(bits >> (56u - 8u * i));
    }
    sha1_update(ctx, len_be, 8);
    for (unsigned i = 0; i < 5; i++) {
        out[4 * i] = (uint8_t)(ctx->h[i] >> 24);
        out[4 * i + 1] = (uint8_t)(ctx->h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(ctx->h[i] >> 8);
        out[4 * i + 3] = (uint8_t)ctx->h[i];
    }
    pm_wipe(ctx, sizeof *ctx);
}

/* RFC 2104: HMAC(K, m) = H((K' ^ opad) || H((K' ^ ipad) || m)) */
static void hmac_sha1(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
                      uint8_t out[SHA1_DIGEST]) {
    uint8_t k[SHA1_BLOCK] = {0};
    sha1_ctx ctx;

    if (key_len > SHA1_BLOCK) { // long keys are hashed first
        sha1_init(&ctx);
        sha1_update(&ctx, key, key_len);
        sha1_final(&ctx, k);
    } else if (key_len > 0) {
        memcpy(k, key, key_len);
    }

    uint8_t pad[SHA1_BLOCK];
    uint8_t inner[SHA1_DIGEST];

    for (unsigned i = 0; i < SHA1_BLOCK; i++) {
        pad[i] = k[i] ^ 0x36u;
    }
    sha1_init(&ctx);
    sha1_update(&ctx, pad, SHA1_BLOCK);
    sha1_update(&ctx, msg, msg_len);
    sha1_final(&ctx, inner);

    for (unsigned i = 0; i < SHA1_BLOCK; i++) {
        pad[i] = k[i] ^ 0x5cu;
    }
    sha1_init(&ctx);
    sha1_update(&ctx, pad, SHA1_BLOCK);
    sha1_update(&ctx, inner, SHA1_DIGEST);
    sha1_final(&ctx, out);

    pm_wipe(k, sizeof k);
    pm_wipe(pad, sizeof pad);
    pm_wipe(inner, sizeof inner);
}

size_t pm_hmac_len(pm_totp_algo algo) {
    switch (algo) {
    case PM_TOTP_SHA1: return SHA1_DIGEST;
    case PM_TOTP_SHA256: return crypto_auth_hmacsha256_BYTES;
    case PM_TOTP_SHA512: return crypto_auth_hmacsha512_BYTES;
    }
    return 0;
}

pm_status pm_hmac(pm_totp_algo algo, const uint8_t *key, size_t key_len, const uint8_t *msg,
                  size_t msg_len, uint8_t *out) {
    if ((key == NULL && key_len > 0) || (msg == NULL && msg_len > 0) || out == NULL) {
        return PM_ERR_ARG;
    }
    switch (algo) {
    case PM_TOTP_SHA1:
        hmac_sha1(key, key_len, msg, msg_len, out);
        return PM_OK;
    case PM_TOTP_SHA256: {
        // the _init/_update/_final API accepts keys of any length, the one-shot one does not
        crypto_auth_hmacsha256_state st;
        crypto_auth_hmacsha256_init(&st, key, key_len);
        crypto_auth_hmacsha256_update(&st, msg, msg_len);
        crypto_auth_hmacsha256_final(&st, out);
        pm_wipe(&st, sizeof st);
        return PM_OK;
    }
    case PM_TOTP_SHA512: {
        crypto_auth_hmacsha512_state st;
        crypto_auth_hmacsha512_init(&st, key, key_len);
        crypto_auth_hmacsha512_update(&st, msg, msg_len);
        crypto_auth_hmacsha512_final(&st, out);
        pm_wipe(&st, sizeof st);
        return PM_OK;
    }
    }
    return PM_ERR_ARG;
}

/* ------------------------------------------------------------------------ */
/* base32, RFC 4648 section 6                                               */
/* ------------------------------------------------------------------------ */

static int base32_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a';
    if (c >= '2' && c <= '7') return c - '2' + 26;
    return -1;
}

pm_status pm_base32_decode(const char *in, uint8_t *out, size_t out_size, size_t *out_len) {
    if (in == NULL || out == NULL || out_len == NULL) {
        return PM_ERR_ARG;
    }
    *out_len = 0;

    uint32_t acc = 0;  // bit accumulator
    unsigned bits = 0; // how many bits of acc are valid
    size_t n = 0;
    int seen_pad = 0;

    for (const char *p = in; *p != '\0'; p++) {
        char c = *p;
        if (c == ' ' || c == '-' || c == '\t') {
            continue;
        }
        if (c == '=') {
            seen_pad = 1;
            continue;
        }
        int v = base32_value(c);
        if (v < 0 || seen_pad) { // data after padding is an error too
            pm_wipe(out, out_size);
            return PM_ERR_ARG;
        }
        acc = (acc << 5) | (uint32_t)v;
        bits += 5;
        if (bits >= 8) {
            if (n >= out_size) {
                pm_wipe(out, out_size);
                acc = 0;
                return PM_ERR_TOO_BIG;
            }
            bits -= 8;
            out[n++] = (uint8_t)(acc >> bits);
            acc &= (1u << bits) - 1u;
        }
    }
    // up to 4 leftover bits are padding bits of the last character, they are dropped
    acc = 0;
    *out_len = n;
    return PM_OK;
}

/* ------------------------------------------------------------------------ */
/* otpauth:// URI (Key Uri Format used by authenticator apps)               */
/* ------------------------------------------------------------------------ */

static int parse_uint(const char *s, size_t len, unsigned long max, unsigned *out) {
    if (len == 0 || len > 9) {
        return -1;
    }
    unsigned long v = 0;
    for (size_t i = 0; i < len; i++) {
        if (!isdigit((unsigned char)s[i])) {
            return -1;
        }
        v = v * 10u + (unsigned long)(s[i] - '0');
    }
    if (v > max) {
        return -1;
    }
    *out = (unsigned)v;
    return 0;
}

static int eq_nocase(const char *s, size_t len, const char *lit) {
    return strlen(lit) == len && strncasecmp(s, lit, len) == 0;
}

static pm_status parse_uri(const char *uri, pm_totp_cfg *cfg) {
    const char *prefix = "otpauth://";
    const char *p = uri + strlen(prefix);

    if (strncasecmp(p, "totp/", 5) != 0) {
        return PM_ERR_ARG; // hotp needs a stored counter, not supported
    }
    const char *query = strchr(p, '?');
    if (query == NULL) {
        return PM_ERR_ARG;
    }
    query++;

    int have_secret = 0;
    while (*query != '\0') {
        const char *amp = strchr(query, '&');
        size_t plen = amp ? (size_t)(amp - query) : strlen(query);
        const char *eq = memchr(query, '=', plen);
        if (eq != NULL) {
            size_t klen = (size_t)(eq - query);
            const char *val = eq + 1;
            size_t vlen = plen - klen - 1;

            if (eq_nocase(query, klen, "secret")) {
                // the secret is base32 and has no characters that need %-escaping;
                // copy it out so it can be NUL-terminated for the decoder
                char tmp[2 * PM_TOTP_MAX_KEY];
                if (vlen >= sizeof tmp) {
                    return PM_ERR_TOO_BIG;
                }
                memcpy(tmp, val, vlen);
                tmp[vlen] = '\0';
                pm_status st = pm_base32_decode(tmp, cfg->key, sizeof cfg->key, &cfg->key_len);
                pm_wipe(tmp, sizeof tmp);
                if (st != PM_OK) {
                    return st;
                }
                have_secret = 1;
            } else if (eq_nocase(query, klen, "algorithm")) {
                if (eq_nocase(val, vlen, "SHA1")) {
                    cfg->algo = PM_TOTP_SHA1;
                } else if (eq_nocase(val, vlen, "SHA256")) {
                    cfg->algo = PM_TOTP_SHA256;
                } else if (eq_nocase(val, vlen, "SHA512")) {
                    cfg->algo = PM_TOTP_SHA512;
                } else {
                    return PM_ERR_ARG;
                }
            } else if (eq_nocase(query, klen, "digits")) {
                if (parse_uint(val, vlen, PM_TOTP_MAX_DIGITS, &cfg->digits) != 0) {
                    return PM_ERR_ARG;
                }
            } else if (eq_nocase(query, klen, "period")) {
                if (parse_uint(val, vlen, PM_TOTP_MAX_PERIOD, &cfg->period) != 0) {
                    return PM_ERR_ARG;
                }
            }
            // issuer, image and other cosmetic parameters are ignored
        }
        query += plen;
        if (*query == '&') {
            query++;
        }
    }
    return have_secret ? PM_OK : PM_ERR_ARG;
}

pm_status pm_totp_parse(const char *text, pm_totp_cfg *cfg) {
    if (text == NULL || cfg == NULL) {
        return PM_ERR_ARG;
    }
    pm_wipe(cfg, sizeof *cfg);
    cfg->algo = PM_TOTP_SHA1;
    cfg->digits = PM_TOTP_DEFAULT_DIGITS;
    cfg->period = PM_TOTP_DEFAULT_PERIOD;

    pm_status st;
    if (strncasecmp(text, "otpauth://", 10) == 0) {
        st = parse_uri(text, cfg);
    } else {
        st = pm_base32_decode(text, cfg->key, sizeof cfg->key, &cfg->key_len);
    }

    // RFC 4226 asks for at least 128 bits of secret, but real services hand out
    // 80-bit ones (16 base32 chars), so only an empty secret is refused
    if (st == PM_OK && (cfg->key_len == 0 || cfg->digits < PM_TOTP_MIN_DIGITS ||
                        cfg->digits > PM_TOTP_MAX_DIGITS || cfg->period == 0)) {
        st = PM_ERR_ARG;
    }
    if (st != PM_OK) {
        pm_wipe(cfg, sizeof *cfg);
    }
    return st;
}

/* ------------------------------------------------------------------------ */
/* HOTP / TOTP                                                              */
/* ------------------------------------------------------------------------ */

static const uint32_t POW10[] = {1u, 10u, 100u, 1000u, 10000u, 100000u, 1000000u, 10000000u,
                                 100000000u};

static int cfg_valid(const pm_totp_cfg *cfg) {
    return cfg != NULL && cfg->key_len > 0 && cfg->key_len <= PM_TOTP_MAX_KEY &&
           cfg->digits >= PM_TOTP_MIN_DIGITS && cfg->digits <= PM_TOTP_MAX_DIGITS &&
           cfg->period > 0 && pm_hmac_len(cfg->algo) != 0;
}

pm_status pm_hotp(const pm_totp_cfg *cfg, uint64_t counter, uint32_t *code) {
    if (!cfg_valid(cfg) || code == NULL) {
        return PM_ERR_ARG;
    }

    uint8_t msg[8]; // counter as 8-byte big-endian
    for (unsigned i = 0; i < 8; i++) {
        msg[i] = (uint8_t)(counter >> (56u - 8u * i));
    }

    uint8_t mac[PM_HMAC_MAX_BYTES];
    size_t mac_len = pm_hmac_len(cfg->algo);
    pm_status st = pm_hmac(cfg->algo, cfg->key, cfg->key_len, msg, sizeof msg, mac);
    if (st != PM_OK) {
        return st;
    }

    // dynamic truncation (RFC 4226 5.3): the low 4 bits of the last byte pick
    // where 4 bytes are taken from; the top bit is masked to avoid sign issues
    unsigned off = mac[mac_len - 1] & 0x0fu;
    uint32_t bin = ((uint32_t)(mac[off] & 0x7fu) << 24) | ((uint32_t)mac[off + 1] << 16) |
                   ((uint32_t)mac[off + 2] << 8) | (uint32_t)mac[off + 3];
    *code = bin % POW10[cfg->digits];

    pm_wipe(mac, sizeof mac);
    bin = 0;
    return PM_OK;
}

pm_status pm_totp_at(const pm_totp_cfg *cfg, int64_t unix_time, uint32_t *code,
                     unsigned *remaining) {
    if (!cfg_valid(cfg) || code == NULL || unix_time < 0) {
        return PM_ERR_ARG;
    }
    uint64_t t = (uint64_t)unix_time;
    uint64_t counter = t / cfg->period; // T0 = 0
    if (remaining != NULL) {
        *remaining = cfg->period - (unsigned)(t % cfg->period);
    }
    return pm_hotp(cfg, counter, code);
}

pm_status pm_totp_format(uint32_t code, unsigned digits, char *out, size_t out_size) {
    if (out == NULL || digits < PM_TOTP_MIN_DIGITS || digits > PM_TOTP_MAX_DIGITS ||
        out_size <= digits || code >= POW10[digits]) {
        return PM_ERR_ARG;
    }
    for (unsigned i = digits; i > 0; i--) {
        out[i - 1] = (char)('0' + code % 10u);
        code /= 10u;
    }
    out[digits] = '\0';
    return PM_OK;
}
