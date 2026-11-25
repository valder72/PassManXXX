#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>

#include "passman/totp.h"

// Every expected value below comes from an RFC appendix and was re-checked
// with Python's hmac/hashlib/base64 (an implementation independent of ours).

static void cfg_from_ascii(pm_totp_cfg *cfg, const char *key, pm_totp_algo algo,
                           unsigned digits) {
    memset(cfg, 0, sizeof *cfg);
    cfg->key_len = strlen(key);
    memcpy(cfg->key, key, cfg->key_len);
    cfg->algo = algo;
    cfg->digits = digits;
    cfg->period = 30;
}

/* ---------------- base32, RFC 4648 section 10 ---------------- */

static void base32_rfc4648_vectors(void **state) {
    (void)state;
    static const struct {
        const char *enc;
        const char *dec;
    } v[] = {
        {"", ""},           {"MY======", "f"},         {"MZXQ====", "fo"},
        {"MZXW6===", "foo"}, {"MZXW6YQ=", "foob"},      {"MZXW6YTB", "fooba"},
        {"MZXW6YTBOI======", "foobar"},
    };
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
        uint8_t out[16];
        size_t len = 99;
        assert_int_equal(pm_base32_decode(v[i].enc, out, sizeof out, &len), PM_OK);
        assert_int_equal(len, strlen(v[i].dec));
        assert_memory_equal(out, v[i].dec, len);
    }
}

static void base32_is_lenient_with_formatting(void **state) {
    (void)state;
    uint8_t a[16], b[16];
    size_t la = 0, lb = 0;
    // how sites usually show the secret: lower case, groups of four
    assert_int_equal(pm_base32_decode("mzxw 6ytb-oi", a, sizeof a, &la), PM_OK);
    assert_int_equal(pm_base32_decode("MZXW6YTBOI", b, sizeof b, &lb), PM_OK);
    assert_int_equal(la, 6);
    assert_int_equal(lb, 6);
    assert_memory_equal(a, "foobar", 6);
    assert_memory_equal(b, "foobar", 6);
}

static void base32_rejects_bad_input(void **state) {
    (void)state;
    uint8_t out[16];
    size_t len;
    assert_int_equal(pm_base32_decode("MZXW1", out, sizeof out, &len), PM_ERR_ARG); // 1 is not base32
    assert_int_equal(pm_base32_decode("MZ!W", out, sizeof out, &len), PM_ERR_ARG);
    assert_int_equal(pm_base32_decode("MY==MY", out, sizeof out, &len), PM_ERR_ARG); // data after '='
    assert_int_equal(pm_base32_decode(NULL, out, sizeof out, &len), PM_ERR_ARG);

    uint8_t small[3];
    assert_int_equal(pm_base32_decode("MZXW6YTB", small, sizeof small, &len), PM_ERR_TOO_BIG);
    uint8_t zero[3] = {0};
    assert_memory_equal(small, zero, sizeof small); // wiped on failure
}

/* ---------------- HMAC-SHA1, RFC 2202 ---------------- */

static void hmac_sha1_rfc2202(void **state) {
    (void)state;
    uint8_t mac[20];

    // test case 1
    static const uint8_t exp1[20] = {0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b,
                                     0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00};
    uint8_t key1[20];
    memset(key1, 0x0b, sizeof key1);
    assert_int_equal(pm_hmac(PM_TOTP_SHA1, key1, 20, (const uint8_t *)"Hi There", 8, mac), PM_OK);
    assert_memory_equal(mac, exp1, 20);

    // test case 2: key shorter than the block
    static const uint8_t exp2[20] = {0xef, 0xfc, 0xdf, 0x6a, 0xe5, 0xeb, 0x2f, 0xa2, 0xd2, 0x74,
                                     0x16, 0xd5, 0xf1, 0x84, 0xdf, 0x9c, 0x25, 0x9a, 0x7c, 0x79};
    const char *m2 = "what do ya want for nothing?";
    assert_int_equal(
        pm_hmac(PM_TOTP_SHA1, (const uint8_t *)"Jefe", 4, (const uint8_t *)m2, strlen(m2), mac),
        PM_OK);
    assert_memory_equal(mac, exp2, 20);

    // test case 6: 80-byte key, longer than the 64-byte block, must be hashed first
    static const uint8_t exp6[20] = {0xaa, 0x4a, 0xe5, 0xe1, 0x52, 0x72, 0xd0, 0x0e, 0x95, 0x70,
                                     0x56, 0x37, 0xce, 0x8a, 0x3b, 0x55, 0xed, 0x40, 0x21, 0x12};
    uint8_t key6[80];
    memset(key6, 0xaa, sizeof key6);
    const char *m6 = "Test Using Larger Than Block-Size Key - Hash Key First";
    assert_int_equal(pm_hmac(PM_TOTP_SHA1, key6, 80, (const uint8_t *)m6, strlen(m6), mac), PM_OK);
    assert_memory_equal(mac, exp6, 20);
}

/* ---------------- HOTP, RFC 4226 appendix D ---------------- */

static void hotp_rfc4226(void **state) {
    (void)state;
    static const uint32_t expected[10] = {755224, 287082, 359152, 969429, 338314,
                                          254676, 287922, 162583, 399871, 520489};
    pm_totp_cfg cfg;
    cfg_from_ascii(&cfg, "12345678901234567890", PM_TOTP_SHA1, 6);
    for (uint64_t c = 0; c < 10; c++) {
        uint32_t code = 0;
        assert_int_equal(pm_hotp(&cfg, c, &code), PM_OK);
        assert_int_equal(code, expected[c]);
    }
}

/* ---------------- TOTP, RFC 6238 appendix B ---------------- */

static void totp_rfc6238(void **state) {
    (void)state;
    static const int64_t times[6] = {59, 1111111109, 1111111111, 1234567890, 2000000000,
                                     20000000000LL};
    static const struct {
        pm_totp_algo algo;
        const char *seed;
        uint32_t codes[6];
    } v[] = {
        {PM_TOTP_SHA1, "12345678901234567890",
         {94287082, 7081804, 14050471, 89005924, 69279037, 65353130}},
        {PM_TOTP_SHA256, "12345678901234567890123456789012",
         {46119246, 68084774, 67062674, 91819424, 90698825, 77737706}},
        {PM_TOTP_SHA512, "1234567890123456789012345678901234567890123456789012345678901234",
         {90693936, 25091201, 99943326, 93441116, 38618901, 47863826}},
    };
    for (size_t a = 0; a < 3; a++) {
        pm_totp_cfg cfg;
        cfg_from_ascii(&cfg, v[a].seed, v[a].algo, 8);
        for (size_t t = 0; t < 6; t++) {
            uint32_t code = 0;
            assert_int_equal(pm_totp_at(&cfg, times[t], &code, NULL), PM_OK);
            assert_int_equal(code, v[a].codes[t]);
        }
    }
}

static void totp_remaining_and_format(void **state) {
    (void)state;
    pm_totp_cfg cfg;
    cfg_from_ascii(&cfg, "12345678901234567890", PM_TOTP_SHA1, 8);
    uint32_t code;
    unsigned rem = 0;

    assert_int_equal(pm_totp_at(&cfg, 59, &code, &rem), PM_OK);
    assert_int_equal(rem, 1); // 59 is the last second of the window [30, 60)
    assert_int_equal(pm_totp_at(&cfg, 60, &code, &rem), PM_OK);
    assert_int_equal(rem, 30);

    char text[9];
    assert_int_equal(pm_totp_at(&cfg, 1111111109, &code, NULL), PM_OK);
    assert_int_equal(pm_totp_format(code, 8, text, sizeof text), PM_OK);
    assert_string_equal(text, "07081804"); // leading zero kept
    assert_int_equal(pm_totp_format(code, 8, text, 8), PM_ERR_ARG); // no room for '\0'
    assert_int_equal(pm_totp_format(123456789u, 8, text, sizeof text), PM_ERR_ARG);
}

/* ---------------- parsing stored secrets ---------------- */

static void parse_plain_base32_uses_defaults(void **state) {
    (void)state;
    pm_totp_cfg cfg;
    assert_int_equal(pm_totp_parse("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", &cfg), PM_OK);
    assert_int_equal(cfg.key_len, 20);
    assert_memory_equal(cfg.key, "12345678901234567890", 20);
    assert_int_equal(cfg.algo, PM_TOTP_SHA1);
    assert_int_equal(cfg.digits, 6);
    assert_int_equal(cfg.period, 30);

    uint32_t code;
    assert_int_equal(pm_totp_at(&cfg, 59, &code, NULL), PM_OK);
    assert_int_equal(code, 287082); // RFC 6238 SHA1 value 94287082, last 6 digits
}

static void parse_otpauth_uri(void **state) {
    (void)state;
    pm_totp_cfg cfg;
    const char *uri = "otpauth://totp/ACME%20Co:dima@example.com?issuer=ACME%20Co"
                      "&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA"
                      "&algorithm=SHA256&digits=8&period=60";
    assert_int_equal(pm_totp_parse(uri, &cfg), PM_OK);
    assert_int_equal(cfg.algo, PM_TOTP_SHA256);
    assert_int_equal(cfg.digits, 8);
    assert_int_equal(cfg.period, 60);
    assert_int_equal(cfg.key_len, 32);
    assert_memory_equal(cfg.key, "12345678901234567890123456789012", 32);

    // with period 60 the counter at t=118 equals the RFC counter at t=59 (period 30)
    uint32_t code;
    assert_int_equal(pm_totp_at(&cfg, 118, &code, NULL), PM_OK);
    assert_int_equal(code, 46119246);
}

static void parse_rejects_bad_secrets(void **state) {
    (void)state;
    pm_totp_cfg cfg;
    assert_int_equal(pm_totp_parse("", &cfg), PM_ERR_ARG);
    assert_int_equal(pm_totp_parse("hello world!", &cfg), PM_ERR_ARG);
    assert_int_equal(pm_totp_parse("otpauth://hotp/x?secret=MZXW6&counter=1", &cfg), PM_ERR_ARG);
    assert_int_equal(pm_totp_parse("otpauth://totp/x?issuer=nobody", &cfg), PM_ERR_ARG);
    assert_int_equal(pm_totp_parse("otpauth://totp/x?secret=MZXW6&digits=5", &cfg), PM_ERR_ARG);
    assert_int_equal(pm_totp_parse("otpauth://totp/x?secret=MZXW6&digits=9", &cfg), PM_ERR_ARG);
    assert_int_equal(pm_totp_parse("otpauth://totp/x?secret=MZXW6&period=0", &cfg), PM_ERR_ARG);
    assert_int_equal(pm_totp_parse("otpauth://totp/x?secret=MZXW6&algorithm=MD5", &cfg),
                     PM_ERR_ARG);
    assert_int_equal(pm_totp_parse(NULL, &cfg), PM_ERR_ARG);

    // a failed parse leaves no key material behind
    pm_totp_cfg zero;
    memset(&zero, 0, sizeof zero);
    assert_int_equal(pm_totp_parse("otpauth://totp/x?secret=MZXW6YTB&digits=5", &cfg), PM_ERR_ARG);
    assert_memory_equal(&cfg, &zero, sizeof cfg);
}

static void hotp_rejects_bad_cfg(void **state) {
    (void)state;
    pm_totp_cfg cfg;
    uint32_t code;
    cfg_from_ascii(&cfg, "12345678901234567890", PM_TOTP_SHA1, 6);
    cfg.digits = 10;
    assert_int_equal(pm_hotp(&cfg, 0, &code), PM_ERR_ARG);
    cfg.digits = 6;
    cfg.key_len = 0;
    assert_int_equal(pm_hotp(&cfg, 0, &code), PM_ERR_ARG);
    cfg.key_len = 20;
    cfg.period = 0;
    assert_int_equal(pm_totp_at(&cfg, 0, &code, NULL), PM_ERR_ARG);
    cfg.period = 30;
    assert_int_equal(pm_totp_at(&cfg, -1, &code, NULL), PM_ERR_ARG);
    assert_int_equal(pm_hotp(NULL, 0, &code), PM_ERR_ARG);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(base32_rfc4648_vectors),
        cmocka_unit_test(base32_is_lenient_with_formatting),
        cmocka_unit_test(base32_rejects_bad_input),
        cmocka_unit_test(hmac_sha1_rfc2202),
        cmocka_unit_test(hotp_rfc4226),
        cmocka_unit_test(totp_rfc6238),
        cmocka_unit_test(totp_remaining_and_format),
        cmocka_unit_test(parse_plain_base32_uses_defaults),
        cmocka_unit_test(parse_otpauth_uri),
        cmocka_unit_test(parse_rejects_bad_secrets),
        cmocka_unit_test(hotp_rejects_bad_cfg),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
