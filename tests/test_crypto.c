#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>
#include <string.h>
#include <time.h>

#include "passman/crypto.h"
#include "passman/error.h"

// vectors for subkeys computed with Python hashlib.blake2b, independent of libsodium with this params: subkey i = blake2b(b"", key=master (below), digest_size=32, salt=LE64(i) + 8 zero bytes, person=b"PMXVAULT" + 8 zero bytes)
static const uint8_t MASTER[PM_KEY_BYTES] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
static const uint8_t HEADER[] = {'P','A','S','S','M','A','N','X', 0x01, 0x00, 0x00, 0x00};
static const uint8_t AEAD_KEY[PM_KEY_BYTES] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};

// Sealed record built by hand from an independent implementation: pycryptodome ChaCha20_Poly1305(key=00..1f, nonce=00..17), update(b"github"), encrypt_and_digest(b"hunter2"); result is ct|tag = f6b7610bf5a0bf 8605043ede2623fd25477829fc6b29dd
static const uint8_t KAT_SEALED[] = {
    // nonce
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b, 0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    // ciphertext
    0xf6,0xb7,0x61,0x0b,0xf5,0xa0,0xbf,
    // tag
    0x86,0x05,0x04,0x3e,0xde,0x26,0x23,0xfd,0x25,0x47,0x78,0x29,0xfc,0x6b,0x29,0xdd
};

static void init_is_idempotent(void **state) {
    (void)state;
    assert_int_equal(pm_crypto_init(), PM_OK);
    assert_int_equal(pm_crypto_init(), PM_OK); // two calls are safe
}

static void strerror_never_null(void **state) {
    (void)state;
    for (int st = PM_ERR_EOF; st <= PM_OK; st++) {
        assert_non_null(pm_strerror((pm_status)st));
    }
    assert_string_equal(pm_strerror((pm_status)-67), "unknown error");
}

// Known answer computed with argon2-cffi (reference argon2 library in py): hash_secret_raw(b"helloguysmyname'swelcome67avissylapmmohyla", bytes(range(16)), time_cost=3, memory_cost=65536 KiB, parallelism=1, hash_len=32, type=ID, version=19)
static void kdf_known_answer(void **state) {
    (void)state;
    static const uint8_t expected[PM_KEY_BYTES] = {0x45, 0xce, 0x9b, 0x2d, 0x0b, 0xa7, 0xc7, 0xd7, 0xcb, 0x75, 0x1b, 0x2b, 0xf2, 0x16, 0xbd, 0x63, 0x37, 0xfb, 0x65, 0x59,  0x0d, 0xef, 0x1c, 0xcc, 0xc8, 0x09, 0x7a, 0xb4, 0xe9, 0x1f, 0x03, 0x6d};
    const char *pw = "helloguysmyname'swelcome67avissylapmmohyla";
    uint8_t salt[PM_SALT_BYTES];
    for (int i = 0; i < (int)PM_SALT_BYTES; i++) salt[i] = (uint8_t)i; // ok for test
    pm_kdf_params p = { .opslimit = 3, .memlimit = 65536u * 1024u };   // 64 MB
    uint8_t key[PM_KEY_BYTES];

    assert_int_equal(pm_kdf_derive(pw, strlen(pw), salt, &p, key), PM_OK);
    assert_memory_equal(key, expected, PM_KEY_BYTES);
}

static void kdf_rejects_weak_or_bad_params(void **state) {
    (void)state;
    uint8_t salt[PM_SALT_BYTES] = {0}, key[PM_KEY_BYTES];
    pm_kdf_params weak = {.opslimit = 1, .memlimit = 64u << 20};
    pm_kdf_params tiny = {.opslimit = 3, .memlimit = 1024};

    assert_int_equal(pm_kdf_derive("123", 3, salt, &weak, key), PM_ERR_ARG);
    assert_int_equal(pm_kdf_derive("b", 1, salt, &tiny, key), PM_ERR_ARG);
    assert_int_equal(pm_kdf_derive(NULL, 1, salt, &weak, key), PM_ERR_ARG);
}

static void calibrate_hits_target(void **state) {
    (void)state;
    pm_kdf_params p;
    assert_int_equal(pm_kdf_calibrate(64u << 20, 300, &p), PM_OK);
    assert_true(p.opslimit >= 3);
    assert_int_equal(p.memlimit, 64u << 20);

    // the calibrated parameters really take roughly the target time
    uint8_t salt[PM_SALT_BYTES] = {0}, key[PM_KEY_BYTES];
    struct timespec a, b;
    clock_gettime(CLOCK_MONOTONIC, &a);
    assert_int_equal(pm_kdf_derive("67", 2, salt, &p, key), PM_OK);
    clock_gettime(CLOCK_MONOTONIC, &b);
    double ms = (double)(b.tv_sec - a.tv_sec) * 1000.0 + (double)(b.tv_nsec - a.tv_nsec) / 1e6;
    assert_int_in_range((long)ms, 150, 600);
}

static void wipe_zeroes_and_accepts_null(void **state) {
    (void)state;
    uint8_t buf[64];
    memset(buf, 0xAB, sizeof buf);
    pm_wipe(buf, sizeof buf);

    uint8_t zero[64] = {0};
    assert_memory_equal(buf, zero, sizeof buf);

    pm_wipe(NULL, 0);
    pm_wipe(NULL, 32);
}

static void random_fills_and_differs(void **state) {
    (void)state;
    uint8_t a[PM_KEY_BYTES] = {0}, b[PM_KEY_BYTES] = {0}, zero[PM_KEY_BYTES] = {0};
    pm_random(a, sizeof a);
    pm_random(b, sizeof b);

    assert_memory_not_equal(a, zero, sizeof a);   // every time you run tests there is chance of 32 zero bytes even if program is working correctly,  2^-256
    assert_memory_not_equal(a, b, sizeof a);      // but in practice these tests never fail (if u written code well)

    pm_random(NULL, 16);
    pm_random(a, 0);
}

static void subkeys_known_answer(void **state) {
    (void)state;
    static const uint8_t exp_check[PM_KEY_BYTES] = {0x22,0xdb,0x16,0xa6,0x60,0x48,0x2e,0xc0,0xe5,0xb0,0x49,0x6e,0x29,0x5d,0x1d,0x17,0x99,0x5d,0xf2,0x9f,0xd9,0x8d,0x53,0xeb,0x8f,0xdd,0x9a,0xd1,0x8b,0xb7,0xc0,0xd5};
    static const uint8_t exp_record[PM_KEY_BYTES] = {0x5f,0x39,0xd9,0x65,0x06,0x5d,0xf9,0x1d,0x3f,0x8e,0x44,0xee,0x75,0xb7,0xbd,0xc7,0xb1,0xfc,0x22,0x19,0x42,0x55,0x11,0x1a,0x88,0xf3,0x81,0x44,0x9b,0xc3,0x1e,0x89};
    uint8_t check[PM_KEY_BYTES], record[PM_KEY_BYTES];
    assert_int_equal(pm_derive_subkeys(MASTER, check, record), PM_OK);
    assert_memory_equal(check, exp_check, PM_KEY_BYTES);
    assert_memory_equal(record, exp_record, PM_KEY_BYTES);
}

static void subkeys_reject_aliasing(void **state) {
    (void)state;
    uint8_t key[PM_KEY_BYTES] = {0}, other[PM_KEY_BYTES];
    assert_int_equal(pm_derive_subkeys(key, key, other), PM_ERR_ARG);
    assert_int_equal(pm_derive_subkeys(key, other, other), PM_ERR_ARG);
}

static void key_check_known_answer_and_mismatch(void **state) {
    (void)state;
    static const uint8_t exp_value[PM_CHECK_BYTES] = {0xa0,0x3c,0x0b,0x92,0xca,0xbd,0x4d,0x52,0x8f,0xca,0x84,0xb0,0x52,0xe2,0x88,0x65,0xe0,0xe3,0x8e,0xb2,0x40,0xe5,0x9b,0xc7,0x6c,0xeb,0xd4,0x80,0x32,0xb6,0x5c,0xb0};
    uint8_t check[PM_KEY_BYTES], record[PM_KEY_BYTES], value[PM_CHECK_BYTES];
    assert_int_equal(pm_derive_subkeys(MASTER, check, record), PM_OK);

    assert_int_equal(pm_key_check_compute(check, HEADER, sizeof HEADER, value), PM_OK);
    assert_memory_equal(value, exp_value, PM_CHECK_BYTES);

    // right key, untouched header
    assert_int_equal(pm_key_check_verify(check, HEADER, sizeof HEADER, value), PM_OK);

    // wrong key (as with a wrong password)
    assert_int_equal(pm_key_check_verify(record, HEADER, sizeof HEADER, value), PM_ERR_WRONG_PASS);

    // header tampered with
    uint8_t tampered[sizeof HEADER];
    memcpy(tampered, HEADER, sizeof HEADER);
    tampered[8] ^= 0x01;
    assert_int_equal(pm_key_check_verify(check, tampered, sizeof tampered, value), PM_ERR_WRONG_PASS);
}

static void open_known_answer(void **state) {
    (void)state;
    uint8_t plain[16];
    size_t plain_len = 0;
    assert_int_equal(pm_open(AEAD_KEY, KAT_SEALED, sizeof KAT_SEALED, (const uint8_t *)"github", 6, plain, sizeof plain, &plain_len), PM_OK);
    assert_int_equal(plain_len, 7);
    assert_memory_equal(plain, "hunter2", 7);
}

static void seal_open_round_trip_and_fresh_nonce(void **state) {
    (void)state;
    const uint8_t *msg = (const uint8_t *)"popolni steam pls";
    const uint8_t *ad = (const uint8_t *)"bobrovnik";
    uint8_t s1[PM_SEALED_SIZE(17)], s2[PM_SEALED_SIZE(17)];
    size_t l1 = 0, l2 = 0;
    memset(s1, 0, sizeof s1);
    memset(s2, 0, sizeof s2);

    assert_int_equal(pm_seal(AEAD_KEY, msg, 17, ad, 9, s1, sizeof s1, &l1), PM_OK);
    assert_int_equal(pm_seal(AEAD_KEY, msg, 17, ad, 9, s2, sizeof s2, &l2), PM_OK);
    assert_int_equal(l1, PM_SEALED_SIZE(17));
    assert_memory_not_equal(s1, s2, PM_NONCE_BYTES); // same input, different nonce => different output

    uint8_t plain[17];
    size_t plain_len = 0;
    assert_int_equal(pm_open(AEAD_KEY, s1, l1, ad, 9, plain, sizeof plain, &plain_len), PM_OK);
    assert_int_equal(plain_len, 17);
    assert_memory_equal(plain, msg, 17);
    // not failing thanks god pro encryptor 1337
}

static void open_rejects_tampering(void **state) {
    (void)state;
    uint8_t s[sizeof KAT_SEALED], plain[16];
    size_t plain_len = 0;

    memcpy(s, KAT_SEALED, sizeof s);
    s[PM_NONCE_BYTES] ^= 0x01;
    assert_int_equal(pm_open(AEAD_KEY, s, sizeof s, (const uint8_t *)"github", 6, plain, sizeof plain, &plain_len), PM_ERR_CORRUPT);

    // ad deosn't match
    assert_int_equal(pm_open(AEAD_KEY, KAT_SEALED, sizeof KAT_SEALED, (const uint8_t *)"notgithub   ", 9, plain, sizeof plain, &plain_len), PM_ERR_CORRUPT);

    // key is wrong
    uint8_t other[PM_KEY_BYTES] = {0};
    assert_int_equal(pm_open(other, KAT_SEALED, sizeof KAT_SEALED, (const uint8_t *)"github", 6, plain, sizeof plain, &plain_len), PM_ERR_CORRUPT);
}

static void aead_size_errors(void **state) {
    (void)state;
    uint8_t out[PM_SEALED_SIZE(4)], small[PM_SEALED_SIZE(4) - 1], plain[2];
    size_t len = 0;

    assert_int_equal(pm_seal(AEAD_KEY, (const uint8_t *)"abcd", 4, NULL, 0, small, sizeof small, &len), PM_ERR_TOO_BIG);
    assert_int_equal(pm_seal(AEAD_KEY, (const uint8_t *)"abcd", 4, NULL, 0, out, sizeof out, &len), PM_OK);

    assert_int_equal(pm_open(AEAD_KEY, out, PM_NONCE_BYTES + PM_TAG_BYTES - 1, NULL, 0, plain, sizeof plain, &len), PM_ERR_FORMAT);
    assert_int_equal(pm_open(AEAD_KEY, out, sizeof out, NULL, 0, plain, sizeof plain, &len), PM_ERR_TOO_BIG);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(init_is_idempotent),
        cmocka_unit_test(strerror_never_null),
        cmocka_unit_test(kdf_known_answer),
        cmocka_unit_test(kdf_rejects_weak_or_bad_params),
        cmocka_unit_test(calibrate_hits_target),
        cmocka_unit_test(wipe_zeroes_and_accepts_null),
        cmocka_unit_test(random_fills_and_differs),
        cmocka_unit_test(subkeys_known_answer),
        cmocka_unit_test(subkeys_reject_aliasing),
        cmocka_unit_test(open_known_answer),
        cmocka_unit_test(open_rejects_tampering),
        cmocka_unit_test(seal_open_round_trip_and_fresh_nonce),
        cmocka_unit_test(aead_size_errors),
        cmocka_unit_test(key_check_known_answer_and_mismatch)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}


