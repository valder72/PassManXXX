#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "passman/vault.h"

// weakest parameters the vault accepts so tests are fast
static const pm_kdf_params FAST = {.opslimit = 3, .memlimit = 8192};

typedef struct {
    char dir[64];
    char path[96];
    uint8_t key[PM_KEY_BYTES];
} fixture;

static int setup(void **state) {
    fixture *f = calloc(1, sizeof *f);
    if (!f || pm_crypto_init() != PM_OK) return -1;
    strcpy(f->dir, "/tmp/pm-vault-test-XXXXXX");
    if (!mkdtemp(f->dir)) return -1;
    snprintf(f->path, sizeof f->path, "%s/v.pmx", f->dir);
    if (pm_vault_create(f->path, "weakpass", &FAST) != PM_OK) return -1;
    if (pm_vault_open(f->path, "weakpass", f->key) != PM_OK) return -1;
    *state = f;
    return 0;
}

static int teardown(void **state) {
    fixture *f = *state;
    unlink(f->path);
    rmdir(f->dir);
    free(f);
    return 0;
}

static void flip_byte(const char *path, long offset) {
    FILE *fp = fopen(path, "r+b");
    assert_non_null(fp);
    assert_int_equal(fseek(fp, offset, SEEK_SET), 0);
    int c = fgetc(fp);
    assert_int_equal(fseek(fp, offset, SEEK_SET), 0);
    fputc(c ^ 0x01, fp);
    fclose(fp);
}

static void put_get_replace(void **state) {
    fixture *f = *state;
    char out[PM_MAX_SECRET_LEN];

    assert_int_equal(pm_vault_put(f->path, f->key, "github", "one"), PM_OK);
    assert_int_equal(pm_vault_put(f->path, f->key, "distedu", "two"), PM_OK);
    assert_int_equal(pm_vault_put(f->path, f->key, "github", "three"), PM_OK);

    assert_int_equal(pm_vault_get(f->path, f->key, "github", out, sizeof out), PM_OK);
    assert_string_equal(out, "three");
    assert_int_equal(pm_vault_get(f->path, f->key, "distedu", out, sizeof out), PM_OK);
    assert_string_equal(out, "two");
    assert_int_equal(pm_vault_get(f->path, f->key, "steam", out, sizeof out), PM_ERR_NOT_FOUND);
}

static int count_cb(const char *name, void *user_data) {
    (void)name;
    (*(int *)user_data)++;
    return 0;
}

static void list_counts_each_name_once(void **state) {
    fixture *f = *state;
    int n = 0;
    assert_int_equal(pm_vault_list(f->path, f->key, count_cb, &n), PM_OK);
    assert_int_equal(n, 0);

    assert_int_equal(pm_vault_put(f->path, f->key, "a", "1"), PM_OK);
    assert_int_equal(pm_vault_put(f->path, f->key, "b", "2"), PM_OK);
    assert_int_equal(pm_vault_put(f->path, f->key, "a", "3"), PM_OK);
    n = 0;
    assert_int_equal(pm_vault_list(f->path, f->key, count_cb, &n), PM_OK);
    assert_int_equal(n, 2);
}

static void wrong_password_and_tampering(void **state) {
    fixture *f = *state;
    uint8_t key[PM_KEY_BYTES];
    assert_int_equal(pm_vault_put(f->path, f->key, "github", "secret"), PM_OK);

    assert_int_equal(pm_vault_open(f->path, "strongpass", key), PM_ERR_WRONG_PASS);

    flip_byte(f->path, 100);
    assert_int_equal(pm_vault_open(f->path, "weakpass", key), PM_ERR_CORRUPT);
    flip_byte(f->path, 100);
    assert_int_equal(pm_vault_open(f->path, "weakpass", key), PM_OK);

    flip_byte(f->path, 0);
    assert_int_equal(pm_vault_open(f->path, "weakpass", key), PM_ERR_FORMAT);
}

static void weak_or_huge_params_in_file_are_refused(void **state) {
    fixture *f = *state;
    uint8_t key[PM_KEY_BYTES];
    flip_byte(f->path, 12);                    // opslimit from 3 to 2
    assert_int_equal(pm_vault_open(f->path, "weakpass", key), PM_ERR_FORMAT);
    flip_byte(f->path, 12);

    flip_byte(f->path, 27);                    // top byte of memlimit
    assert_int_equal(pm_vault_open(f->path, "weakpas", key), PM_ERR_FORMAT);
}

static void create_refuses_existing_file_and_is_0600(void **state) {
    fixture *f = *state;
    struct stat st;
    assert_int_equal(stat(f->path, &st), 0);
    assert_int_equal(st.st_mode & 0777, 0600);
    assert_int_equal(pm_vault_create(f->path, "whatever", &FAST), PM_ERR_IO);
}

static void size_limits(void **state) {
    fixture *f = *state;
    char big[PM_MAX_SECRET_LEN + 1];
    memset(big, 'x', sizeof big - 1);
    big[sizeof big - 1] = '\0';
    assert_int_equal(pm_vault_put(f->path, f->key, "github", big), PM_ERR_TOO_BIG);
    assert_int_equal(pm_vault_put(f->path, f->key, "", "hacker"), PM_ERR_ARG);
    char small[4];
    (void)small;
    assert_int_equal(pm_vault_put(f->path, f->key, "github", "four"), PM_OK);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(put_get_replace, setup, teardown),
        cmocka_unit_test_setup_teardown(list_counts_each_name_once, setup, teardown),
        cmocka_unit_test_setup_teardown(wrong_password_and_tampering, setup, teardown),
        cmocka_unit_test_setup_teardown(weak_or_huge_params_in_file_are_refused, setup, teardown),
        cmocka_unit_test_setup_teardown(create_refuses_existing_file_and_is_0600, setup, teardown),
        cmocka_unit_test_setup_teardown(size_limits, setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
