#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <time.h>

#include "passman/vault.h"

// weakest parameters the vault accepts so tests are fast
static const pm_kdf_params FAST = {.opslimit = 3, .memlimit = 64 * 1024 * 1024};

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

    char lock[sizeof f->path + sizeof ".lock"];
    snprintf(lock, sizeof lock, "%s.lock", f->path);
    unlink(lock);

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

static void in_dir(const fixture *f, const char *name, char *out, size_t size) {
    snprintf(out, size, "%s/%s", f->dir, name);
}

static double now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1000.0 + (double)t.tv_nsec / 1e6;
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
    assert_int_equal(pm_vault_open(f->path, "weakpass", key), PM_ERR_FORMAT);
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

static void put_through_symlink_updates_real_vault(void **state) {
    fixture *f = *state;
    char link[128];
    in_dir(f, "link.pmx", link, sizeof link);
    assert_int_equal(symlink("v.pmx", link), 0);

    assert_int_equal(pm_vault_put(link, f->key, "github", "one"), PM_OK);

    struct stat st;
    assert_int_equal(lstat(link, &st), 0);
    assert_true(S_ISLNK(st.st_mode));

    char out[16];
    assert_int_equal(pm_vault_get(f->path, f->key, "github", out, sizeof out), PM_OK);
    assert_string_equal(out, "one");

    char lock[128];
    in_dir(f, "link.pmx.lock", lock, sizeof lock);
    assert_int_equal(access(lock, F_OK), -1);

    unlink(link);
}

static void put_waits_for_lock_taken_through_other_path(void **state) {
    fixture *f = *state;
    char link[128], lock[128];
    in_dir(f, "link.pmx", link, sizeof link);
    in_dir(f, "v.pmx.lock", lock, sizeof lock);
    assert_int_equal(symlink("v.pmx", link), 0);

    int ready[2];
    assert_int_equal(pipe(ready), 0);
    pid_t pid = fork();
    assert_true(pid >= 0);
    if (pid == 0) { // another "agent" in the middle of its put
        int lk = open(lock, O_RDWR | O_CREAT, 0600);
        if (lk < 0 || flock(lk, LOCK_EX) != 0) _exit(1);
        if (write(ready[1], "x", 1) != 1) _exit(1);
        struct timespec ts = {0, 300 * 1000000L};
        nanosleep(&ts, NULL);
        _exit(0);
    }
    char c;
    assert_int_equal(read(ready[0], &c, 1), 1);

    double start = now_ms();
    assert_int_equal(pm_vault_put(link, f->key, "github", "two"), PM_OK);
    assert_true(now_ms() - start >= 250.0);

    int status = 0;
    assert_int_equal(waitpid(pid, &status, 0), pid);
    assert_true(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    close(ready[0]);
    close(ready[1]);
    unlink(link);
}

static void open_on_fifo_does_not_hang(void **state) {
    fixture *f = *state;
    char fifo[128];
    in_dir(f, "fifo.pmx", fifo, sizeof fifo);
    assert_int_equal(mkfifo(fifo, 0600), 0);

    uint8_t key[PM_KEY_BYTES];
    assert_int_equal(pm_vault_open(fifo, "weakpass", key), PM_ERR_IO);

    unlink(fifo);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(put_get_replace, setup, teardown),
        cmocka_unit_test_setup_teardown(list_counts_each_name_once, setup, teardown),
        cmocka_unit_test_setup_teardown(wrong_password_and_tampering, setup, teardown),
        cmocka_unit_test_setup_teardown(weak_or_huge_params_in_file_are_refused, setup, teardown),
        cmocka_unit_test_setup_teardown(create_refuses_existing_file_and_is_0600, setup, teardown),
        cmocka_unit_test_setup_teardown(size_limits, setup, teardown),
        cmocka_unit_test_setup_teardown(put_through_symlink_updates_real_vault, setup, teardown),
        cmocka_unit_test_setup_teardown(put_waits_for_lock_taken_through_other_path, setup, teardown),
        cmocka_unit_test_setup_teardown(open_on_fifo_does_not_hang, setup, teardown)

    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
