#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <unistd.h>

#include "passman/cli.h"
#include "passman/error.h"

/* Helper to feed string into stdin via pipe */
static void run_with_input(const char *input, size_t input_len,
                           char *buf, size_t buf_size, pm_status *res) {
    int fds[2];
    assert_int_equal(pipe(fds), 0);

    if (input != NULL && input_len > 0) {
        ssize_t written = write(fds[1], input, input_len);
        assert_int_equal(written, (ssize_t)input_len);
    }
    close(fds[1]);

    int saved_stdin = dup(STDIN_FILENO);
    assert_true(saved_stdin >= 0);

    assert_int_equal(dup2(fds[0], STDIN_FILENO), STDIN_FILENO);
    close(fds[0]);

    *res = pm_read_password(NULL, buf, buf_size);

    assert_int_equal(dup2(saved_stdin, STDIN_FILENO), STDIN_FILENO);
    close(saved_stdin);
}

static void test_read_password_normal(void **state) {
    (void)state;
    char buf[64];
    pm_status res = -999;
    run_with_input("my_secret_pass\n", 15, buf, sizeof(buf), &res);
    assert_int_equal(res, PM_OK);
    assert_string_equal(buf, "my_secret_pass");
}

static void test_read_password_crlf(void **state) {
    (void)state;
    char buf[64];
    pm_status res = -999;
    run_with_input("crlf_pass\r\n", 11, buf, sizeof(buf), &res);
    assert_int_equal(res, PM_OK);
    assert_string_equal(buf, "crlf_pass");
}

static void test_read_password_empty(void **state) {
    (void)state;
    char buf[64];
    pm_status res = -999;
    run_with_input("\n", 1, buf, sizeof(buf), &res);
    assert_int_equal(res, PM_OK);
    assert_string_equal(buf, "");
}

static void test_read_password_truncated(void **state) {
    (void)state;
    char buf[8]; /* capacity is 7 chars + NUL */
    pm_status res = -999;
    run_with_input("1234567890\n", 11, buf, sizeof(buf), &res);
    assert_int_equal(res, PM_ERR_TOO_BIG);
}

static void test_read_password_invalid_args(void **state) {
    (void)state;
    char buf[16];
    assert_int_equal(pm_read_password(NULL, NULL, 16), PM_ERR_ARG);
    assert_int_equal(pm_read_password(NULL, buf, 0), PM_ERR_ARG);
}

static void test_read_password_eof(void **state) {
    (void)state;
    char buf[64];
    pm_status res = -999;
    run_with_input("", 0, buf, sizeof(buf), &res);
    assert_int_equal(res, PM_ERR_EOF);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_read_password_normal),
        cmocka_unit_test(test_read_password_crlf),
        cmocka_unit_test(test_read_password_empty),
        cmocka_unit_test(test_read_password_truncated),
        cmocka_unit_test(test_read_password_invalid_args),
        cmocka_unit_test(test_read_password_eof),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
