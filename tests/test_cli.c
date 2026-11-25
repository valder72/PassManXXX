#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <pthread.h>
#include <pty.h>
#include <signal.h>
#include <string.h>
#include <termios.h>
#include <time.h>
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

/* ---- terminal path: stdin is the slave side of a pseudo-terminal ---- */

typedef struct {
    int master;
    int slave;
    pthread_t target;   /* thread that sits in pm_read_password */
    int send_sigint;    /* 0: type `input`, 1: send SIGINT instead */
    const char *input;
    int saw_echo_off;   /* ECHO was cleared while the read was waiting */
} tty_helper;

/* pm_read_password switches ECHO off with TCSAFLUSH, which drops anything
 * typed before that moment, so the helper waits for it first. */
static int wait_echo_off(int fd) {
    for (int i = 0; i < 5000; i++) {
        struct termios t;
        if (tcgetattr(fd, &t) == 0 && (t.c_lflag & ECHO) == 0) {
            return 1;
        }
        struct timespec ts = {0, 1000000L};
        nanosleep(&ts, NULL);
    }
    return 0;
}

static void *tty_helper_main(void *arg) {
    tty_helper *h = arg;
    h->saw_echo_off = wait_echo_off(h->slave);
    if (h->send_sigint && h->saw_echo_off) {
        pthread_kill(h->target, SIGINT);
    } else {
        /* on timeout still send a newline so the test fails instead of hanging */
        const char *s = h->saw_echo_off && h->input != NULL ? h->input : "\n";
        ssize_t w = write(h->master, s, strlen(s));
        (void)w;
    }
    return NULL;
}

/* Runs pm_read_password with a pty as stdin. echo_after: ECHO state on return. */
static void run_with_tty(tty_helper *h, char *buf, size_t buf_size, pm_status *res,
                         int *echo_after) {
    assert_int_equal(openpty(&h->master, &h->slave, NULL, NULL, NULL), 0);

    struct termios t;
    assert_int_equal(tcgetattr(h->slave, &t), 0);
    assert_true((t.c_lflag & ECHO) != 0);

    int saved_stdin = dup(STDIN_FILENO);
    assert_true(saved_stdin >= 0);
    assert_int_equal(dup2(h->slave, STDIN_FILENO), STDIN_FILENO);

    h->target = pthread_self();
    pthread_t th;
    assert_int_equal(pthread_create(&th, NULL, tty_helper_main, h), 0);

    *res = pm_read_password(NULL, buf, buf_size);

    assert_int_equal(pthread_join(th, NULL), 0);
    assert_int_equal(tcgetattr(h->slave, &t), 0);
    *echo_after = (t.c_lflag & ECHO) != 0;

    assert_int_equal(dup2(saved_stdin, STDIN_FILENO), STDIN_FILENO);
    close(saved_stdin);
    close(h->slave);
    close(h->master);
}

static void test_read_password_tty(void **state) {
    (void)state;
    char buf[64];
    pm_status res = -999;
    int echo_after = 0;
    tty_helper h = {.send_sigint = 0, .input = "tty_secret\n"};

    run_with_tty(&h, buf, sizeof(buf), &res, &echo_after);

    assert_true(h.saw_echo_off);
    assert_int_equal(res, PM_OK);
    assert_string_equal(buf, "tty_secret");
    assert_true(echo_after);
}

static void test_read_password_tty_sigint(void **state) {
    (void)state;
    char buf[64];
    pm_status res = -999;
    int echo_after = 0;
    tty_helper h = {.send_sigint = 1, .input = NULL};

    run_with_tty(&h, buf, sizeof(buf), &res, &echo_after);

    assert_true(h.saw_echo_off);
    assert_int_equal(res, PM_ERR_INTR);
    assert_true(echo_after); /* terminal restored after Ctrl+C */

    /* the caught signal must not leak into the next call (stdin is a pipe now) */
    run_with_input("after_intr\n", 11, buf, sizeof(buf), &res);
    assert_int_equal(res, PM_OK);
    assert_string_equal(buf, "after_intr");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_read_password_tty),
        cmocka_unit_test(test_read_password_tty_sigint),
        cmocka_unit_test(test_read_password_normal),
        cmocka_unit_test(test_read_password_crlf),
        cmocka_unit_test(test_read_password_empty),
        cmocka_unit_test(test_read_password_truncated),
        cmocka_unit_test(test_read_password_invalid_args),
        cmocka_unit_test(test_read_password_eof),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
