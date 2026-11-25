#include <errno.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cmocka.h>

#include "passman/agent.h"
#include "ipc_internal.h"

void __wrap_pm_wipe(void *buf, size_t len) {
    if (buf && len > 0) {
        memset(buf, 0, len);
    }
}

static void test_msg_wipe(void **state) {
    (void)state;

    pm_msg_wipe(NULL);

    pm_msg_t msg;
    memset(&msg, 0x41, sizeof(msg));
    msg.type = PM_MSG_PUT;
    pm_msg_wipe(&msg);

    assert_int_equal(msg.type, PM_MSG_INVALID);
    assert_int_equal(msg.site[0], '\0');
    assert_int_equal(msg.email[0], '\0');
    assert_int_equal(msg.username[0], '\0');
    assert_int_equal(msg.phone[0], '\0');
    assert_int_equal(msg.password[0], '\0');
    assert_int_equal(msg.error[0], '\0');
}

static void test_encode_decode_simple_commands(void **state) {
    (void)state;

    pm_msg_type types[] = {PM_MSG_PING, PM_MSG_LOCK, PM_MSG_STOP, PM_MSG_LIST, PM_MSG_LIST_END};
    for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
        pm_msg_t in;
        pm_msg_wipe(&in);
        in.type = types[i];

        char buf[PM_IPC_MAX_LINE];
        int len = pm_msg_encode(&in, buf, sizeof(buf));
        assert_int_equal(len, (int)(sizeof(msg_header_t) + 1u));

        pm_msg_t out;
        assert_int_equal(pm_msg_decode(buf, (size_t)len, &out), 0);
        assert_int_equal(out.type, types[i]);
    }
}

static void test_encode_decode_single_field(void **state) {
    (void)state;

    pm_msg_t in;
    pm_msg_wipe(&in);
    in.type = PM_MSG_UNLOCK;
    snprintf(in.password, sizeof(in.password), "%s", "007\tsecret\n!");

    char buf[PM_IPC_MAX_LINE];
    int len = pm_msg_encode(&in, buf, sizeof(buf));
    assert_true(len > 0);

    pm_msg_t out;
    assert_int_equal(pm_msg_decode(buf, (size_t)len, &out), 0);
    assert_int_equal(out.type, PM_MSG_UNLOCK);
    assert_string_equal(out.password, "007\tsecret\n!");

    pm_msg_wipe(&in);
    in.type = PM_MSG_GET;
    snprintf(in.site, sizeof(in.site), "%s", "github");
    len = pm_msg_encode(&in, buf, sizeof(buf));
    assert_true(len > 0);
    assert_int_equal(pm_msg_decode(buf, (size_t)len, &out), 0);
    assert_int_equal(out.type, PM_MSG_GET);
    assert_string_equal(out.site, "github");

    pm_msg_wipe(&in);
    in.type = PM_MSG_ERR;
    in.status = PM_ERR_WRONG_PASS;
    snprintf(in.error, sizeof(in.error), "%s", "wrong password");
    len = pm_msg_encode(&in, buf, sizeof(buf));
    assert_true(len > 0);
    assert_int_equal(pm_msg_decode(buf, (size_t)len, &out), 0);
    assert_int_equal(out.type, PM_MSG_ERR);
    assert_int_equal(out.status, PM_ERR_WRONG_PASS);
    assert_string_equal(out.error, "wrong password");
}

static void test_encode_decode_put_and_ok(void **state) {
    (void)state;

    pm_msg_t in;
    pm_msg_wipe(&in);
    in.type = PM_MSG_PUT;
    snprintf(in.site, sizeof(in.site), "%s", "github");
    snprintf(in.email, sizeof(in.email), "%s", "user@example.com");
    snprintf(in.username, sizeof(in.username), "%s", "volodymyr");
    snprintf(in.phone, sizeof(in.phone), "%s", "+380991112233");
    snprintf(in.password, sizeof(in.password), "%s", "p@ss|w0rd");

    char buf[PM_IPC_MAX_LINE];
    int len = pm_msg_encode(&in, buf, sizeof(buf));
    assert_true(len > 0);

    pm_msg_t out;
    assert_int_equal(pm_msg_decode(buf, (size_t)len, &out), 0);
    assert_int_equal(out.type, PM_MSG_PUT);
    assert_string_equal(out.site, "github");
    assert_string_equal(out.email, "user@example.com");
    assert_string_equal(out.username, "volodymyr");
    assert_string_equal(out.phone, "+380991112233");
    assert_string_equal(out.password, "p@ss|w0rd");
}

static void test_encode_rejects_invalid(void **state) {
    (void)state;

    char buf[PM_IPC_MAX_LINE];
    pm_msg_t msg;
    pm_msg_wipe(&msg);

    assert_int_equal(pm_msg_encode(NULL, buf, sizeof(buf)), -1);
    assert_int_equal(pm_msg_encode(&msg, NULL, sizeof(buf)), -1);
    assert_int_equal(pm_msg_encode(&msg, buf, 2u), -1);

    msg.type = PM_MSG_GET;
    assert_int_equal(pm_msg_encode(&msg, buf, sizeof(buf)), -1);

    msg.type = PM_MSG_UNLOCK;
    assert_int_equal(pm_msg_encode(&msg, buf, sizeof(buf)), -1);

    msg.type = PM_MSG_ERR;
    assert_int_equal(pm_msg_encode(&msg, buf, sizeof(buf)), -1);

    msg.type = PM_MSG_GET;
    snprintf(msg.site, sizeof(msg.site), "%s", "github");
    assert_int_equal(pm_msg_encode(&msg, buf, 5u), -1);
}

static void test_decode_rejects_corrupted(void **state) {
    (void)state;

    pm_msg_t in;
    pm_msg_wipe(&in);
    in.type = PM_MSG_GET;
    snprintf(in.site, sizeof(in.site), "%s", "github");

    char buf[PM_IPC_MAX_LINE];
    int len = pm_msg_encode(&in, buf, sizeof(buf));
    assert_true(len > 0);

    pm_msg_t out;
    assert_int_equal(pm_msg_decode(NULL, (size_t)len, &out), -1);
    assert_int_equal(pm_msg_decode(buf, (size_t)len, NULL), -1);
    assert_int_equal(pm_msg_decode(buf, 2u, &out), -1);
    assert_int_equal(pm_msg_decode(buf, (size_t)(len - 1), &out), -1);

    uint16_t bloated_size = (uint16_t)(len - sizeof(msg_header_t) + 1u);
    memcpy(buf, &bloated_size, sizeof(bloated_size));
    buf[len] = 'x';
    assert_int_equal(pm_msg_decode(buf, (size_t)(len + 1), &out), -1);

    uint16_t zero = 0;
    memcpy(buf, &zero, sizeof(zero));
    assert_int_equal(pm_msg_decode(buf, (size_t)len, &out), -1);

    uint16_t psize = 3u;
    uint16_t bad_field_len = 500u;
    memcpy(buf, &psize, sizeof(psize));
    buf[2] = (char)PM_MSG_GET;
    memcpy(buf + 3, &bad_field_len, sizeof(bad_field_len));
    assert_int_equal(pm_msg_decode(buf, 5u, &out), -1);
    assert_int_equal(out.type, PM_MSG_INVALID);
}

static void test_socketpair_send_recv_msg(void **state) {
    (void)state;

    int sv[2];
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);

    pm_msg_t req;
    pm_msg_wipe(&req);
    req.type = PM_MSG_PUT;
    snprintf(req.site, sizeof(req.site), "%s", "gitlab");
    snprintf(req.username, sizeof(req.username), "%s", "valder");
    snprintf(req.password, sizeof(req.password), "%s", "hunter2");

    assert_int_equal(pm_ipc_send_msg(sv[0], &req), 0);

    pm_msg_t got;
    assert_int_equal(pm_ipc_recv_msg(sv[1], &got), 0);
    assert_int_equal(got.type, PM_MSG_PUT);
    assert_string_equal(got.site, "gitlab");
    assert_string_equal(got.username, "valder");
    assert_string_equal(got.password, "hunter2");

    close(sv[0]);
    close(sv[1]);
}

static void test_slow_client_hits_overall_deadline(void **state) {
    (void)state;

    int sv[2];
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);

    pid_t pid = fork();
    assert_true(pid >= 0);
    if (pid == 0) {
        close(sv[1]);
        uint8_t frame[] = {0x04, 0x00, 'a', 'b', 'c', 'd'};
        for (size_t i = 0; i < sizeof(frame); i++) {
            ssize_t n = send(sv[0], &frame[i], 1, 0);
            if (n <= 0) {
                break;
            }
            usleep(60000);
        }
        close(sv[0]);
        _exit(0);
    }

    close(sv[0]);
    char buf[64];
    uint16_t out_size = 0;
    errno = 0;
    assert_int_equal(pm_ipc_recv_frame_timeout(sv[1], buf, sizeof(buf), &out_size, 150), -1);
    assert_int_equal(errno, ETIMEDOUT);
    close(sv[1]);

    int status = 0;
    assert_int_equal(waitpid(pid, &status, 0), pid);
}

static void test_slow_reader_send_hits_deadline(void **state) {
    (void)state;

    int sv[2];
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);

    int sndbuf = 1024;
    setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    char payload[PM_IPC_MAX_PAYLOAD];
    memset(payload, 'A', sizeof(payload));

    int timed_out = 0;
    for (int i = 0; i < 64; i++) {
        errno = 0;
        if (pm_ipc_send_frame_timeout(sv[0], payload, (uint16_t)sizeof(payload), 100) != 0) {
            if (errno == ETIMEDOUT) {
                timed_out = 1;
            }
            break;
        }
    }
    assert_int_equal(timed_out, 1);

    close(sv[0]);
    close(sv[1]);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_msg_wipe),
        cmocka_unit_test(test_encode_decode_simple_commands),
        cmocka_unit_test(test_encode_decode_single_field),
        cmocka_unit_test(test_encode_decode_put_and_ok),
        cmocka_unit_test(test_encode_rejects_invalid),
        cmocka_unit_test(test_decode_rejects_corrupted),
        cmocka_unit_test(test_socketpair_send_recv_msg),
        cmocka_unit_test(test_slow_client_hits_overall_deadline),
        cmocka_unit_test(test_slow_reader_send_hits_deadline),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
