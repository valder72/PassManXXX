#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cmocka.h>

#include "passman/agent.h"
#include "passman/vault.h"

static char g_mock_name[256];
static char g_mock_secret[PM_MAX_SECRET_LEN];
static int g_mock_has_record = 0;

void __wrap_pm_wipe(void *buf, size_t len) {
    if (buf && len > 0) {
        memset(buf, 0, len);
    }
}

int __wrap_pm_vault_open(const char *path, const char *password, uint8_t key[PM_KEY_BYTES]) {
    (void)path;
    if (!password || strcmp(password, "master123") != 0) {
        return -1;
    }
    memset(key, 0xAB, PM_KEY_BYTES);
    return 0;
}

int __wrap_pm_vault_put(const char *path, const uint8_t key[PM_KEY_BYTES], const char *name,
                        const char *secret) {
    (void)path;
    (void)key;
    if (!name || !secret) {
        return -1;
    }
    snprintf(g_mock_name, sizeof(g_mock_name), "%s", name);
    snprintf(g_mock_secret, sizeof(g_mock_secret), "%s", secret);
    g_mock_has_record = 1;
    return 0;
}

int __wrap_pm_vault_get(const char *path, const uint8_t key[PM_KEY_BYTES], const char *name,
                        char *out, size_t out_size) {
    (void)path;
    (void)key;
    if (!g_mock_has_record || !name || strcmp(name, g_mock_name) != 0) {
        return PM_ERR_NOT_FOUND;
    }
    int n = snprintf(out, out_size, "%s", g_mock_secret);
    return (n >= 0 && (size_t)n < out_size) ? 0 : -1;
}

int __wrap_pm_vault_list(const char *path, const uint8_t key[PM_KEY_BYTES], pm_vault_list_cb cb,
                         void *user_data) {
    (void)path;
    (void)key;
    if (!cb) {
        return -1;
    }
    if (g_mock_has_record && cb(g_mock_name, user_data) != 0) {
        return -1;
    }
    if (cb("gmail", user_data) != 0) {
        return -1;
    }
    return 0;
}

typedef struct {
    char sites[8][PM_IPC_FIELD_LEN];
    size_t count;
} collected_sites_t;

static int collect_site_cb(const char *site, void *user_data) {
    collected_sites_t *col = (collected_sites_t *)user_data;
    if (col->count >= 8) {
        return -1;
    }
    snprintf(col->sites[col->count++], PM_IPC_FIELD_LEN, "%s", site);
    return 0;
}

static int wait_for_socket(const char *sock_path) {
    for (int i = 0; i < 100; i++) {
        if (access(sock_path, F_OK) == 0) {
            return 0;
        }
        usleep(20000);
    }
    return -1;
}

static void test_agent_bad_args(void **state) {
    (void)state;

    char buf[16];
    assert_int_equal(pm_socket_path(NULL, sizeof(buf)), -1);
    assert_int_equal(pm_socket_path(buf, 0), -1);
    assert_int_equal(pm_agent_run(NULL, 10), -1);
    assert_int_equal(pm_agent_run("", 10), -1);
    assert_int_equal(pm_agent_stop(NULL), -1);
    assert_int_equal(pm_agent_stop(""), -1);
    assert_int_equal(pm_agent_stop("/tmp/nonexistent_passman_agent_test.sock"), -1);
}

static void test_agent_full_lifecycle(void **state) {
    (void)state;

    char sock_path[108];
    snprintf(sock_path, sizeof(sock_path), "/tmp/passman_test_%ld.sock", (long)getpid());
    unlink(sock_path);
    assert_int_equal(setenv("PASSMAN_SOCKET", sock_path, 1), 0);

    pid_t pid = fork();
    assert_true(pid >= 0);

    if (pid == 0) {
        int rc = pm_agent_run("/tmp/mock.vault", 1);
        _exit(rc == 0 ? 0 : 1);
    }

    assert_int_equal(wait_for_socket(sock_path), 0);

    struct stat st;
    assert_int_equal(lstat(sock_path, &st), 0);
    assert_true(S_ISSOCK(st.st_mode));
    assert_int_equal(st.st_mode & 0777, 0600);

    pm_msg_t req;
    pm_msg_t resp;

    pm_msg_wipe(&req);
    req.type = PM_MSG_PING;
    assert_int_equal(pm_agent_request(sock_path, &req, &resp), 0);
    assert_int_equal(resp.type, PM_MSG_OK);

    pm_msg_wipe(&req);
    req.type = PM_MSG_GET;
    snprintf(req.site, sizeof(req.site), "%s", "github");
    assert_int_equal(pm_agent_request(sock_path, &req, &resp), 0);
    assert_int_equal(resp.type, PM_MSG_ERR);
    assert_string_equal(resp.error, "vault is locked");

    collected_sites_t col;
    memset(&col, 0, sizeof(col));
    assert_int_equal(pm_agent_list(sock_path, collect_site_cb, &col), -1);
    assert_int_equal(col.count, 0);

    pm_msg_wipe(&req);
    req.type = PM_MSG_UNLOCK;
    snprintf(req.password, sizeof(req.password), "%s", "wrong");
    assert_int_equal(pm_agent_request(sock_path, &req, &resp), 0);
    assert_int_equal(resp.type, PM_MSG_ERR);

    pm_msg_wipe(&req);
    req.type = PM_MSG_UNLOCK;
    snprintf(req.password, sizeof(req.password), "%s", "master123");
    assert_int_equal(pm_agent_request(sock_path, &req, &resp), 0);
    assert_int_equal(resp.type, PM_MSG_OK);

    pm_msg_wipe(&req);
    req.type = PM_MSG_PUT;
    snprintf(req.site, sizeof(req.site), "%s", "github");
    snprintf(req.email, sizeof(req.email), "%s", "dev@example.com");
    snprintf(req.username, sizeof(req.username), "%s", "valder");
    snprintf(req.phone, sizeof(req.phone), "%s", "+380991112233");
    snprintf(req.password, sizeof(req.password), "%s", "s3cr3t");
    assert_int_equal(pm_agent_request(sock_path, &req, &resp), 0);
    assert_int_equal(resp.type, PM_MSG_OK);

    memset(&col, 0, sizeof(col));
    assert_int_equal(pm_agent_list(sock_path, collect_site_cb, &col), 0);
    assert_int_equal(col.count, 2);
    assert_string_equal(col.sites[0], "github");
    assert_string_equal(col.sites[1], "gmail");

    pm_msg_wipe(&req);
    req.type = PM_MSG_GET;
    snprintf(req.site, sizeof(req.site), "%s", "github");
    assert_int_equal(pm_agent_request(sock_path, &req, &resp), 0);
    assert_int_equal(resp.type, PM_MSG_OK);
    assert_string_equal(resp.site, "github");
    assert_string_equal(resp.email, "dev@example.com");
    assert_string_equal(resp.username, "valder");
    assert_string_equal(resp.phone, "+380991112233");
    assert_string_equal(resp.password, "s3cr3t");

    pm_msg_wipe(&req);
    req.type = PM_MSG_PUT;
    snprintf(req.site, sizeof(req.site), "%s", "special");
    snprintf(req.email, sizeof(req.email), "%s", "a\\b@example.com");
    snprintf(req.username, sizeof(req.username), "%s", "user\tname");
    snprintf(req.phone, sizeof(req.phone), "%s", "+380");
    snprintf(req.password, sizeof(req.password), "%s", "line1\nline2\r\n\t\\end");
    assert_int_equal(pm_agent_request(sock_path, &req, &resp), 0);
    assert_int_equal(resp.type, PM_MSG_OK);

    pm_msg_wipe(&req);
    req.type = PM_MSG_GET;
    snprintf(req.site, sizeof(req.site), "%s", "special");
    assert_int_equal(pm_agent_request(sock_path, &req, &resp), 0);
    assert_int_equal(resp.type, PM_MSG_OK);
    assert_string_equal(resp.email, "a\\b@example.com");
    assert_string_equal(resp.username, "user\tname");
    assert_string_equal(resp.phone, "+380");
    assert_string_equal(resp.password, "line1\nline2\r\n\t\\end");

    pm_msg_wipe(&req);
    req.type = PM_MSG_GET;
    snprintf(req.site, sizeof(req.site), "%s", "missing");
    assert_int_equal(pm_agent_request(sock_path, &req, &resp), 0);
    assert_int_equal(resp.type, PM_MSG_ERR);
    assert_string_equal(resp.error, pm_strerror(PM_ERR_NOT_FOUND));

    pm_msg_wipe(&req);
    req.type = PM_MSG_LOCK;
    assert_int_equal(pm_agent_request(sock_path, &req, &resp), 0);
    assert_int_equal(resp.type, PM_MSG_OK);

    pm_msg_wipe(&req);
    req.type = PM_MSG_GET;
    snprintf(req.site, sizeof(req.site), "%s", "github");
    assert_int_equal(pm_agent_request(sock_path, &req, &resp), 0);
    assert_int_equal(resp.type, PM_MSG_ERR);

    pm_msg_wipe(&req);
    req.type = PM_MSG_UNLOCK;
    snprintf(req.password, sizeof(req.password), "%s", "master123");
    assert_int_equal(pm_agent_request(sock_path, &req, &resp), 0);
    assert_int_equal(resp.type, PM_MSG_OK);

    usleep(1200000);

    pm_msg_wipe(&req);
    req.type = PM_MSG_GET;
    snprintf(req.site, sizeof(req.site), "%s", "github");
    assert_int_equal(pm_agent_request(sock_path, &req, &resp), 0);
    assert_int_equal(resp.type, PM_MSG_ERR);
    assert_string_equal(resp.error, "vault is locked");

    assert_int_equal(pm_agent_stop(sock_path), 0);

    int status = 0;
    assert_int_equal(waitpid(pid, &status, 0), pid);
    assert_true(WIFEXITED(status));
    assert_int_equal(WEXITSTATUS(status), 0);
    assert_int_equal(access(sock_path, F_OK), -1);
}

static void test_agent_xdg_and_fallback_socket_path(void **state) {
    (void)state;

    char xdg_dir[96];
    char sock_path[128];
    snprintf(xdg_dir, sizeof(xdg_dir), "/tmp/passman_xdg_%ld", (long)getpid());
    snprintf(sock_path, sizeof(sock_path), "%s/passman.sock", xdg_dir);
    unlink(sock_path);
    rmdir(xdg_dir);
    assert_int_equal(mkdir(xdg_dir, 0700), 0);

    assert_int_equal(unsetenv("PASSMAN_SOCKET"), 0);
    assert_int_equal(setenv("XDG_RUNTIME_DIR", xdg_dir, 1), 0);

    char resolved[128];
    assert_int_equal(pm_socket_path(resolved, sizeof(resolved)), 0);
    assert_string_equal(resolved, sock_path);

    pid_t pid = fork();
    assert_true(pid >= 0);
    if (pid == 0) {
        int rc = pm_agent_run("/tmp/mock.vault", 10);
        _exit(rc == 0 ? 0 : 1);
    }

    assert_int_equal(wait_for_socket(sock_path), 0);

    pm_msg_t req;
    pm_msg_t resp;
    pm_msg_wipe(&req);
    req.type = PM_MSG_PING;
    assert_int_equal(pm_agent_request(sock_path, &req, &resp), 0);
    assert_int_equal(resp.type, PM_MSG_OK);
    assert_int_equal(pm_agent_stop(sock_path), 0);

    int status = 0;
    assert_int_equal(waitpid(pid, &status, 0), pid);
    assert_true(WIFEXITED(status));
    assert_int_equal(WEXITSTATUS(status), 0);
    assert_int_equal(rmdir(xdg_dir), 0);

    char run_dir[64];
    snprintf(run_dir, sizeof(run_dir), "/run/user/%u", (unsigned)getuid());
    if (access(run_dir, W_OK | X_OK) != 0) {
        char fallback_dir[64];
        snprintf(fallback_dir, sizeof(fallback_dir), "/tmp/passman-%u", (unsigned)getuid());
        snprintf(sock_path, sizeof(sock_path), "%s/passman.sock", fallback_dir);
        unlink(sock_path);

        assert_int_equal(unsetenv("XDG_RUNTIME_DIR"), 0);
        pid = fork();
        assert_true(pid >= 0);
        if (pid == 0) {
            int rc = pm_agent_run("/tmp/mock.vault", 10);
            _exit(rc == 0 ? 0 : 1);
        }

        assert_int_equal(wait_for_socket(sock_path), 0);
        struct stat st;
        assert_int_equal(lstat(fallback_dir, &st), 0);
        assert_true(S_ISDIR(st.st_mode));
        assert_int_equal(st.st_mode & 0777, 0700);
        assert_int_equal(pm_agent_stop(sock_path), 0);

        assert_int_equal(waitpid(pid, &status, 0), pid);
        assert_true(WIFEXITED(status));
        assert_int_equal(WEXITSTATUS(status), 0);
        rmdir(fallback_dir);
    }
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_agent_bad_args),
        cmocka_unit_test(test_agent_full_lifecycle),
        cmocka_unit_test(test_agent_xdg_and_fallback_socket_path),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
