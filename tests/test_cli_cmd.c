// Tests for the CLI commands (src/cli/cli.c) without a real agent, terminal or vault.
//
// The linker replaces (-Wl,--wrap) the functions cli.c calls into other modules:
//   pm_agent_request / pm_agent_list / pm_agent_stop -> a fake agent in memory that
//       answers like src/agent/agent.c (same error texts and status codes, locked/unlocked state)
//   pm_read_password / pm_read_line -> scripted user input
//   pm_cli_spawn_agent, pm_vault_create, time -> recorded / fixed
// So every test checks what the user sees AND what was sent to the agent.

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "passman/agent.h"
#include "passman/cli.h"
#include "passman/error.h"

/* ------------------------------------------------------------------ */
/* fake agent                                                         */
/* ------------------------------------------------------------------ */

#define MAX_RECORDS 8
#define MASTER "correct horse"

static struct {
    int running;
    int unlocked;
    int spawn_calls;
    int put_calls;
    int get_calls;
    int unlock_calls;
    pm_status unlock_error; // PM_OK: check the password; else fail with this status
    int nrec;
    pm_msg_t rec[MAX_RECORDS]; // type unused, the other fields as sent with PUT
} agent;

static pm_msg_t *find(const char *site) {
    for (int i = 0; i < agent.nrec; i++) {
        if (strcmp(agent.rec[i].site, site) == 0) {
            return &agent.rec[i];
        }
    }
    return NULL;
}

static void err_reply(pm_msg_t *resp, pm_status status, const char *text) {
    resp->type = PM_MSG_ERR;
    resp->status = status;
    snprintf(resp->error, sizeof resp->error, "%s", text);
}

int __wrap_pm_agent_request(const char *socket_path, const pm_msg_t *req, pm_msg_t *resp);
int __wrap_pm_agent_request(const char *socket_path, const pm_msg_t *req, pm_msg_t *resp) {
    assert_non_null(socket_path);
    memset(resp, 0, sizeof *resp);
    if (!agent.running) {
        return -1;
    }
    switch (req->type) {
    case PM_MSG_PING:
    case PM_MSG_LOCK:
        if (req->type == PM_MSG_LOCK) agent.unlocked = 0;
        resp->type = PM_MSG_OK;
        return 0;
    case PM_MSG_UNLOCK:
        agent.unlock_calls++;
        if (agent.unlock_error != PM_OK) { // e.g. a damaged vault file
            agent.unlocked = 0;
            err_reply(resp, agent.unlock_error, pm_strerror(agent.unlock_error));
            return 0;
        }
        agent.unlocked = strcmp(req->password, MASTER) == 0;
        if (agent.unlocked) resp->type = PM_MSG_OK;
        else err_reply(resp, PM_ERR_WRONG_PASS, pm_strerror(PM_ERR_WRONG_PASS));
        return 0;
    case PM_MSG_GET: {
        agent.get_calls++;
        if (!agent.unlocked) {
            err_reply(resp, PM_ERR_LOCKED, pm_strerror(PM_ERR_LOCKED));
            return 0;
        }
        pm_msg_t *r = find(req->site);
        if (r == NULL) {
            err_reply(resp, PM_ERR_NOT_FOUND, pm_strerror(PM_ERR_NOT_FOUND));
            return 0;
        }
        *resp = *r;
        resp->type = PM_MSG_OK;
        return 0;
    }
    case PM_MSG_PUT: {
        if (!agent.unlocked) {
            err_reply(resp, PM_ERR_LOCKED, pm_strerror(PM_ERR_LOCKED));
            return 0;
        }
        agent.put_calls++;
        pm_msg_t *r = find(req->site);
        if (r == NULL) {
            assert_true(agent.nrec < MAX_RECORDS);
            r = &agent.rec[agent.nrec++];
        }
        *r = *req;
        resp->type = PM_MSG_OK;
        return 0;
    }
    default:
        err_reply(resp, PM_ERR_ARG, "unknown request");
        return 0;
    }
}

int __wrap_pm_agent_list(const char *socket_path, pm_agent_list_cb cb, void *user_data);
int __wrap_pm_agent_list(const char *socket_path, pm_agent_list_cb cb, void *user_data) {
    (void)socket_path;
    if (!agent.running || !agent.unlocked) {
        return -1;
    }
    for (int i = 0; i < agent.nrec; i++) {
        if (cb(agent.rec[i].site, user_data) != 0) {
            return -1;
        }
    }
    return 0;
}

int __wrap_pm_agent_stop(const char *socket_path);
int __wrap_pm_agent_stop(const char *socket_path) {
    (void)socket_path;
    if (!agent.running) return -1;
    agent.running = 0;
    agent.unlocked = 0;
    return 0;
}

pm_status __wrap_pm_cli_spawn_agent(const char *vault_path, unsigned timeout_sec);
pm_status __wrap_pm_cli_spawn_agent(const char *vault_path, unsigned timeout_sec) {
    assert_non_null(vault_path);
    (void)timeout_sec;
    agent.spawn_calls++;
    agent.running = 1;
    return PM_OK;
}

static int vault_create_calls;
static char vault_create_path[512];
static char vault_create_pw[PM_MAX_SECRET_LEN];

pm_status __wrap_pm_vault_create(const char *path, const char *password, const void *params);
pm_status __wrap_pm_vault_create(const char *path, const char *password, const void *params) {
    assert_null(params); // CLI asks the vault to calibrate Argon2id
    vault_create_calls++;
    snprintf(vault_create_path, sizeof vault_create_path, "%s", path);
    snprintf(vault_create_pw, sizeof vault_create_pw, "%s", password);
    return PM_OK;
}

time_t __wrap_time(time_t *t);
time_t __wrap_time(time_t *t) {
    if (t != NULL) *t = 59;
    return 59; // RFC 6238 first test time
}

/* ------------------------------------------------------------------ */
/* scripted user input                                                */
/* ------------------------------------------------------------------ */

#define INTR "\x03" // stands for Ctrl+C while reading

static const char *input[16];
static int input_n, input_pos;
static int password_reads, line_reads;

static void type_in(int n, ...) {
    va_list ap;
    va_start(ap, n);
    for (int i = 0; i < n; i++) input[i] = va_arg(ap, const char *);
    va_end(ap);
    input_n = n;
    input_pos = 0;
}

static pm_status next_input(char *buf, size_t size) {
    if (input_pos >= input_n) {
        buf[0] = '\0';
        return PM_ERR_EOF;
    }
    const char *s = input[input_pos++];
    if (strcmp(s, INTR) == 0) {
        memset(buf, 0, size);
        return PM_ERR_INTR;
    }
    if (strlen(s) >= size) {
        memset(buf, 0, size);
        return PM_ERR_TOO_BIG;
    }
    strcpy(buf, s);
    return PM_OK;
}

pm_status __wrap_pm_read_password(const char *prompt, char *buf, size_t size);
pm_status __wrap_pm_read_password(const char *prompt, char *buf, size_t size) {
    (void)prompt;
    password_reads++;
    return next_input(buf, size);
}

pm_status __wrap_pm_read_line(const char *prompt, char *buf, size_t size);
pm_status __wrap_pm_read_line(const char *prompt, char *buf, size_t size) {
    (void)prompt;
    line_reads++;
    return next_input(buf, size);
}

/* ------------------------------------------------------------------ */
/* running a command                                                  */
/* ------------------------------------------------------------------ */

static char *out_text, *err_text;
static size_t out_len, err_len;
static char vault_file[64];

static int run(int n, ...) {
    char *argv[16];
    argv[0] = "passman";
    va_list ap;
    va_start(ap, n);
    for (int i = 0; i < n; i++) argv[i + 1] = va_arg(ap, char *);
    va_end(ap);
    argv[n + 1] = NULL;

    free(out_text);
    free(err_text);
    FILE *out = open_memstream(&out_text, &out_len);
    FILE *err = open_memstream(&err_text, &err_len);
    assert_non_null(out);
    assert_non_null(err);
    int rc = pm_cli_run(n + 1, argv, out, err);
    fclose(out);
    fclose(err);
    return rc;
}

static void add_record(const char *site, const char *email, const char *password) {
    pm_msg_t *r = &agent.rec[agent.nrec++];
    memset(r, 0, sizeof *r);
    snprintf(r->site, sizeof r->site, "%s", site);
    snprintf(r->email, sizeof r->email, "%s", email);
    snprintf(r->password, sizeof r->password, "%s", password);
}

static int setup(void **state) {
    (void)state;
    memset(&agent, 0, sizeof agent);
    agent.running = 1;
    agent.unlocked = 1;
    input_n = input_pos = password_reads = line_reads = 0;
    vault_create_calls = 0;
    vault_create_pw[0] = '\0';

    // an existing (empty) file stands in for the vault; the fake agent never opens it
    snprintf(vault_file, sizeof vault_file, "/tmp/pm-cli-test-XXXXXX");
    int fd = mkstemp(vault_file);
    assert_true(fd >= 0);
    close(fd);
    setenv("PASSMAN_VAULT", vault_file, 1);
    setenv("PASSMAN_SOCKET", "/tmp/pm-cli-test.sock", 1); // never connected to
    return 0;
}

static int teardown(void **state) {
    (void)state;
    unlink(vault_file);
    free(out_text);
    free(err_text);
    out_text = err_text = NULL;
    return 0;
}

/* ------------------------------------------------------------------ */
/* tests                                                              */
/* ------------------------------------------------------------------ */

static void get_prints_record(void **state) {
    (void)state;
    add_record("github", "dima@example.com", "hunter2");
    assert_int_equal(run(2, "get", "github"), 0);
    assert_non_null(strstr(out_text, "name:     github\n"));
    assert_non_null(strstr(out_text, "e-mail:   dima@example.com\n"));
    assert_non_null(strstr(out_text, "password: hunter2\n"));
    assert_null(strstr(out_text, "phone")); // empty fields are not shown
}

static void get_password_only_is_script_friendly(void **state) {
    (void)state;
    add_record("github", "dima@example.com", "hunter2");
    assert_int_equal(run(3, "get", "github", "-p"), 0);
    assert_string_equal(out_text, "hunter2\n");
}

static void get_errors(void **state) {
    (void)state;
    assert_int_equal(run(2, "get", "nope"), 1);
    assert_non_null(strstr(err_text, "no such entry"));
    assert_int_equal(out_len, 0);

    agent.unlocked = 0;
    assert_int_equal(run(2, "get", "nope"), 1);
    assert_non_null(strstr(err_text, "vault is locked"));
    assert_non_null(strstr(err_text, "passman unlock"));

    agent.running = 0;
    assert_int_equal(run(2, "get", "nope"), 1);
    assert_non_null(strstr(err_text, "agent is not running"));
}

static void add_sends_all_fields(void **state) {
    (void)state;
    type_in(5, "dima@example.com", "dima", "+380001112233", "s3cret!", "s3cret!");
    assert_int_equal(run(2, "add", "github"), 0);
    assert_int_equal(agent.put_calls, 1);
    pm_msg_t *r = find("github");
    assert_non_null(r);
    assert_string_equal(r->email, "dima@example.com");
    assert_string_equal(r->username, "dima");
    assert_string_equal(r->phone, "+380001112233");
    assert_string_equal(r->password, "s3cret!");
    assert_int_equal(password_reads, 2); // asked twice
}

static void add_password_mismatch_saves_nothing(void **state) {
    (void)state;
    type_in(5, "", "", "", "s3cret!", "s3cret?");
    assert_int_equal(run(2, "add", "github"), 1);
    assert_non_null(strstr(err_text, "do not match"));
    assert_int_equal(agent.put_calls, 0);
}

static void add_ctrl_c_saves_nothing(void **state) {
    (void)state;
    type_in(4, "", "", "", INTR);
    assert_int_equal(run(2, "add", "github"), 1);
    assert_non_null(strstr(err_text, "cancelled"));
    assert_int_equal(agent.put_calls, 0);
    assert_int_equal(password_reads, 1); // not asked again after Ctrl+C
}

static void add_existing_asks_before_replacing(void **state) {
    (void)state;
    add_record("github", "", "old");

    type_in(1, "n");
    assert_int_equal(run(2, "add", "github"), 1);
    assert_int_equal(agent.put_calls, 0);
    assert_string_equal(find("github")->password, "old");

    type_in(6, "y", "", "", "", "new", "new");
    assert_int_equal(run(2, "add", "github"), 0);
    assert_string_equal(find("github")->password, "new");

    line_reads = 0;
    type_in(5, "", "", "", "newer", "newer");
    assert_int_equal(run(3, "add", "github", "-f"), 0); // --force: no question
    assert_string_equal(find("github")->password, "newer");
    assert_int_equal(line_reads, 3);

    // the existence check uses the name list: the old secret is never fetched
    assert_int_equal(agent.get_calls, 0);
}

static void add_generate(void **state) {
    (void)state;
    type_in(3, "", "", "");
    assert_int_equal(run(6, "add", "wifi", "-g", "-l", "24", "--no-symbols"), 0);
    assert_int_equal(password_reads, 0); // nothing to type
    const char *pw = find("wifi")->password;
    assert_int_equal(strlen(pw), 24);
    for (size_t i = 0; i < 24; i++) assert_true(isalnum((unsigned char)pw[i]));
}

static void add_when_locked(void **state) {
    (void)state;
    agent.unlocked = 0;
    assert_int_equal(run(2, "add", "github"), 1);
    assert_non_null(strstr(err_text, "vault is locked"));
    assert_int_equal(line_reads, 0); // fails before asking anything
}

static void unlock_starts_agent_once(void **state) {
    (void)state;
    agent.running = 0;
    agent.unlocked = 0;
    type_in(1, MASTER);
    assert_int_equal(run(3, "unlock", "-t", "60"), 0);
    assert_int_equal(agent.spawn_calls, 1);
    assert_true(agent.unlocked);
    assert_non_null(strstr(err_text, "60 s"));

    // already running: no second agent
    agent.unlocked = 0;
    type_in(1, MASTER);
    assert_int_equal(run(1, "unlock"), 0);
    assert_int_equal(agent.spawn_calls, 1);
    // its timeout is unknown here, so no "locks after 300 s" from the default
    assert_null(strstr(err_text, "locks after"));
}

static void running_agent_refuses_vault_and_timeout(void **state) {
    (void)state;
    agent.unlocked = 0;

    // -t / -v cannot change an agent that already runs: refuse before asking
    // for the master password, so it never goes to an agent with another vault
    assert_int_equal(run(3, "unlock", "-t", "60"), 1);
    assert_non_null(strstr(err_text, "already running"));
    assert_non_null(strstr(err_text, "passman stop"));
    assert_int_equal(run(3, "-v", vault_file, "unlock"), 1);
    assert_int_equal(password_reads, 0);
    assert_int_equal(agent.unlock_calls, 0);

    agent.unlocked = 1;
    assert_int_equal(run(4, "-v", vault_file, "get", "github"), 1);
    assert_int_equal(agent.get_calls, 0);

    // stop does not care which vault it is; afterwards -v and -t work
    assert_int_equal(run(3, "-v", vault_file, "stop"), 0);
    assert_false(agent.running);
    type_in(1, MASTER);
    assert_int_equal(run(5, "-v", vault_file, "unlock", "-t", "60"), 0);
    assert_int_equal(agent.spawn_calls, 1);
    assert_true(agent.unlocked);
    assert_non_null(strstr(err_text, "60 s"));
}

static void unlock_wrong_password(void **state) {
    (void)state;
    agent.unlocked = 0;
    type_in(1, "wrong");
    assert_int_equal(run(1, "unlock"), 1);
    assert_non_null(strstr(err_text, "wrong password"));
    assert_false(agent.unlocked);
}

static void unlock_reports_exact_reason(void **state) {
    (void)state;
    agent.unlocked = 0;
    agent.unlock_error = PM_ERR_CORRUPT;
    type_in(1, MASTER);
    assert_int_equal(run(1, "unlock"), 1);
    // the status from the agent, not a guess between password and file
    assert_non_null(strstr(err_text, pm_strerror(PM_ERR_CORRUPT)));
    assert_null(strstr(err_text, "wrong password"));
    assert_false(agent.unlocked);
}

static void unlock_ctrl_c_sends_nothing(void **state) {
    (void)state;
    agent.unlocked = 0;
    type_in(1, INTR);
    assert_int_equal(run(1, "unlock"), 1);
    assert_int_equal(agent.unlock_calls, 0);
    assert_int_equal(password_reads, 1);
}

static void unlock_without_vault(void **state) {
    (void)state;
    agent.running = 0;
    assert_int_equal(run(3, "-v", "/nonexistent/vault.pmx", "unlock"), 1);
    assert_non_null(strstr(err_text, "passman init"));
    assert_int_equal(agent.spawn_calls, 0);
}

static void lock_and_stop(void **state) {
    (void)state;
    assert_int_equal(run(1, "lock"), 0);
    assert_false(agent.unlocked);
    assert_int_equal(run(1, "stop"), 0);
    assert_false(agent.running);
    assert_int_equal(run(1, "stop"), 0); // stopping a stopped agent is fine
    assert_non_null(strstr(err_text, "not running"));
    assert_int_equal(run(1, "status"), 1);
}

static void totp_add_and_show(void **state) {
    (void)state;
    type_in(1, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"); // "12345678901234567890", RFC 6238 seed
    assert_int_equal(run(3, "totp", "add", "google"), 0);
    pm_msg_t *r = find("totp:google");
    assert_non_null(r);
    assert_string_equal(r->password, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");

    // time() is fixed at 59: RFC 6238 SHA1 code 94287082, 6 digits -> 287082
    assert_int_equal(run(2, "totp", "google"), 0);
    assert_string_equal(out_text, "287082\n");
    assert_non_null(strstr(err_text, "valid for 1 more second\n"));
}

static void totp_add_rejects_bad_secret(void **state) {
    (void)state;
    type_in(1, "this is not base32!");
    assert_int_equal(run(3, "totp", "add", "google"), 1);
    assert_non_null(strstr(err_text, "not a valid TOTP secret"));
    assert_int_equal(agent.put_calls, 0);
}

static void totp_show_missing(void **state) {
    (void)state;
    assert_int_equal(run(2, "totp", "google"), 1);
    assert_non_null(strstr(err_text, "no such entry"));
}

static void list_separates_totp(void **state) {
    (void)state;
    add_record("github", "", "x");
    add_record("totp:github", "", "MZXW6YTB");
    add_record("mail", "", "y");

    assert_int_equal(run(1, "list"), 0);
    assert_string_equal(out_text, "github\nmail\n");
    assert_int_equal(run(2, "totp", "list"), 0);
    assert_string_equal(out_text, "github\n");

    agent.unlocked = 0;
    assert_int_equal(run(1, "list"), 1);
}

static void gen_password(void **state) {
    (void)state;
    assert_int_equal(run(3, "gen", "-l", "40"), 0);
    assert_int_equal(out_len, 41);
    char first[64];
    snprintf(first, sizeof first, "%s", out_text);

    assert_int_equal(run(3, "gen", "-l", "40"), 0);
    assert_string_not_equal(first, out_text); // 40 random characters never repeat in practice

    assert_int_equal(run(2, "gen", "--no-symbols"), 0);
    assert_int_equal(out_len, PM_CLI_DEFAULT_LENGTH + 1);
    for (size_t i = 0; i < PM_CLI_DEFAULT_LENGTH; i++) {
        assert_true(isalnum((unsigned char)out_text[i]));
    }
}

static void init_creates_vault(void **state) {
    (void)state;
    char dir[64], path[128];
    snprintf(dir, sizeof dir, "/tmp/pm-cli-init-XXXXXX");
    assert_non_null(mkdtemp(dir));
    snprintf(path, sizeof path, "%s/a/b/vault.pmx", dir);

    type_in(2, "short", "short");
    assert_int_equal(run(3, "-v", path, "init"), 1);
    assert_non_null(strstr(err_text, "too short"));
    assert_int_equal(vault_create_calls, 0);

    type_in(2, "long enough pw", "long enough PW");
    assert_int_equal(run(3, "-v", path, "init"), 1);
    assert_int_equal(vault_create_calls, 0);

    type_in(2, "long enough pw", "long enough pw");
    assert_int_equal(run(3, "-v", path, "init"), 0);
    assert_int_equal(vault_create_calls, 1);
    assert_string_equal(vault_create_path, path);
    assert_string_equal(vault_create_pw, "long enough pw");

    char sub[128];
    snprintf(sub, sizeof sub, "%s/a/b", dir);
    assert_int_equal(access(sub, W_OK), 0); // parent directories were created

    // refuses to overwrite an existing vault
    assert_int_equal(run(1, "init"), 1); // PASSMAN_VAULT points to an existing file
    assert_non_null(strstr(err_text, "already exists"));

    rmdir(sub);
    snprintf(sub, sizeof sub, "%s/a", dir);
    rmdir(sub);
    rmdir(dir);
}

static void agent_log_next_to_socket(void **state) {
    (void)state;
    char path[256];
    // setup() points PASSMAN_SOCKET at /tmp/pm-cli-test.sock
    assert_int_equal(pm_cli_agent_log_path(path, sizeof path), 0);
    assert_string_equal(path, "/tmp/pm-cli-test.sock.log");

    char tiny[8];
    assert_int_equal(pm_cli_agent_log_path(tiny, sizeof tiny), -1);
}

static void usage_errors_exit_2(void **state) {
    (void)state;
    assert_int_equal(run(1, "frobnicate"), 2);
    assert_non_null(strstr(err_text, "unknown command"));
    assert_int_equal(run(0), 0); // no arguments: help on stdout
    assert_non_null(strstr(out_text, "usage: passman"));
}

int main(void) {
#define T(f) cmocka_unit_test_setup_teardown(f, setup, teardown)
    const struct CMUnitTest tests[] = {
        T(get_prints_record),
        T(get_password_only_is_script_friendly),
        T(get_errors),
        T(add_sends_all_fields),
        T(add_password_mismatch_saves_nothing),
        T(add_ctrl_c_saves_nothing),
        T(add_existing_asks_before_replacing),
        T(add_generate),
        T(add_when_locked),
        T(unlock_starts_agent_once),
        T(running_agent_refuses_vault_and_timeout),
        T(unlock_wrong_password),
        T(unlock_reports_exact_reason),
        T(unlock_ctrl_c_sends_nothing),
        T(unlock_without_vault),
        T(lock_and_stop),
        T(totp_add_and_show),
        T(totp_add_rejects_bad_secret),
        T(totp_show_missing),
        T(list_separates_totp),
        T(gen_password),
        T(init_creates_vault),
        T(agent_log_next_to_socket),
        T(usage_errors_exit_2),
    };
#undef T
    return cmocka_run_group_tests(tests, NULL, NULL);
}
