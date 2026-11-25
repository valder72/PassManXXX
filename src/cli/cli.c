#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "passman/agent.h"
#include "passman/cli.h"
#include "passman/crypto.h"
#include "passman/totp.h"
#include "passman/vault.h"

#define EXIT_OK 0
#define EXIT_FAIL 1
#define EXIT_USAGE 2

#define AGENT_START_WAIT_MS 3000
#define AGENT_POLL_MS 50

typedef struct {
    const pm_cli_args *args;
    FILE *out; /* data: records, codes, generated passwords */
    FILE *err; /* everything else */
    char vault[PATH_MAX];
    char sock[sizeof(((struct sockaddr_un *)0)->sun_path)];
} cli_ctx;

static void say(cli_ctx *c, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void say(cli_ctx *c, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fputs("passman: ", c->err);
    vfprintf(c->err, fmt, ap);
    fputc('\n', c->err);
    va_end(ap);
}

/* ------------------------------------------------------------------------ */
/* paths                                                                    */
/* ------------------------------------------------------------------------ */

static int default_vault_path(char *out, size_t size) {
    const char *env = getenv("PASSMAN_VAULT");
    int n;
    if (env != NULL && env[0] != '\0') {
        n = snprintf(out, size, "%s", env);
    } else if ((env = getenv("XDG_DATA_HOME")) != NULL && env[0] == '/') {
        n = snprintf(out, size, "%s/passman/vault.pmx", env);
    } else if ((env = getenv("HOME")) != NULL && env[0] != '\0') {
        n = snprintf(out, size, "%s/.local/share/passman/vault.pmx", env);
    } else {
        return -1;
    }
    return (n > 0 && (size_t)n < size) ? 0 : -1;
}

/* mkdir -p for the directories above path, new ones get mode 0700 */
static int make_parent_dirs(const char *path) {
    char tmp[PATH_MAX];
    int n = snprintf(tmp, sizeof tmp, "%s", path);
    if (n <= 0 || (size_t)n >= sizeof tmp) {
        return -1;
    }
    char *last = strrchr(tmp, '/');
    if (last == NULL || last == tmp) {
        return 0; /* current directory or "/" */
    }
    *last = '\0';
    for (char *p = tmp + 1; ; p++) {
        if (*p == '/' || *p == '\0') {
            char saved = *p;
            *p = '\0';
            if (mkdir(tmp, 0700) != 0 && errno != EEXIST) {
                return -1;
            }
            *p = saved;
            if (saved == '\0') {
                break;
            }
        }
    }
    return 0;
}

/* ------------------------------------------------------------------------ */
/* agent requests                                                           */
/* ------------------------------------------------------------------------ */

static int agent_alive(cli_ctx *c) {
    pm_msg_t req, resp;
    pm_msg_wipe(&req);
    req.type = PM_MSG_PING;
    int ok = pm_agent_request(c->sock, &req, &resp) == 0 && resp.type == PM_MSG_OK;
    pm_msg_wipe(&resp);
    return ok;
}

/* One round trip. Returns 0 when the agent answered PM_MSG_OK; otherwise
 * prints why and returns -1. resp is always filled or wiped. */
static int agent_call(cli_ctx *c, const pm_msg_t *req, pm_msg_t *resp) {
    if (pm_agent_request(c->sock, req, resp) != 0) {
        pm_msg_wipe(resp);
        say(c, "agent is not running, start it with 'passman unlock'");
        return -1;
    }
    if (resp->type == PM_MSG_OK) {
        return 0;
    }
    if (resp->type == PM_MSG_ERR) {
        say(c, "%s", resp->error);
        if (strcmp(resp->error, "vault is locked") == 0) {
            fputs("hint: run 'passman unlock'\n", c->err);
        }
    } else {
        say(c, "unexpected reply from agent");
    }
    pm_msg_wipe(resp);
    return -1;
}

static int set_field(char *dst, size_t dst_size, const char *src) {
    size_t len = strlen(src);
    if (len >= dst_size) {
        return -1;
    }
    memcpy(dst, src, len + 1);
    return 0;
}

/* ------------------------------------------------------------------------ */
/* input helpers                                                            */
/* ------------------------------------------------------------------------ */

static int report_input_error(cli_ctx *c, pm_status st) {
    if (st == PM_ERR_INTR) {
        say(c, "cancelled");
    } else if (st == PM_ERR_TOO_BIG) {
        say(c, "input is too long");
    } else {
        say(c, "cannot read input: %s", pm_strerror(st));
    }
    return EXIT_FAIL;
}

/* Ask for a new secret twice so a typo cannot lock the user out. Both copies
 * are wiped on every path. Returns PM_OK and the password in buf. */
static pm_status read_new_password(cli_ctx *c, const char *what, char *buf, size_t size,
                                   size_t min_len) {
    char again[PM_MAX_SECRET_LEN];
    char prompt[64];
    pm_status st;

    snprintf(prompt, sizeof prompt, "%s: ", what);
    st = pm_read_password(prompt, buf, size);
    if (st != PM_OK) {
        return st;
    }
    if (strlen(buf) < min_len) {
        pm_wipe(buf, size);
        say(c, "too short, at least %zu characters", min_len);
        return PM_ERR_ARG;
    }
    snprintf(prompt, sizeof prompt, "repeat %s: ", what);
    st = pm_read_password(prompt, again, sizeof again < size ? sizeof again : size);
    if (st == PM_OK && strcmp(buf, again) != 0) {
        say(c, "the two entries do not match");
        st = PM_ERR_ARG;
    }
    pm_wipe(again, sizeof again);
    if (st != PM_OK) {
        pm_wipe(buf, size);
    }
    return st;
}

static int confirm(const char *question) {
    char answer[8];
    if (pm_read_line(question, answer, sizeof answer) != PM_OK) {
        return 0;
    }
    return answer[0] == 'y' || answer[0] == 'Y';
}

/* ------------------------------------------------------------------------ */
/* password generator                                                       */
/* ------------------------------------------------------------------------ */

static const char LETTERS_DIGITS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
static const char SYMBOLS[] = "!#$%&()*+,-./:;<=>?@[]^_{|}~";

/* Uniform choice with rejection sampling: a random byte b is used only if
 * b < 256 - (256 % n), otherwise "b % n" would make the first characters of
 * the alphabet slightly more likely (modulo bias). */
static void generate_password(char *out, unsigned length, int no_symbols) {
    char alphabet[sizeof LETTERS_DIGITS + sizeof SYMBOLS];
    size_t n = (size_t)snprintf(alphabet, sizeof alphabet, "%s%s", LETTERS_DIGITS,
                                no_symbols ? "" : SYMBOLS);
    unsigned limit = 256u - (256u % (unsigned)n);

    uint8_t pool[64];
    size_t used = sizeof pool;
    for (unsigned i = 0; i < length;) {
        if (used == sizeof pool) {
            pm_random(pool, sizeof pool);
            used = 0;
        }
        uint8_t b = pool[used++];
        if (b < limit) {
            out[i++] = alphabet[b % n];
        }
    }
    out[length] = '\0';
    pm_wipe(pool, sizeof pool);
}

/* ------------------------------------------------------------------------ */
/* commands                                                                 */
/* ------------------------------------------------------------------------ */

static int cmd_init(cli_ctx *c) {
    if (access(c->vault, F_OK) == 0) {
        say(c, "%s already exists", c->vault);
        return EXIT_FAIL;
    }
    if (make_parent_dirs(c->vault) != 0) {
        say(c, "cannot create directory for %s: %s", c->vault, strerror(errno));
        return EXIT_FAIL;
    }

    char pw[PM_MAX_SECRET_LEN];
    pm_status st = read_new_password(c, "new master password", pw, sizeof pw,
                                     PM_CLI_MIN_MASTER_LEN);
    if (st != PM_OK) {
        return st == PM_ERR_ARG ? EXIT_FAIL : report_input_error(c, st);
    }

    fputs("deriving key, this takes about a second...\n", c->err);
    st = pm_vault_create(c->vault, pw, NULL); /* NULL: calibrate Argon2id on this machine */
    pm_wipe(pw, sizeof pw);
    if (st != PM_OK) {
        say(c, "cannot create vault: %s", pm_strerror(st));
        return EXIT_FAIL;
    }
    fprintf(c->err, "created %s\n", c->vault);
    return EXIT_OK;
}

static int start_agent(cli_ctx *c) {
    pm_status st = pm_cli_spawn_agent(c->vault, c->args->timeout_sec);
    if (st != PM_OK) {
        say(c, "cannot start pm-agentd: %s", pm_strerror(st));
        return -1;
    }
    for (int waited = 0; waited < AGENT_START_WAIT_MS; waited += AGENT_POLL_MS) {
        if (agent_alive(c)) {
            return 0;
        }
        struct timespec ts = {0, AGENT_POLL_MS * 1000000L};
        nanosleep(&ts, NULL);
    }
    say(c, "pm-agentd did not start (is it installed? set PASSMAN_AGENT to its path)");
    return -1;
}

static int cmd_unlock(cli_ctx *c) {
    if (!agent_alive(c)) {
        if (access(c->vault, R_OK) != 0) {
            say(c, "no vault at %s, create one with 'passman init'", c->vault);
            return EXIT_FAIL;
        }
        if (start_agent(c) != 0) {
            return EXIT_FAIL;
        }
    }

    pm_msg_t req, resp;
    pm_msg_wipe(&req);
    req.type = PM_MSG_UNLOCK;
    pm_status st = pm_read_password("master password: ", req.password, sizeof req.password);
    if (st != PM_OK) {
        pm_msg_wipe(&req);
        return report_input_error(c, st);
    }
    if (req.password[0] == '\0') {
        pm_msg_wipe(&req);
        say(c, "empty password");
        return EXIT_FAIL;
    }

    int rc = pm_agent_request(c->sock, &req, &resp);
    pm_msg_wipe(&req);
    if (rc != 0) {
        say(c, "lost connection to the agent");
        return EXIT_FAIL;
    }
    int ok = resp.type == PM_MSG_OK;
    pm_msg_wipe(&resp);
    if (!ok) {
        /* the agent does not tell wrong password and damaged file apart on purpose */
        say(c, "unlock failed: wrong password or damaged vault");
        return EXIT_FAIL;
    }
    if (c->args->timeout_sec == 0) {
        fputs("unlocked\n", c->err);
    } else {
        fprintf(c->err, "unlocked (locks after %u s idle)\n", c->args->timeout_sec);
    }
    return EXIT_OK;
}

static int simple_request(cli_ctx *c, pm_msg_type type, const char *done) {
    if (!agent_alive(c)) {
        fputs("agent is not running\n", c->err);
        return EXIT_OK; /* nothing is unlocked, so lock/stop already hold */
    }
    pm_msg_t req, resp;
    pm_msg_wipe(&req);
    req.type = type;
    int rc = agent_call(c, &req, &resp);
    pm_msg_wipe(&resp);
    if (rc != 0) {
        return EXIT_FAIL;
    }
    fprintf(c->err, "%s\n", done);
    return EXIT_OK;
}

static int cmd_stop(cli_ctx *c) {
    if (!agent_alive(c)) {
        fputs("agent is not running\n", c->err);
        return EXIT_OK;
    }
    if (pm_agent_stop(c->sock) != 0) {
        say(c, "agent did not confirm stop");
        return EXIT_FAIL;
    }
    fputs("agent stopped\n", c->err);
    return EXIT_OK;
}

static int cmd_status(cli_ctx *c) {
    if (agent_alive(c)) {
        fprintf(c->out, "agent running (socket %s)\n", c->sock);
        return EXIT_OK;
    }
    fprintf(c->out, "agent not running\n");
    return EXIT_FAIL; /* non-zero so scripts can test it */
}

typedef struct {
    const char *site;
    int found;
} exists_ctx;

static int exists_cb(const char *site, void *user_data) {
    exists_ctx *e = user_data;
    if (strcmp(site, e->site) == 0) {
        e->found = 1;
    }
    return 0; /* non-zero would make pm_agent_list report a failure */
}

/* Does a record exist? 1 yes, 0 no, -1 agent problem (already reported).
 * Asks for the name list instead of GET, so no secret crosses the socket or
 * lands in CLI memory just to answer yes/no, and no error text is parsed. */
static int record_exists(cli_ctx *c, const char *site) {
    if (!agent_alive(c)) {
        say(c, "agent is not running, start it with 'passman unlock'");
        return -1;
    }
    exists_ctx e = {site, 0};
    if (pm_agent_list(c->sock, exists_cb, &e) != 0) {
        say(c, "cannot read the record list: vault is locked or the agent failed");
        fputs("hint: run 'passman unlock'\n", c->err);
        return -1;
    }
    return e.found;
}

static int send_put(cli_ctx *c, pm_msg_t *req) {
    pm_msg_t resp;
    req->type = PM_MSG_PUT;
    int rc = agent_call(c, req, &resp);
    pm_msg_wipe(req);
    pm_msg_wipe(&resp);
    return rc;
}

static int ask_overwrite(cli_ctx *c, const char *site, const char *shown) {
    if (c->args->force) {
        return 0;
    }
    int exists = record_exists(c, site);
    if (exists < 0) {
        return -1;
    }
    if (exists) {
        char q[300];
        snprintf(q, sizeof q, "'%s' exists, replace it? [y/N] ", shown);
        if (!confirm(q)) {
            fputs("not changed\n", c->err);
            return -1;
        }
    }
    return 0;
}

static int cmd_add(cli_ctx *c) {
    const char *name = c->args->name;
    if (ask_overwrite(c, name, name) != 0) {
        return EXIT_FAIL;
    }

    pm_msg_t req;
    pm_msg_wipe(&req);
    set_field(req.site, sizeof req.site, name);

    /* visible fields, all optional */
    pm_status st = pm_read_line("e-mail (optional): ", req.email, sizeof req.email);
    if (st == PM_OK || st == PM_ERR_EOF) {
        st = pm_read_line("username (optional): ", req.username, sizeof req.username);
    }
    if (st == PM_OK || st == PM_ERR_EOF) {
        st = pm_read_line("phone (optional): ", req.phone, sizeof req.phone);
    }
    if (st != PM_OK && st != PM_ERR_EOF) {
        pm_msg_wipe(&req);
        return report_input_error(c, st);
    }

    if (c->args->generate) {
        generate_password(req.password, c->args->length, c->args->no_symbols);
    } else {
        st = read_new_password(c, "password", req.password, sizeof req.password, 1);
        if (st != PM_OK) {
            pm_msg_wipe(&req);
            return st == PM_ERR_ARG ? EXIT_FAIL : report_input_error(c, st);
        }
    }

    if (send_put(c, &req) != 0) {
        return EXIT_FAIL;
    }
    fprintf(c->err, "saved '%s'%s\n", name,
            c->args->generate ? ", see it with 'passman get'" : "");
    return EXIT_OK;
}

static int cmd_get(cli_ctx *c) {
    pm_msg_t req, resp;
    pm_msg_wipe(&req);
    req.type = PM_MSG_GET;
    set_field(req.site, sizeof req.site, c->args->name);
    if (agent_call(c, &req, &resp) != 0) {
        return EXIT_FAIL;
    }

    if (c->args->password_only) {
        fprintf(c->out, "%s\n", resp.password);
    } else {
        fprintf(c->out, "name:     %s\n", c->args->name);
        if (resp.email[0] != '\0') fprintf(c->out, "e-mail:   %s\n", resp.email);
        if (resp.username[0] != '\0') fprintf(c->out, "username: %s\n", resp.username);
        if (resp.phone[0] != '\0') fprintf(c->out, "phone:    %s\n", resp.phone);
        fprintf(c->out, "password: %s\n", resp.password);
    }
    fflush(c->out);
    pm_msg_wipe(&resp);
    return EXIT_OK;
}

typedef struct {
    FILE *out;
    int totp; /* 1: print only "totp:" names without the prefix, 0: only the others */
    unsigned count;
} list_ctx;

static int list_cb(const char *site, void *user_data) {
    list_ctx *l = user_data;
    size_t plen = sizeof(PM_TOTP_PREFIX) - 1;
    int is_totp = strncmp(site, PM_TOTP_PREFIX, plen) == 0;
    if (is_totp == l->totp) {
        fprintf(l->out, "%s\n", is_totp ? site + plen : site);
        l->count++;
    }
    return 0;
}

static int cmd_list(cli_ctx *c, int totp) {
    if (!agent_alive(c)) {
        say(c, "agent is not running, start it with 'passman unlock'");
        return EXIT_FAIL;
    }
    list_ctx l = {c->out, totp, 0};
    if (pm_agent_list(c->sock, list_cb, &l) != 0) {
        say(c, "cannot list records (is the vault unlocked?)");
        return EXIT_FAIL;
    }
    if (l.count == 0) {
        fputs(totp ? "no TOTP secrets\n" : "no records\n", c->err);
    }
    return EXIT_OK;
}

static int cmd_gen(cli_ctx *c) {
    char pw[PM_CLI_MAX_LENGTH + 1];
    generate_password(pw, c->args->length, c->args->no_symbols);
    fprintf(c->out, "%s\n", pw);
    fflush(c->out);
    pm_wipe(pw, sizeof pw);
    return EXIT_OK;
}

static int totp_record_name(cli_ctx *c, char *out, size_t size) {
    int n = snprintf(out, size, "%s%s", PM_TOTP_PREFIX, c->args->name);
    return (n > 0 && (size_t)n < size) ? 0 : -1;
}

static int cmd_totp_add(cli_ctx *c) {
    char site[PM_IPC_FIELD_LEN];
    if (totp_record_name(c, site, sizeof site) != 0) {
        say(c, "name is too long");
        return EXIT_FAIL;
    }
    if (ask_overwrite(c, site, c->args->name) != 0) {
        return EXIT_FAIL;
    }

    pm_msg_t req;
    pm_msg_wipe(&req);
    set_field(req.site, sizeof req.site, site);
    pm_status st = pm_read_password("secret (base32 or otpauth:// URI): ", req.password,
                                    sizeof req.password);
    if (st != PM_OK) {
        pm_msg_wipe(&req);
        return report_input_error(c, st);
    }

    /* check it now, not on first use: a typo would otherwise be found only
     * when the user is already locked out of the service */
    pm_totp_cfg cfg;
    st = pm_totp_parse(req.password, &cfg);
    pm_wipe(&cfg, sizeof cfg);
    if (st != PM_OK) {
        pm_msg_wipe(&req);
        say(c, "not a valid TOTP secret (base32 or otpauth://totp/... expected)");
        return EXIT_FAIL;
    }

    if (send_put(c, &req) != 0) {
        return EXIT_FAIL;
    }
    fprintf(c->err, "saved TOTP secret '%s', get codes with 'passman totp %s'\n", c->args->name,
            c->args->name);
    return EXIT_OK;
}

static int cmd_totp_show(cli_ctx *c) {
    pm_msg_t req, resp;
    pm_msg_wipe(&req);
    req.type = PM_MSG_GET;
    if (totp_record_name(c, req.site, sizeof req.site) != 0) {
        say(c, "name is too long");
        return EXIT_FAIL;
    }
    if (agent_call(c, &req, &resp) != 0) {
        return EXIT_FAIL;
    }

    pm_totp_cfg cfg;
    pm_status st = pm_totp_parse(resp.password, &cfg);
    pm_msg_wipe(&resp);
    if (st != PM_OK) {
        say(c, "stored TOTP secret is invalid");
        return EXIT_FAIL;
    }

    uint32_t code = 0;
    unsigned remaining = 0;
    char text[PM_TOTP_MAX_DIGITS + 1];
    st = pm_totp_at(&cfg, (int64_t)time(NULL), &code, &remaining);
    if (st == PM_OK) {
        st = pm_totp_format(code, cfg.digits, text, sizeof text);
    }
    pm_wipe(&cfg, sizeof cfg);
    code = 0;
    if (st != PM_OK) {
        say(c, "cannot compute code: %s", pm_strerror(st));
        return EXIT_FAIL;
    }
    fprintf(c->out, "%s\n", text);
    fflush(c->out);
    fprintf(c->err, "valid for %u more second%s\n", remaining, remaining == 1 ? "" : "s");
    pm_wipe(text, sizeof text);
    return EXIT_OK;
}

/* ------------------------------------------------------------------------ */
/* entry points                                                             */
/* ------------------------------------------------------------------------ */

int pm_cli_run(int argc, char **argv, FILE *out, FILE *err) {
    pm_cli_args args;
    char why[160];
    if (pm_cli_parse(argc, argv, &args, why, sizeof why) != PM_OK) {
        fprintf(err, "passman: %s\n(see 'passman help')\n", why);
        return EXIT_USAGE;
    }

    cli_ctx c;
    memset(&c, 0, sizeof c);
    c.args = &args;
    c.out = out;
    c.err = err;

    switch (args.cmd) {
    case PM_CMD_HELP:
        pm_cli_usage(out);
        return EXIT_OK;
    case PM_CMD_VERSION:
        fprintf(out, "passman 0.1.0\n");
        return EXIT_OK;
    default:
        break;
    }

    if (pm_crypto_init() != PM_OK) {
        say(&c, "%s", pm_strerror(PM_ERR_CRYPTO));
        return EXIT_FAIL;
    }
    if (args.cmd == PM_CMD_GEN) {
        return cmd_gen(&c); /* needs neither vault nor agent */
    }

    if (args.vault_path != NULL) {
        int n = snprintf(c.vault, sizeof c.vault, "%s", args.vault_path);
        if (n <= 0 || (size_t)n >= sizeof c.vault) {
            say(&c, "vault path is too long");
            return EXIT_USAGE;
        }
    } else if (default_vault_path(c.vault, sizeof c.vault) != 0) {
        say(&c, "cannot pick a vault location, set PASSMAN_VAULT or use -v");
        return EXIT_USAGE;
    }
    if (args.cmd == PM_CMD_INIT) {
        return cmd_init(&c);
    }
    if (pm_socket_path(c.sock, sizeof c.sock) != 0) {
        say(&c, "cannot find a directory for the agent socket");
        return EXIT_FAIL;
    }

    switch (args.cmd) {
    case PM_CMD_UNLOCK: return cmd_unlock(&c);
    case PM_CMD_LOCK: return simple_request(&c, PM_MSG_LOCK, "locked");
    case PM_CMD_STOP: return cmd_stop(&c);
    case PM_CMD_STATUS: return cmd_status(&c);
    case PM_CMD_ADD: return cmd_add(&c);
    case PM_CMD_GET: return cmd_get(&c);
    case PM_CMD_LIST: return cmd_list(&c, 0);
    case PM_CMD_TOTP_ADD: return cmd_totp_add(&c);
    case PM_CMD_TOTP_SHOW: return cmd_totp_show(&c);
    case PM_CMD_TOTP_LIST: return cmd_list(&c, 1);
    default:
        say(&c, "internal error: unhandled command");
        return EXIT_FAIL;
    }
}

int pm_cli_main(int argc, char **argv) {
    /* a crash must not write a core file with the passwords we handled, and
     * other processes of the same user must not ptrace us to read them */
    struct rlimit no_core = {0, 0};
    (void)setrlimit(RLIMIT_CORE, &no_core);
#ifdef PR_SET_DUMPABLE
    (void)prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif
    return pm_cli_run(argc, argv, stdout, stderr);
}
