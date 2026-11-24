#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "passman/cli.h"

/* Which options each command accepts. -v/--vault and -h/--help are global. */
enum {
    OPT_TIMEOUT = 1 << 0,
    OPT_LENGTH = 1 << 1,
    OPT_GENERATE = 1 << 2,
    OPT_NO_SYMBOLS = 1 << 3,
    OPT_PASSWORD = 1 << 4,
    OPT_FORCE = 1 << 5,
};

typedef struct {
    const char *word;
    pm_cli_command cmd;
    int needs_name; /* 1: exactly one positional NAME */
    unsigned opts;
} cmd_spec;

static const cmd_spec COMMANDS[] = {
    {"help", PM_CMD_HELP, 0, 0},
    {"version", PM_CMD_VERSION, 0, 0},
    {"init", PM_CMD_INIT, 0, 0},
    {"unlock", PM_CMD_UNLOCK, 0, OPT_TIMEOUT},
    {"lock", PM_CMD_LOCK, 0, 0},
    {"stop", PM_CMD_STOP, 0, 0},
    {"status", PM_CMD_STATUS, 0, 0},
    {"add", PM_CMD_ADD, 1, OPT_GENERATE | OPT_LENGTH | OPT_NO_SYMBOLS | OPT_FORCE},
    {"put", PM_CMD_ADD, 1, OPT_GENERATE | OPT_LENGTH | OPT_NO_SYMBOLS | OPT_FORCE},
    {"get", PM_CMD_GET, 1, OPT_PASSWORD},
    {"list", PM_CMD_LIST, 0, 0},
    {"ls", PM_CMD_LIST, 0, 0},
    {"gen", PM_CMD_GEN, 0, OPT_LENGTH | OPT_NO_SYMBOLS},
};

/* "totp" has its own sub-words; these are the specs after it is resolved */
static const cmd_spec TOTP_ADD = {"totp add", PM_CMD_TOTP_ADD, 1, OPT_FORCE};
static const cmd_spec TOTP_LIST = {"totp list", PM_CMD_TOTP_LIST, 0, 0};
static const cmd_spec TOTP_SHOW = {"totp", PM_CMD_TOTP_SHOW, 1, 0};

#define MAX_POSITIONAL 3

static pm_status fail(char *err, size_t err_size, const char *fmt, ...) {
    if (err != NULL && err_size > 0) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(err, err_size, fmt, ap);
        va_end(ap);
    }
    return PM_ERR_ARG;
}

static int parse_number(const char *s, unsigned long min, unsigned long max, unsigned *out) {
    if (s == NULL || *s == '\0' || *s == '-' || *s == '+') {
        return -1;
    }
    char *end;
    errno = 0;
    unsigned long v = strtoul(s, &end, 10);
    if (*end != '\0' || errno == ERANGE || v < min || v > max) {
        return -1;
    }
    *out = (unsigned)v;
    return 0;
}

/* Record names travel in a fixed IPC field and are shown in a terminal: no
 * control characters (an escape sequence in a name could rewrite the screen). */
static int name_ok(const char *name) {
    size_t len = strlen(name);
    if (len == 0 || len + sizeof(PM_TOTP_PREFIX) > 256u) {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)name[i];
        if (c < 0x20 || c == 0x7f) {
            return 0;
        }
    }
    return 1;
}

pm_status pm_cli_parse(int argc, char **argv, pm_cli_args *args, char *err, size_t err_size) {
    if (args == NULL || argc < 0 || (argc > 0 && argv == NULL)) {
        return fail(err, err_size, "internal error");
    }
    if (err != NULL && err_size > 0) {
        err[0] = '\0';
    }

    memset(args, 0, sizeof *args);
    args->timeout_sec = PM_CLI_DEFAULT_TIMEOUT;
    args->length = PM_CLI_DEFAULT_LENGTH;

    const char *pos[MAX_POSITIONAL];
    int npos = 0;
    unsigned seen = 0; /* OPT_* flags given on the command line */
    int want_help = 0, want_version = 0, opts_done = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];

        if (opts_done || a[0] != '-' || a[1] == '\0') { /* "-" alone is positional */
            if (npos == MAX_POSITIONAL) {
                return fail(err, err_size, "too many arguments: '%s'", a);
            }
            pos[npos++] = a;
            continue;
        }
        if (strcmp(a, "--") == 0) {
            opts_done = 1;
            continue;
        }

        /* split "--name=value" */
        const char *inline_val = NULL;
        char optname[32];
        const char *eq = (a[1] == '-') ? strchr(a, '=') : NULL;
        if (eq != NULL) {
            size_t n = (size_t)(eq - a);
            if (n >= sizeof optname) {
                return fail(err, err_size, "unknown option '%s'", a);
            }
            memcpy(optname, a, n);
            optname[n] = '\0';
            inline_val = eq + 1;
        } else {
            snprintf(optname, sizeof optname, "%s", a);
        }

#define IS(s, l) (strcmp(optname, (s)) == 0 || strcmp(optname, (l)) == 0)
        int takes_value = IS("-v", "--vault") || IS("-t", "--timeout") || IS("-l", "--length");
        const char *val = NULL;
        if (takes_value) {
            if (inline_val != NULL) {
                val = inline_val;
            } else if (i + 1 < argc) {
                val = argv[++i];
            } else {
                return fail(err, err_size, "option '%s' needs a value", optname);
            }
        } else if (inline_val != NULL) {
            return fail(err, err_size, "option '%s' does not take a value", optname);
        }

        if (IS("-h", "--help")) {
            want_help = 1;
        } else if (strcmp(optname, "--version") == 0) {
            want_version = 1;
        } else if (IS("-v", "--vault")) {
            if (val[0] == '\0') {
                return fail(err, err_size, "empty vault path");
            }
            args->vault_path = val;
        } else if (IS("-t", "--timeout")) {
            if (parse_number(val, 0, PM_CLI_MAX_TIMEOUT, &args->timeout_sec) != 0) {
                return fail(err, err_size, "bad timeout '%s' (0..%u seconds, 0 = never)", val,
                            PM_CLI_MAX_TIMEOUT);
            }
            seen |= OPT_TIMEOUT;
        } else if (IS("-l", "--length")) {
            if (parse_number(val, PM_CLI_MIN_LENGTH, PM_CLI_MAX_LENGTH, &args->length) != 0) {
                return fail(err, err_size, "bad length '%s' (%u..%u)", val, PM_CLI_MIN_LENGTH,
                            PM_CLI_MAX_LENGTH);
            }
            seen |= OPT_LENGTH;
        } else if (IS("-g", "--generate")) {
            args->generate = 1;
            seen |= OPT_GENERATE;
        } else if (strcmp(optname, "--no-symbols") == 0) {
            args->no_symbols = 1;
            seen |= OPT_NO_SYMBOLS;
        } else if (IS("-p", "--password")) {
            args->password_only = 1;
            seen |= OPT_PASSWORD;
        } else if (IS("-f", "--force")) {
            args->force = 1;
            seen |= OPT_FORCE;
        } else {
            return fail(err, err_size, "unknown option '%s'", optname);
        }
#undef IS
    }

    if (want_help || (npos == 0 && !want_version)) {
        args->cmd = PM_CMD_HELP;
        return PM_OK;
    }
    if (npos == 0) {
        args->cmd = PM_CMD_VERSION;
        return PM_OK;
    }

    /* resolve the command word */
    const cmd_spec *spec = NULL;
    int first_arg = 1; /* index in pos[] of the first argument after the command */
    if (strcmp(pos[0], "totp") == 0) {
        if (npos >= 2 && strcmp(pos[1], "add") == 0) {
            spec = &TOTP_ADD;
            first_arg = 2;
        } else if (npos >= 2 && (strcmp(pos[1], "list") == 0 || strcmp(pos[1], "ls") == 0)) {
            spec = &TOTP_LIST;
            first_arg = 2;
        } else if (npos >= 2 && strcmp(pos[1], "show") == 0) {
            spec = &TOTP_SHOW; /* "totp show add" reaches a secret named "add" */
            first_arg = 2;
        } else {
            spec = &TOTP_SHOW;
        }
    } else {
        for (size_t c = 0; c < sizeof COMMANDS / sizeof COMMANDS[0]; c++) {
            if (strcmp(pos[0], COMMANDS[c].word) == 0) {
                spec = &COMMANDS[c];
                break;
            }
        }
    }
    if (spec == NULL) {
        return fail(err, err_size, "unknown command '%s'", pos[0]);
    }

    int nargs = npos - first_arg;
    if (spec->needs_name && nargs != 1) {
        return fail(err, err_size, nargs == 0 ? "'%s' needs a NAME" : "'%s' takes one NAME",
                    spec->word);
    }
    if (!spec->needs_name && nargs != 0) {
        return fail(err, err_size, "'%s' takes no arguments", spec->word);
    }
    if (seen & ~spec->opts) {
        return fail(err, err_size, "option not valid for '%s'", spec->word);
    }
    if (spec->cmd == PM_CMD_ADD && (seen & (OPT_LENGTH | OPT_NO_SYMBOLS)) && !args->generate) {
        return fail(err, err_size, "--length/--no-symbols only make sense with --generate");
    }

    if (spec->needs_name) {
        const char *name = pos[first_arg];
        if (!name_ok(name)) {
            return fail(err, err_size, "bad name (empty, too long or has control characters)");
        }
        if (spec->cmd != PM_CMD_TOTP_ADD && spec->cmd != PM_CMD_TOTP_SHOW &&
            strncmp(name, PM_TOTP_PREFIX, sizeof(PM_TOTP_PREFIX) - 1) == 0) {
            return fail(err, err_size, "names starting with '%s' are reserved, use 'totp'",
                        PM_TOTP_PREFIX);
        }
        args->name = name;
    }

    args->cmd = spec->cmd;
    return PM_OK;
}

void pm_cli_usage(FILE *out) {
    fputs("usage: passman [-v VAULT] COMMAND [ARGS]\n"
          "\n"
          "vault and agent:\n"
          "  init                  create a new vault\n"
          "  unlock [-t SECONDS]   start the agent and unlock (idle lock, default 300, 0 = never)\n"
          "  lock                  agent forgets the key\n"
          "  stop                  agent forgets the key and exits\n"
          "  status                is the agent running?\n"
          "\n"
          "records:\n"
          "  add NAME [-f] [-g [-l N] [--no-symbols]]   add or replace (-g: generate password)\n"
          "  get NAME [-p]         show a record (-p: only the password, for scripts)\n"
          "  list                  record names\n"
          "  gen [-l N] [--no-symbols]                  print a random password\n"
          "\n"
          "two-factor codes (TOTP, RFC 6238):\n"
          "  totp add NAME [-f]    store a base32 secret or otpauth:// URI\n"
          "  totp NAME             print the current code\n"
          "  totp list             names of stored secrets\n"
          "\n"
          "VAULT defaults to $PASSMAN_VAULT, then $XDG_DATA_HOME/passman/vault.pmx,\n"
          "then ~/.local/share/passman/vault.pmx\n",
          out);
}
