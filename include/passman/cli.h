#ifndef PASSMAN_CLI_H
#define PASSMAN_CLI_H

#include <stddef.h>
#include <stdio.h>

#include "passman/error.h"

/*
 * CLI: argument parsing and terminal I/O only.
 * It never touches the key material directly, it talks to the agent.
 */

/*
 * Read a password from the terminal without echo (termios).
 * Returns PM_OK on success, or one of PM_ERR_* status codes on failure.
 * Reads directly from file descriptor to avoid stdio buffering.
 * On error, signal interruption or truncation, buf is wiped with pm_wipe.
 *
 * Signal handling note:
 * Signals SIGINT (Ctrl+C), SIGTERM, SIGQUIT, and SIGTSTP (Ctrl+Z)
 * are intercepted while waiting for input. They do NOT terminate or
 * suspend the process inside this function; instead, terminal echo is
 * restored, buf is wiped, and PM_ERR_INTR is returned.
 * The calling CLI code must inspect this return code and abort/exit
 * rather than prompting the user for password again.
 */
pm_status pm_read_password(const char *prompt, char *buf, size_t buf_size);

/*
 * Read one visible line (e-mail, user name, y/n answer) straight from the
 * stdin descriptor. The trailing '\n' (and '\r') is dropped.
 * Returns PM_OK, PM_ERR_ARG, PM_ERR_EOF (end of input before any byte),
 * PM_ERR_TOO_BIG (line does not fit, rest of the line is discarded) or PM_ERR_IO.
 * On failure buf is wiped.
 */
pm_status pm_read_line(const char *prompt, char *buf, size_t buf_size);

/* ---- argument parsing ---- */

typedef enum {
    PM_CMD_NONE = 0,
    PM_CMD_HELP,
    PM_CMD_VERSION,
    PM_CMD_INIT,      /* create a new vault                         */
    PM_CMD_UNLOCK,    /* start the agent if needed, send password   */
    PM_CMD_LOCK,      /* agent forgets the key                      */
    PM_CMD_STOP,      /* agent forgets the key and exits            */
    PM_CMD_STATUS,    /* is the agent running?                      */
    PM_CMD_ADD,       /* add or replace a record                    */
    PM_CMD_GET,       /* print a record                             */
    PM_CMD_LIST,      /* print record names                         */
    PM_CMD_GEN,       /* print a random password, no agent needed   */
    PM_CMD_TOTP_ADD,  /* store a 2FA secret                         */
    PM_CMD_TOTP_SHOW, /* print the current one-time code            */
    PM_CMD_TOTP_LIST  /* print names of stored 2FA secrets          */
} pm_cli_command;

#define PM_CLI_DEFAULT_TIMEOUT 300u  /* agent idle timeout, seconds */
#define PM_CLI_MAX_TIMEOUT 86400u    /* same limit as pm-agentd     */
#define PM_CLI_DEFAULT_LENGTH 20u    /* generated password length   */
#define PM_CLI_MIN_LENGTH 8u
#define PM_CLI_MAX_LENGTH 128u
#define PM_CLI_MIN_MASTER_LEN 8u     /* master password policy      */

/* TOTP secrets are stored as ordinary records under this name prefix, so the
 * agent and vault formats did not have to change. */
#define PM_TOTP_PREFIX "totp:"

typedef struct {
    pm_cli_command cmd;
    const char *vault_path; /* -v/--vault, NULL = default location */
    const char *name;       /* record / totp name, points into argv */
    unsigned timeout_sec;   /* unlock -t/--timeout                  */
    unsigned length;        /* add -g / gen: -l/--length            */
    int generate;           /* add -g/--generate                    */
    int no_symbols;         /* add -g / gen: --no-symbols           */
    int password_only;      /* get -p/--password                    */
    int force;              /* add -f/--force: replace without asking */
} pm_cli_args;

/*
 * Parse argv (argv[0] is the program name) into args. Pure function: no I/O,
 * no global state (unlike getopt), so it is unit-tested directly.
 * Returns PM_OK or PM_ERR_ARG; on PM_ERR_ARG a one-line reason is written to
 * err (if err != NULL).
 */
pm_status pm_cli_parse(int argc, char **argv, pm_cli_args *args, char *err, size_t err_size);

/* Usage text. */
void pm_cli_usage(FILE *out);

/*
 * Run one command. Normal output goes to out, messages and errors to err.
 * Returns the process exit code: 0 success, 1 failure, 2 usage error.
 */
int pm_cli_run(int argc, char **argv, FILE *out, FILE *err);

/* Entry point for main(): hardens the process, then pm_cli_run on stdout/stderr. */
int pm_cli_main(int argc, char **argv);

/*
 * Start pm-agentd in the background for vault_path (internal, exposed so
 * tests can replace it with --wrap). Binary lookup: $PASSMAN_AGENT, then
 * pm-agentd next to the passman executable, then $PATH.
 */
pm_status pm_cli_spawn_agent(const char *vault_path, unsigned timeout_sec);

/*
 * Where a spawned agent writes its stderr: the socket path plus ".log"
 * (usually /run/user/<uid>/passman.sock.log). The file is rewritten on every
 * spawn, so it holds the messages of the last start only.
 * Returns 0 and the path in out, -1 if it does not fit.
 */
int pm_cli_agent_log_path(char *out, size_t out_size);

#endif /* PASSMAN_CLI_H */
