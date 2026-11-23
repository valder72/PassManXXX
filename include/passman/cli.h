#ifndef PASSMAN_CLI_H
#define PASSMAN_CLI_H

#include <stddef.h>

/*
 * CLI: argument parsing and terminal I/O only.
 * It never touches the key material directly, it talks to the agent.
 */

/* Return codes for pm_read_password and CLI operations */
#define PM_OK               0
#define PM_ERR_INVALID_ARG -1  /* Invalid argument (NULL buffer or size 0) */
#define PM_ERR_IO          -2  /* I/O or terminal setup error */
#define PM_ERR_TRUNCATED   -3  /* Password too long for buffer */
#define PM_ERR_INTR        -4  /* Interrupted by signal (e.g. SIGINT / Ctrl+C) */
#define PM_ERR_EOF         -5  /* Premature EOF */

/* Read a password from the terminal without echo (termios).
 * Returns PM_OK on success, or one of PM_ERR_* on failure.
 * Reads directly from file descriptor to avoid stdio buffering.
 * On error, signal or truncation, buf is wiped.
 */
int pm_read_password(const char *prompt, char *buf, size_t buf_size);

/* Entry point for all subcommands: vault, get, put, totp, lock, ... */
int pm_cli_main(int argc, char **argv);

#endif /* PASSMAN_CLI_H */

