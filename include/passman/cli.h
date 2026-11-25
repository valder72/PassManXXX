#ifndef PASSMAN_CLI_H
#define PASSMAN_CLI_H

#include <stddef.h>

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

/* Entry point for all subcommands: vault, get, put, totp, lock, ... */
int pm_cli_main(int argc, char **argv);

#endif /* PASSMAN_CLI_H */
