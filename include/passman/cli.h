#ifndef PASSMAN_CLI_H
#define PASSMAN_CLI_H

/*
 * CLI: argument parsing and terminal I/O only.
 * It never touches the key material directly, it talks to the agent.
 */

/* Read a password from the terminal without echo (termios). */
int pm_read_password(const char *prompt, char *buf, size_t buf_size);

/* Entry point for all subcommands: vault, get, put, totp, lock, ... */
int pm_cli_main(int argc, char **argv);

#endif /* PASSMAN_CLI_H */
