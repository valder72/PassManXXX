#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "passman/cli.h"

int pm_read_password(const char *prompt, char *buf, size_t buf_size) {
    if (buf == NULL || buf_size == 0) {
        return -1;
    }

    /* Print prompt if provided */
    if (prompt != NULL && prompt[0] != '\0') {
        fputs(prompt, stderr);
        fflush(stderr);
    }

    int is_tty = isatty(STDIN_FILENO);
    struct termios old_term, new_term;

    if (is_tty) {
        if (tcgetattr(STDIN_FILENO, &old_term) != 0) {
            return -1;
        }

        new_term = old_term;
        new_term.c_lflag &= ~ECHO;

        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &new_term) != 0) {
            return -1;
        }
    }

    char *res = fgets(buf, (int)buf_size, stdin);

    if (is_tty) {
        /* Always restore terminal attributes */
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_term);
        /* With ECHO disabled, pressing Enter did not print a newline */
        fputc('\n', stderr);
    }

    if (res == NULL) {
        return -1;
    }

    /* Strip trailing newline characters (\n and \r) */
    size_t len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) {
        buf[--len] = '\0';
    }

    return 0;
}

