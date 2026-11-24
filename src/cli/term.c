#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <string.h>
#include <sys/select.h>
#include <termios.h>
#include <unistd.h>

#include "passman/cli.h"
#include "passman/crypto.h"
#include "passman/error.h"

static const int s_signals[] = {SIGINT, SIGTERM, SIGQUIT, SIGTSTP};
#define NUM_SIGNALS (sizeof(s_signals) / sizeof(s_signals[0]))

static volatile sig_atomic_t g_caught_sig = 0;
static volatile sig_atomic_t g_tty_fd = -1;
static struct termios g_old_term;
static volatile sig_atomic_t g_term_modified = 0;

static void handle_signal(int sig) {
    g_caught_sig = sig;
    if (g_term_modified && g_tty_fd >= 0) {
        /* tcsetattr is async-signal-safe on POSIX.1 / glibc */
        (void)tcsetattr(g_tty_fd, TCSANOW, &g_old_term);
        g_term_modified = 0;
    }
}

pm_status pm_read_password(const char *prompt, char *buf, size_t buf_size) {
    if (buf == NULL || buf_size == 0) {
        return PM_ERR_ARG;
    }

    buf[0] = '\0';

    int tty_fd = STDIN_FILENO;
    int is_tty = isatty(tty_fd);

    /* Print prompt if provided; write directly to avoid stdio buffering */
    if (prompt != NULL && prompt[0] != '\0') {
        size_t plen = strlen(prompt);
        if (write(STDERR_FILENO, prompt, plen) < 0) {
            /* Non-fatal: prompt write error */
        }
    }

    struct sigaction old_sa[NUM_SIGNALS];
    int sa_installed = 0;
    sigset_t block_mask, orig_mask;

    if (is_tty) {
        if (tcgetattr(tty_fd, &g_old_term) != 0) {
            return PM_ERR_IO;
        }

        g_tty_fd = tty_fd;
        g_caught_sig = 0;

        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = handle_signal;
        sigemptyset(&sa.sa_mask);
        /* Do NOT set SA_RESTART so read/pselect fails with EINTR when signal arrives */
        sa.sa_flags = 0;

        for (size_t i = 0; i < NUM_SIGNALS; i++) {
            if (sigaction(s_signals[i], &sa, &old_sa[i]) != 0) {
                for (size_t j = 0; j < i; j++) {
                    sigaction(s_signals[j], &old_sa[j], NULL);
                }
                return PM_ERR_IO;
            }
        }
        sa_installed = 1;

        struct termios new_term = g_old_term;
        new_term.c_lflag &= ~ECHO;

        if (tcsetattr(tty_fd, TCSAFLUSH, &new_term) != 0) {
            for (size_t i = 0; i < NUM_SIGNALS; i++) {
                sigaction(s_signals[i], &old_sa[i], NULL);
            }
            return PM_ERR_IO;
        }
        g_term_modified = 1;

        /* Block signals during loop; pselect unblocks orig_mask atomically while waiting */
        sigemptyset(&block_mask);
        for (size_t i = 0; i < NUM_SIGNALS; i++) {
            sigaddset(&block_mask, s_signals[i]);
        }
        sigprocmask(SIG_BLOCK, &block_mask, &orig_mask);
    }

    size_t pos = 0;
    int truncated = 0;
    int read_err = 0;
    int last_ch = -1;

    /* Read directly from descriptor without libc stdio buffers */
    while (1) {
        if (g_caught_sig != 0) {
            break;
        }

        if (is_tty) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(tty_fd, &rfds);

            /* Atomically unblock signals and wait for input to prevent race conditions */
            int prc = pselect(tty_fd + 1, &rfds, NULL, NULL, NULL, &orig_mask);
            if (prc < 0) {
                if (errno == EINTR) {
                    if (g_caught_sig != 0) {
                        break;
                    }
                    continue;
                }
                read_err = 1;
                break;
            }
        }

        char ch;
        ssize_t n = read(tty_fd, &ch, 1);
        if (n < 0) {
            if (errno == EINTR) {
                if (g_caught_sig != 0) {
                    break;
                }
                continue;
            }
            read_err = 1;
            break;
        }
        if (n == 0) {
            break; /* EOF */
        }

        last_ch = (unsigned char)ch;

        if (ch == '\r') {
            continue; /* Ignore carriage return (e.g. CRLF from non-tty streams) */
        }
        if (ch == '\n') {
            break; /* End of line */
        }

        if (pos + 1 < buf_size) {
            buf[pos++] = ch;
        } else {
            truncated = 1;
        }
    }

    if (is_tty) {
        if (g_term_modified) {
            tcsetattr(tty_fd, TCSAFLUSH, &g_old_term);
            g_term_modified = 0;
        }
        if (sa_installed) {
            sigprocmask(SIG_SETMASK, &orig_mask, NULL);
            for (size_t i = 0; i < NUM_SIGNALS; i++) {
                sigaction(s_signals[i], &old_sa[i], NULL);
            }
        }
        if (write(STDERR_FILENO, "\n", 1) < 0) {
            /* Non-fatal */
        }
    }

    if (g_caught_sig != 0) {
        pm_wipe(buf, buf_size);
        return PM_ERR_INTR;
    }

    if (read_err) {
        pm_wipe(buf, buf_size);
        return PM_ERR_IO;
    }

    if (truncated) {
        pm_wipe(buf, buf_size);
        return PM_ERR_TOO_BIG;
    }

    if (pos == 0 && last_ch < 0) {
        /* EOF reached immediately with no input */
        pm_wipe(buf, buf_size);
        return PM_ERR_EOF;
    }

    buf[pos] = '\0';
    return PM_OK;
}

pm_status pm_read_line(const char *prompt, char *buf, size_t buf_size) {
    if (buf == NULL || buf_size == 0) {
        return PM_ERR_ARG;
    }
    buf[0] = '\0';

    if (prompt != NULL && prompt[0] != '\0') {
        if (write(STDERR_FILENO, prompt, strlen(prompt)) < 0) {
            /* Non-fatal: prompt write error */
        }
    }

    size_t pos = 0;
    int got_any = 0;
    int truncated = 0;

    for (;;) {
        char ch;
        ssize_t n = read(STDIN_FILENO, &ch, 1);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            pm_wipe(buf, buf_size);
            return PM_ERR_IO;
        }
        if (n == 0) {
            break; /* EOF */
        }
        got_any = 1;
        if (ch == '\n') {
            break;
        }
        if (ch == '\r') {
            continue;
        }
        if (pos + 1 < buf_size) {
            buf[pos++] = ch;
        } else {
            truncated = 1; /* keep reading so the rest of the line is not left in stdin */
        }
    }

    if (truncated) {
        pm_wipe(buf, buf_size);
        return PM_ERR_TOO_BIG;
    }
    if (!got_any) {
        pm_wipe(buf, buf_size);
        return PM_ERR_EOF;
    }
    buf[pos] = '\0';
    return PM_OK;
}
