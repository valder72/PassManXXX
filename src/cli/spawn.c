#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "passman/agent.h"
#include "passman/cli.h"

int pm_cli_agent_log_path(char *out, size_t out_size) {
    char sock[PATH_MAX];
    if (out == NULL || pm_socket_path(sock, sizeof sock) != 0) {
        return -1;
    }
    int n = snprintf(out, out_size, "%s.log", sock);
    return (n > 0 && (size_t)n < out_size) ? 0 : -1;
}

/* Child side: open the log for the agent's stderr. It must be a regular file
 * of ours (no symlink, nobody else's file); it is emptied only after that
 * check. Returns the descriptor or -1, then the caller uses /dev/null. */
static int open_agent_log(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != getuid() ||
        ftruncate(fd, 0) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Find pm-agentd: $PASSMAN_AGENT, then next to our own binary. Returns 0 and
 * the path in out, or -1 to fall back to a $PATH lookup. */
static int agent_binary(char *out, size_t out_size) {
    const char *env = getenv("PASSMAN_AGENT");
    if (env != NULL && env[0] != '\0') {
        int n = snprintf(out, out_size, "%s", env);
        return (n > 0 && (size_t)n < out_size) ? 0 : -1;
    }

    char self[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", self, sizeof self - 1);
    if (len <= 0) {
        return -1;
    }
    self[len] = '\0';
    char *slash = strrchr(self, '/');
    if (slash == NULL) {
        return -1;
    }
    *slash = '\0';
    int n = snprintf(out, out_size, "%s/pm-agentd", self);
    if (n <= 0 || (size_t)n >= out_size || access(out, X_OK) != 0) {
        return -1;
    }
    return 0;
}

pm_status pm_cli_spawn_agent(const char *vault_path, unsigned timeout_sec) {
    if (vault_path == NULL || vault_path[0] == '\0') {
        return PM_ERR_ARG;
    }

    /* the agent chdir()s to "/", so a relative vault path must be resolved now */
    char abs_vault[PATH_MAX];
    if (realpath(vault_path, abs_vault) == NULL) {
        return PM_ERR_IO;
    }
    char bin[PATH_MAX];
    int have_bin = agent_binary(bin, sizeof bin) == 0;
    char timeout_str[16];
    snprintf(timeout_str, sizeof timeout_str, "%u", timeout_sec);
    char log_path[PATH_MAX];
    int have_log = pm_cli_agent_log_path(log_path, sizeof log_path) == 0;

    pid_t pid = fork();
    if (pid < 0) {
        return PM_ERR_IO;
    }
    if (pid == 0) {
        /* first child: new session so the agent does not get the terminal's
         * SIGHUP/SIGINT, then fork again so the agent is not a session leader
         * (it can never reacquire a controlling terminal) and is reparented to init */
        if (setsid() < 0) {
            _exit(127);
        }
        pid_t pid2 = fork();
        if (pid2 < 0) {
            _exit(127);
        }
        if (pid2 > 0) {
            _exit(0);
        }

        if (chdir("/") != 0) {
            _exit(127);
        }
        umask(077);
        /* stdin/stdout go nowhere; stderr goes to the log so that a failed
         * start (e.g. mlock over RLIMIT_MEMLOCK) can be explained */
        int log_fd = have_log ? open_agent_log(log_path) : -1;
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            dup2(devnull, STDOUT_FILENO);
            dup2(log_fd >= 0 ? log_fd : devnull, STDERR_FILENO);
            if (devnull > STDERR_FILENO) {
                close(devnull);
            }
        }
        if (log_fd > STDERR_FILENO) {
            close(log_fd);
        }

        char *argv[] = {have_bin ? bin : "pm-agentd", abs_vault, timeout_str, NULL};
        if (have_bin) {
            execv(bin, argv);
        } else {
            execvp("pm-agentd", argv);
        }
        _exit(127);
    }

    /* reap the first child; the agent itself is now a child of init */
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
            return PM_ERR_IO;
        }
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        return PM_ERR_IO;
    }
    return PM_OK;
}
