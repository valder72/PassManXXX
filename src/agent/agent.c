#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "passman/agent.h"
#include "passman/vault.h"
#include "ipc_internal.h"

#define PM_LISTEN_BACKLOG 16

static volatile sig_atomic_t g_stop_requested = 0;

typedef struct {
    uint8_t key[PM_KEY_BYTES];
    int unlocked;
    struct timespec last_activity;
    unsigned idle_timeout_sec;
    const char *vault_path;
    int stop_loop;
} agent_session_t;

static void handle_stop_signal(int sig) {
    (void)sig;
    g_stop_requested = 1;
}

static int install_signal_handlers(void) {
    struct sigaction sa_stop;
    memset(&sa_stop, 0, sizeof(sa_stop));
    sa_stop.sa_handler = handle_stop_signal;
    sigemptyset(&sa_stop.sa_mask);
    if (sigaction(SIGINT, &sa_stop, NULL) != 0 || sigaction(SIGTERM, &sa_stop, NULL) != 0) {
        return -1;
    }

    struct sigaction sa_ign;
    memset(&sa_ign, 0, sizeof(sa_ign));
    sa_ign.sa_handler = SIG_IGN;
    sigemptyset(&sa_ign.sa_mask);
    if (sigaction(SIGPIPE, &sa_ign, NULL) != 0) {
        return -1;
    }

    return 0;
}

static int resolve_socket_path(char *out, size_t out_size) {
    const char *override = getenv("PASSMAN_SOCKET");
    if (override && override[0] != '\0') {
        int n = snprintf(out, out_size, "%s", override);
        if (n < 0 || (size_t)n >= out_size) {
            return -1;
        }
        return 0;
    }

    struct stat st;
    const char *xdg_dir = getenv("XDG_RUNTIME_DIR");
    if (xdg_dir && xdg_dir[0] != '\0') {
        if (stat(xdg_dir, &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == getuid() &&
            access(xdg_dir, W_OK | X_OK) == 0) {
            size_t len = strlen(xdg_dir);
            int n;
            if (xdg_dir[len - 1] == '/') {
                n = snprintf(out, out_size, "%spassman.sock", xdg_dir);
            } else {
                n = snprintf(out, out_size, "%s/passman.sock", xdg_dir);
            }
            if (n < 0 || (size_t)n >= out_size) {
                return -1;
            }
            return 0;
        }
    }

    char dir[64];
    snprintf(dir, sizeof(dir), "/run/user/%u", (unsigned)getuid());
    if (stat(dir, &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == getuid() &&
        access(dir, W_OK | X_OK) == 0) {
        int n = snprintf(out, out_size, PM_SOCKET_PATH, (unsigned)getuid());
        if (n < 0 || (size_t)n >= out_size) {
            return -1;
        }
        return 0;
    }

    snprintf(dir, sizeof(dir), "/tmp/passman-%u", (unsigned)getuid());
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
        return -1;
    }
    if (lstat(dir, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != getuid()) {
        return -1;
    }
    if ((st.st_mode & 0777) != 0700 && chmod(dir, 0700) != 0) {
        return -1;
    }
    if (access(dir, W_OK | X_OK) != 0) {
        return -1;
    }

    int n = snprintf(out, out_size, "%s/passman.sock", dir);
    if (n < 0 || (size_t)n >= out_size) {
        return -1;
    }
    return 0;
}

static int is_socket_live(const char *sock_path) {
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    size_t len = strlen(sock_path);
    if (len >= sizeof(addr.sun_path)) {
        return -1;
    }
    memcpy(addr.sun_path, sock_path, len + 1u);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    int live = 0;
    if (connect(fd, (const struct sockaddr *)&addr, sizeof(addr)) == 0) {
        live = 1;
    } else if (errno != ECONNREFUSED && errno != ENOENT) {
        live = -1;
    }
    close(fd);
    return live;
}

static int prepare_socket_path(const char *sock_path) {
    struct stat st;
    if (lstat(sock_path, &st) != 0) {
        return errno == ENOENT ? 0 : -1;
    }
    if (!S_ISSOCK(st.st_mode)) {
        return -1;
    }

    int live = is_socket_live(sock_path);
    if (live != 0) {
        return -1;
    }
    return unlink(sock_path);
}

static int create_listen_socket(const char *sock_path) {
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    size_t len = strlen(sock_path);
    if (len == 0 || len >= sizeof(addr.sun_path)) {
        return -1;
    }
    memcpy(addr.sun_path, sock_path, len + 1u);

    if (prepare_socket_path(sock_path) != 0) {
        return -1;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    mode_t old_umask = umask(0177);
    int bind_rc = bind(fd, (const struct sockaddr *)&addr, sizeof(addr));
    umask(old_umask);

    if (bind_rc != 0) {
        close(fd);
        return -1;
    }
    if (chmod(sock_path, S_IRUSR | S_IWUSR) != 0 || listen(fd, PM_LISTEN_BACKLOG) != 0) {
        close(fd);
        unlink(sock_path);
        return -1;
    }

    return fd;
}

static void lock_session(agent_session_t *sess) {
    pm_wipe(sess->key, sizeof(sess->key));
    sess->unlocked = 0;
}

static int update_activity(agent_session_t *sess) {
    return clock_gettime(CLOCK_MONOTONIC, &sess->last_activity);
}

static int compute_poll_timeout_ms(const agent_session_t *sess) {
    if (!sess->unlocked || sess->idle_timeout_sec == 0) {
        return -1;
    }

    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0;
    }

    int64_t elapsed_ms = (int64_t)(now.tv_sec - sess->last_activity.tv_sec) * 1000 +
                         (int64_t)(now.tv_nsec - sess->last_activity.tv_nsec) / 1000000;
    if (elapsed_ms < 0) {
        elapsed_ms = 0;
    }

    int64_t limit_ms = (int64_t)sess->idle_timeout_sec * 1000;
    if (elapsed_ms >= limit_ms) {
        return 0;
    }

    int64_t remaining = limit_ms - elapsed_ms;
    return remaining > INT_MAX ? INT_MAX : (int)remaining;
}

static void set_error(pm_msg_t *resp, const char *text) {
    resp->type = PM_MSG_ERR;
    snprintf(resp->error, sizeof(resp->error), "%s", text);
}

static int append_escaped_field(char *out, size_t out_size, size_t *pos, const char *src) {
    for (size_t i = 0; src[i] != '\0'; i++) {
        char c = src[i];
        if (c == '\\' || c == '\t' || c == '\n' || c == '\r') {
            if (*pos + 2 >= out_size) {
                return -1;
            }
            out[(*pos)++] = '\\';
            if (c == '\\') {
                out[(*pos)++] = '\\';
            } else if (c == '\t') {
                out[(*pos)++] = 't';
            } else if (c == '\n') {
                out[(*pos)++] = 'n';
            } else {
                out[(*pos)++] = 'r';
            }
        } else {
            if (*pos + 1 >= out_size) {
                return -1;
            }
            out[(*pos)++] = c;
        }
    }
    return 0;
}

static int pack_secret(const pm_msg_t *req, char *out, size_t out_size) {
    if (!out || out_size == 0) {
        return -1;
    }

    size_t pos = 0;
    if (append_escaped_field(out, out_size, &pos, req->email) != 0 || pos + 1 >= out_size) {
        pm_wipe(out, out_size);
        return -1;
    }
    out[pos++] = '\t';

    if (append_escaped_field(out, out_size, &pos, req->username) != 0 || pos + 1 >= out_size) {
        pm_wipe(out, out_size);
        return -1;
    }
    out[pos++] = '\t';

    if (append_escaped_field(out, out_size, &pos, req->phone) != 0 || pos + 1 >= out_size) {
        pm_wipe(out, out_size);
        return -1;
    }
    out[pos++] = '\t';

    if (append_escaped_field(out, out_size, &pos, req->password) != 0) {
        pm_wipe(out, out_size);
        return -1;
    }

    out[pos] = '\0';
    return 0;
}

static int unpack_field(char *dst, size_t dst_size, const char *start, size_t len) {
    if (dst_size == 0) {
        return -1;
    }

    size_t out_i = 0;
    for (size_t i = 0; i < len; i++) {
        char ch = start[i];
        if (ch == '\\' && i + 1 < len) {
            char next = start[i + 1];
            if (next == '\\') {
                ch = '\\';
                i++;
            } else if (next == 't') {
                ch = '\t';
                i++;
            } else if (next == 'n') {
                ch = '\n';
                i++;
            } else if (next == 'r') {
                ch = '\r';
                i++;
            }
        }
        if (out_i + 1 >= dst_size) {
            pm_wipe(dst, dst_size);
            return -1;
        }
        dst[out_i++] = ch;
    }
    dst[out_i] = '\0';
    return 0;
}

static int unpack_secret(const char *secret, const char *site, pm_msg_t *resp) {
    snprintf(resp->site, sizeof(resp->site), "%s", site);

    const char *t1 = strchr(secret, '\t');
    const char *t2 = t1 ? strchr(t1 + 1, '\t') : NULL;
    const char *t3 = t2 ? strchr(t2 + 1, '\t') : NULL;
    if (!t1 || !t2 || !t3) {
        size_t len = strlen(secret);
        if (len >= sizeof(resp->password)) {
            pm_wipe(resp->password, sizeof(resp->password));
            return -1;
        }
        memcpy(resp->password, secret, len + 1u);
        return 0;
    }

    if (unpack_field(resp->email, sizeof(resp->email), secret, (size_t)(t1 - secret)) != 0 ||
        unpack_field(resp->username, sizeof(resp->username), t1 + 1, (size_t)(t2 - (t1 + 1))) !=
            0 ||
        unpack_field(resp->phone, sizeof(resp->phone), t2 + 1, (size_t)(t3 - (t2 + 1))) != 0 ||
        unpack_field(resp->password, sizeof(resp->password), t3 + 1, strlen(t3 + 1)) != 0) {
        return -1;
    }
    return 0;
}

static void handle_request(agent_session_t *sess, pm_msg_t *req, pm_msg_t *resp) {
    pm_msg_wipe(resp);

    switch (req->type) {
    case PM_MSG_PING:
        resp->type = PM_MSG_OK;
        break;

    case PM_MSG_UNLOCK:
        if (pm_vault_open(sess->vault_path, req->password, sess->key) == 0) {
            sess->unlocked = 1;
            update_activity(sess);
            resp->type = PM_MSG_OK;
        } else {
            lock_session(sess);
            set_error(resp, "unlock failed");
        }
        pm_msg_wipe(req);
        break;

    case PM_MSG_LOCK:
        lock_session(sess);
        resp->type = PM_MSG_OK;
        break;

    case PM_MSG_STOP:
        lock_session(sess);
        sess->stop_loop = 1;
        resp->type = PM_MSG_OK;
        break;

    case PM_MSG_GET: {
        if (!sess->unlocked) {
            set_error(resp, "vault is locked");
            break;
        }
        update_activity(sess);
        char secret[PM_MAX_SECRET_LEN];
        if (pm_vault_get(sess->vault_path, sess->key, req->site, secret, sizeof(secret)) == 0) {
            if (unpack_secret(secret, req->site, resp) == 0) {
                resp->type = PM_MSG_OK;
            } else {
                pm_msg_wipe(resp);
                set_error(resp, "record too large");
            }
        } else {
            set_error(resp, "record not found");
        }
        pm_wipe(secret, sizeof(secret));
        break;
    }

    case PM_MSG_PUT: {
        if (!sess->unlocked) {
            set_error(resp, "vault is locked");
            break;
        }
        update_activity(sess);
        char secret[PM_MAX_SECRET_LEN];
        if (pack_secret(req, secret, sizeof(secret)) != 0) {
            set_error(resp, "invalid record fields");
        } else if (pm_vault_put(sess->vault_path, sess->key, req->site, secret) == 0) {
            resp->type = PM_MSG_OK;
        } else {
            set_error(resp, "vault write failed");
        }
        pm_wipe(secret, sizeof(secret));
        pm_msg_wipe(req);
        break;
    }

    default:
        set_error(resp, "unknown request");
        break;
    }
}

typedef struct {
    int client_fd;
    int sent_any;
    int send_err;
} list_send_ctx_t;

static int list_send_cb(const char *name, void *user_data) {
    list_send_ctx_t *ctx = (list_send_ctx_t *)user_data;
    if (!name || name[0] == '\0') {
        return 0;
    }

    pm_msg_t item;
    pm_msg_wipe(&item);
    item.type = PM_MSG_OK;
    snprintf(item.site, sizeof(item.site), "%s", name);

    int rc = pm_ipc_send_msg(ctx->client_fd, &item);
    pm_msg_wipe(&item);
    if (rc != 0) {
        ctx->send_err = 1;
        return -1;
    }
    ctx->sent_any = 1;
    return 0;
}

static void handle_list(int client_fd, agent_session_t *sess) {
    pm_msg_t resp;
    pm_msg_wipe(&resp);

    if (!sess->unlocked) {
        set_error(&resp, "vault is locked");
        pm_ipc_send_msg(client_fd, &resp);
        pm_msg_wipe(&resp);
        return;
    }

    update_activity(sess);
    list_send_ctx_t ctx = {.client_fd = client_fd, .sent_any = 0, .send_err = 0};
    int vault_rc = pm_vault_list(sess->vault_path, sess->key, list_send_cb, &ctx);
    if (ctx.send_err) {
        return;
    }
    if (vault_rc != 0) {
        if (!ctx.sent_any) {
            set_error(&resp, "vault list failed");
            pm_ipc_send_msg(client_fd, &resp);
            pm_msg_wipe(&resp);
        }
        return;
    }

    resp.type = PM_MSG_LIST_END;
    pm_ipc_send_msg(client_fd, &resp);
    pm_msg_wipe(&resp);
}

static int check_peer_credentials(int client_fd) {
#if defined(__linux__) && defined(SO_PEERCRED)
    struct ucred cred;
    socklen_t len = sizeof(cred);
    if (getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0 ||
        len != sizeof(cred)) {
        return -1;
    }
    if (cred.uid != getuid()) {
        return -1;
    }
#else
    (void)client_fd;
#endif
    return 0;
}

static void handle_client(int client_fd, agent_session_t *sess) {
    pm_msg_t req;
    pm_msg_t resp;
    pm_msg_wipe(&req);
    pm_msg_wipe(&resp);

    if (pm_ipc_recv_msg(client_fd, &req) == 0) {
        if (req.type == PM_MSG_LIST) {
            handle_list(client_fd, sess);
        } else {
            handle_request(sess, &req, &resp);
            pm_ipc_send_msg(client_fd, &resp);
        }
    }

    pm_msg_wipe(&req);
    pm_msg_wipe(&resp);
}

int pm_agent_run(const char *vault_path, unsigned idle_timeout_sec) {
    if (!vault_path || vault_path[0] == '\0') {
        return -1;
    }

    g_stop_requested = 0;
    if (install_signal_handlers() != 0) {
        return -1;
    }

    struct sockaddr_un dummy;
    char sock_path[sizeof(dummy.sun_path)];
    if (resolve_socket_path(sock_path, sizeof(sock_path)) != 0) {
        return -1;
    }

    int listen_fd = create_listen_socket(sock_path);
    if (listen_fd < 0) {
        return -1;
    }

    agent_session_t sess;
    memset(&sess, 0, sizeof(sess));
    sess.idle_timeout_sec = idle_timeout_sec;
    sess.vault_path = vault_path;

    if (mlock(sess.key, sizeof(sess.key)) != 0) {
        perror("pm-agentd: mlock");
        close(listen_fd);
        unlink(sock_path);
        return -1;
    }

    while (!g_stop_requested && !sess.stop_loop) {
        int timeout_ms = compute_poll_timeout_ms(&sess);
        if (timeout_ms == 0) {
            lock_session(&sess);
            timeout_ms = -1;
        }

        struct pollfd pfd;
        pfd.fd = listen_fd;
        pfd.events = POLLIN;
        pfd.revents = 0;

        int rc = poll(&pfd, 1, timeout_ms);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (rc == 0) {
            lock_session(&sess);
            continue;
        }
        if (pfd.revents & (POLLERR | POLLNVAL)) {
            break;
        }
        if (pfd.revents & POLLIN) {
            int client_fd = accept(listen_fd, NULL, NULL);
            if (client_fd < 0) {
                if (errno == EINTR) {
                    continue;
                }
                break;
            }
            if (check_peer_credentials(client_fd) == 0) {
                handle_client(client_fd, &sess);
            }
            close(client_fd);
        }
    }

    lock_session(&sess);
    munlock(sess.key, sizeof(sess.key));
    close(listen_fd);
    unlink(sock_path);
    return 0;
}

int pm_agent_stop(const char *socket_path) {
    if (!socket_path || socket_path[0] == '\0') {
        return -1;
    }

    pm_msg_t req;
    pm_msg_t resp;
    pm_msg_wipe(&req);
    pm_msg_wipe(&resp);
    req.type = PM_MSG_STOP;

    int rc = -1;
    if (pm_agent_request(socket_path, &req, &resp) == 0 && resp.type == PM_MSG_OK) {
        rc = 0;
    }

    pm_msg_wipe(&req);
    pm_msg_wipe(&resp);
    return rc;
}
