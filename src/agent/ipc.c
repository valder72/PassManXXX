#include <errno.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "passman/agent.h"
#include "ipc_internal.h"

#define PM_IPC_RECV_TIMEOUT_MS 10000

void pm_msg_wipe(pm_msg_t *msg) {
    if (!msg) {
        return;
    }
    pm_wipe(msg, sizeof(*msg));
}

static int send_all(int fd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t sent = 0;

    while (sent < len) {
        ssize_t n = send(fd, p + sent, len - sent, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

static int calc_remaining_ms(const struct timespec *start, int total_timeout_ms) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0;
    }
    int64_t elapsed_ms = (int64_t)(now.tv_sec - start->tv_sec) * 1000 +
                         (int64_t)(now.tv_nsec - start->tv_nsec) / 1000000;
    if (elapsed_ms < 0) {
        elapsed_ms = 0;
    }
    if (elapsed_ms >= total_timeout_ms) {
        return 0;
    }
    return (int)(total_timeout_ms - elapsed_ms);
}

static int wait_readable(int fd, const struct timespec *start, int total_timeout_ms) {
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;

    for (;;) {
        int timeout_ms = calc_remaining_ms(start, total_timeout_ms);
        if (timeout_ms <= 0) {
            errno = ETIMEDOUT;
            return -1;
        }

        int rc = poll(&pfd, 1, timeout_ms);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (rc == 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        if (pfd.revents & (POLLERR | POLLNVAL)) {
            return -1;
        }
        return 0;
    }
}

static int recv_all(int fd, void *buf, size_t len, const struct timespec *start,
                    int total_timeout_ms) {
    uint8_t *p = (uint8_t *)buf;
    size_t recvd = 0;

    while (recvd < len) {
        if (wait_readable(fd, start, total_timeout_ms) != 0) {
            return -1;
        }
        ssize_t n = recv(fd, p + recvd, len - recvd, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        recvd += (size_t)n;
    }
    return 0;
}

static int write_field(uint8_t *dst, size_t cap, size_t *offset, const char *src, size_t max_src) {
    size_t len = strnlen(src, max_src);
    if (len >= max_src || len > UINT16_MAX) {
        return -1;
    }
    if (*offset + sizeof(uint16_t) + len > cap) {
        return -1;
    }

    uint16_t wire_len = (uint16_t)len;
    memcpy(dst + *offset, &wire_len, sizeof(wire_len));
    *offset += sizeof(wire_len);
    if (len > 0) {
        memcpy(dst + *offset, src, len);
        *offset += len;
    }
    return 0;
}

static int read_field(const uint8_t *src, size_t total, size_t *offset, char *dst,
                      size_t dst_size) {
    if (*offset + sizeof(uint16_t) > total) {
        return -1;
    }

    uint16_t wire_len = 0;
    memcpy(&wire_len, src + *offset, sizeof(wire_len));
    *offset += sizeof(wire_len);

    if ((size_t)wire_len >= dst_size || *offset + wire_len > total) {
        return -1;
    }
    if (wire_len > 0) {
        memcpy(dst, src + *offset, wire_len);
        *offset += wire_len;
    }
    dst[wire_len] = '\0';
    return 0;
}

static int validate_msg_fields(const pm_msg_t *msg) {
    switch (msg->type) {
    case PM_MSG_PING:
    case PM_MSG_LOCK:
    case PM_MSG_STOP:
    case PM_MSG_LIST:
    case PM_MSG_LIST_END:
        return 0;
    case PM_MSG_UNLOCK:
        return msg->password[0] != '\0' ? 0 : -1;
    case PM_MSG_GET:
        return msg->site[0] != '\0' ? 0 : -1;
    case PM_MSG_ERR:
        return msg->error[0] != '\0' ? 0 : -1;
    case PM_MSG_PUT:
        return msg->site[0] != '\0' ? 0 : -1;
    case PM_MSG_OK:
        return 0;
    default:
        return -1;
    }
}

int pm_msg_encode(const pm_msg_t *msg, char *buf, size_t buf_size) {
    if (!msg || !buf || buf_size < sizeof(msg_header_t) + 1u) {
        return -1;
    }
    if (validate_msg_fields(msg) != 0) {
        return -1;
    }

    uint8_t *payload = (uint8_t *)buf + sizeof(msg_header_t);
    size_t payload_cap = buf_size - sizeof(msg_header_t);
    if (payload_cap > PM_IPC_MAX_PAYLOAD) {
        payload_cap = PM_IPC_MAX_PAYLOAD;
    }

    size_t offset = 0;
    payload[offset++] = (uint8_t)msg->type;

    int rc = 0;
    switch (msg->type) {
    case PM_MSG_PING:
    case PM_MSG_LOCK:
    case PM_MSG_STOP:
    case PM_MSG_LIST:
    case PM_MSG_LIST_END:
        break;
    case PM_MSG_UNLOCK:
        rc = write_field(payload, payload_cap, &offset, msg->password, sizeof(msg->password));
        break;
    case PM_MSG_GET:
        rc = write_field(payload, payload_cap, &offset, msg->site, sizeof(msg->site));
        break;
    case PM_MSG_ERR:
        rc = write_field(payload, payload_cap, &offset, msg->error, sizeof(msg->error));
        break;
    case PM_MSG_PUT:
    case PM_MSG_OK:
        rc = write_field(payload, payload_cap, &offset, msg->site, sizeof(msg->site));
        if (rc == 0) {
            rc = write_field(payload, payload_cap, &offset, msg->email, sizeof(msg->email));
        }
        if (rc == 0) {
            rc = write_field(payload, payload_cap, &offset, msg->username, sizeof(msg->username));
        }
        if (rc == 0) {
            rc = write_field(payload, payload_cap, &offset, msg->phone, sizeof(msg->phone));
        }
        if (rc == 0) {
            rc = write_field(payload, payload_cap, &offset, msg->password, sizeof(msg->password));
        }
        break;
    default:
        rc = -1;
        break;
    }

    if (rc != 0) {
        pm_wipe(buf, buf_size);
        return -1;
    }

    uint16_t frame_payload_size = (uint16_t)offset;
    memcpy(buf, &frame_payload_size, sizeof(frame_payload_size));
    return (int)(sizeof(msg_header_t) + offset);
}

int pm_msg_decode(const char *buf, size_t buf_len, pm_msg_t *msg) {
    if (!buf || !msg || buf_len < sizeof(msg_header_t) + 1u) {
        return -1;
    }

    pm_msg_wipe(msg);

    uint16_t payload_size = 0;
    memcpy(&payload_size, buf, sizeof(payload_size));
    if (payload_size == 0 || payload_size > PM_IPC_MAX_PAYLOAD ||
        (size_t)payload_size > buf_len - sizeof(msg_header_t)) {
        return -1;
    }

    const uint8_t *payload = (const uint8_t *)buf + sizeof(msg_header_t);
    size_t offset = 0;
    msg->type = (pm_msg_type)payload[offset++];

    int rc = 0;
    switch (msg->type) {
    case PM_MSG_PING:
    case PM_MSG_LOCK:
    case PM_MSG_STOP:
    case PM_MSG_LIST:
    case PM_MSG_LIST_END:
        break;
    case PM_MSG_UNLOCK:
        rc = read_field(payload, payload_size, &offset, msg->password, sizeof(msg->password));
        break;
    case PM_MSG_GET:
        rc = read_field(payload, payload_size, &offset, msg->site, sizeof(msg->site));
        break;
    case PM_MSG_ERR:
        rc = read_field(payload, payload_size, &offset, msg->error, sizeof(msg->error));
        break;
    case PM_MSG_PUT:
    case PM_MSG_OK:
        rc = read_field(payload, payload_size, &offset, msg->site, sizeof(msg->site));
        if (rc == 0) {
            rc = read_field(payload, payload_size, &offset, msg->email, sizeof(msg->email));
        }
        if (rc == 0) {
            rc = read_field(payload, payload_size, &offset, msg->username, sizeof(msg->username));
        }
        if (rc == 0) {
            rc = read_field(payload, payload_size, &offset, msg->phone, sizeof(msg->phone));
        }
        if (rc == 0) {
            rc = read_field(payload, payload_size, &offset, msg->password, sizeof(msg->password));
        }
        break;
    default:
        rc = -1;
        break;
    }

    if (rc != 0 || offset != payload_size || validate_msg_fields(msg) != 0) {
        pm_msg_wipe(msg);
        return -1;
    }
    return 0;
}

int pm_ipc_send_frame(int fd, const void *data, uint16_t size) {
    if (fd < 0 || !data || size == 0 || size > PM_IPC_MAX_PAYLOAD) {
        return -1;
    }
    if (send_all(fd, &size, sizeof(size)) != 0) {
        return -1;
    }
    if (send_all(fd, data, size) != 0) {
        return -1;
    }
    return 0;
}

int pm_ipc_recv_frame_timeout(int fd, void *buf, size_t buf_size, uint16_t *out_size,
                              int timeout_ms) {
    if (fd < 0 || !buf || !out_size || buf_size == 0 || timeout_ms <= 0) {
        return -1;
    }

    struct timespec start;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        return -1;
    }

    uint16_t size = 0;
    if (recv_all(fd, &size, sizeof(size), &start, timeout_ms) != 0) {
        return -1;
    }
    if (size == 0 || size > PM_IPC_MAX_PAYLOAD || (size_t)size > buf_size) {
        return -1;
    }
    if (recv_all(fd, buf, size, &start, timeout_ms) != 0) {
        pm_wipe(buf, buf_size);
        return -1;
    }

    *out_size = size;
    return 0;
}

int pm_ipc_recv_frame(int fd, void *buf, size_t buf_size, uint16_t *out_size) {
    return pm_ipc_recv_frame_timeout(fd, buf, buf_size, out_size, PM_IPC_RECV_TIMEOUT_MS);
}

int pm_ipc_send_msg(int fd, const pm_msg_t *msg) {
    if (fd < 0 || !msg) {
        return -1;
    }

    char frame[PM_IPC_MAX_LINE];
    int total_len = pm_msg_encode(msg, frame, sizeof(frame));
    if (total_len < 0) {
        pm_wipe(frame, sizeof(frame));
        return -1;
    }

    int rc = send_all(fd, frame, (size_t)total_len);
    pm_wipe(frame, sizeof(frame));
    return rc;
}

int pm_ipc_recv_msg(int fd, pm_msg_t *msg) {
    if (fd < 0 || !msg) {
        return -1;
    }

    char frame[PM_IPC_MAX_LINE];
    uint16_t payload_size = 0;
    if (pm_ipc_recv_frame(fd, frame + sizeof(msg_header_t), PM_IPC_MAX_PAYLOAD, &payload_size) !=
        0) {
        pm_wipe(frame, sizeof(frame));
        return -1;
    }

    memcpy(frame, &payload_size, sizeof(payload_size));
    int rc = pm_msg_decode(frame, sizeof(msg_header_t) + payload_size, msg);
    pm_wipe(frame, sizeof(frame));
    return rc;
}

static int connect_unix_socket(const char *socket_path) {
    if (!socket_path || socket_path[0] == '\0') {
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    size_t path_len = strlen(socket_path);
    if (path_len >= sizeof(addr.sun_path)) {
        return -1;
    }
    memcpy(addr.sun_path, socket_path, path_len + 1u);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    if (connect(fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int pm_agent_request(const char *socket_path, const pm_msg_t *req, pm_msg_t *resp) {
    if (!req || !resp) {
        return -1;
    }

    pm_msg_wipe(resp);

    int fd = connect_unix_socket(socket_path);
    if (fd < 0) {
        return -1;
    }

    int rc = -1;
    if (pm_ipc_send_msg(fd, req) == 0 && pm_ipc_recv_msg(fd, resp) == 0) {
        rc = 0;
    }

    close(fd);
    return rc;
}

int pm_agent_list(const char *socket_path, pm_agent_list_cb cb, void *user_data) {
    if (!cb) {
        return -1;
    }

    int fd = connect_unix_socket(socket_path);
    if (fd < 0) {
        return -1;
    }

    int rc = -1;
    pm_msg_t req;
    pm_msg_wipe(&req);
    req.type = PM_MSG_LIST;

    if (pm_ipc_send_msg(fd, &req) == 0) {
        pm_msg_t resp;
        pm_msg_wipe(&resp);
        for (;;) {
            if (pm_ipc_recv_msg(fd, &resp) != 0) {
                break;
            }
            if (resp.type == PM_MSG_LIST_END) {
                rc = 0;
                break;
            }
            if (resp.type != PM_MSG_OK || cb(resp.site, user_data) != 0) {
                break;
            }
        }
        pm_msg_wipe(&resp);
    }

    pm_msg_wipe(&req);
    close(fd);
    return rc;
}
