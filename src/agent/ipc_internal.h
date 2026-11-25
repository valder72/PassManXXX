#ifndef IPC_INTERNAL_H
#define IPC_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "passman/agent.h"

#define PM_IPC_MAX_LINE    4096u
#define PM_IPC_MAX_PAYLOAD (PM_IPC_MAX_LINE - sizeof(uint16_t))

typedef struct msg_header {
    uint16_t size;
    uint8_t data[];
} msg_header_t;

int pm_msg_encode(const pm_msg_t *msg, char *buf, size_t buf_size);
int pm_msg_decode(const char *buf, size_t buf_len, pm_msg_t *msg);

int pm_ipc_send_frame(int fd, const void *data, uint16_t size);
int pm_ipc_send_frame_timeout(int fd, const void *data, uint16_t size, int timeout_ms);
int pm_ipc_recv_frame(int fd, void *buf, size_t buf_size, uint16_t *out_size);
int pm_ipc_recv_frame_timeout(int fd, void *buf, size_t buf_size, uint16_t *out_size,
                              int timeout_ms);
int pm_ipc_send_msg(int fd, const pm_msg_t *msg);
int pm_ipc_recv_msg(int fd, pm_msg_t *msg);
int pm_ipc_check_peer_uid(int fd);

#endif
