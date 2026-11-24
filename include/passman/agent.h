#ifndef PASSMAN_AGENT_H
#define PASSMAN_AGENT_H

#include <stddef.h>
#include <stdint.h>

#include "passman/crypto.h"

#define PM_SOCKET_PATH "/run/user/%u/passman.sock"

#define PM_IPC_FIELD_LEN 256u
#define PM_IPC_PHONE_LEN 32u
#define PM_IPC_ERR_LEN   256u

typedef enum {
    PM_MSG_INVALID = 0,
    PM_MSG_PING = 1,
    PM_MSG_UNLOCK = 2,
    PM_MSG_LOCK = 3,
    PM_MSG_STOP = 4,
    PM_MSG_GET = 5,
    PM_MSG_PUT = 6,
    PM_MSG_OK = 7,
    PM_MSG_ERR = 8,
    PM_MSG_LIST = 9,
    PM_MSG_LIST_END = 10
} pm_msg_type;

typedef struct {
    pm_msg_type type;
    char site[PM_IPC_FIELD_LEN];
    char email[PM_IPC_FIELD_LEN];
    char username[PM_IPC_FIELD_LEN];
    char phone[PM_IPC_PHONE_LEN];
    char password[PM_MAX_SECRET_LEN];
    char error[PM_IPC_ERR_LEN];
} pm_msg_t;

void pm_msg_wipe(pm_msg_t *msg);

int pm_agent_run(const char *vault_path, unsigned idle_timeout_sec);

int pm_agent_request(const char *socket_path, const pm_msg_t *req, pm_msg_t *resp);

typedef int (*pm_agent_list_cb)(const char *site, void *user_data);

int pm_agent_list(const char *socket_path, pm_agent_list_cb cb, void *user_data);

int pm_agent_stop(const char *socket_path);

#endif
