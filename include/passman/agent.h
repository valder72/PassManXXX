#ifndef PASSMAN_AGENT_H
#define PASSMAN_AGENT_H

/*
 * Agent: a long-lived process that keeps the unlocked key in memory
 * (mlock-ed) and serves requests over a Unix socket with 0600 permissions.
 */

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

/* Securely wipe a message struct (clears passwords/secrets). */
void pm_msg_wipe(pm_msg_t *msg);

/* Start the agent: bind the socket, drop to serving. Blocks until stopped. */
int pm_agent_run(const char *vault_path, unsigned idle_timeout_sec);

/* Send one structured request to a running agent and receive its reply. */
int pm_agent_request(const char *socket_path, const pm_msg_t *req, pm_msg_t *resp);

/* Callback invoked for each site name returned by pm_agent_list. */
typedef int (*pm_agent_list_cb)(const char *site, void *user_data);

/* Request the list of site names from an unlocked agent (no secrets sent). */
int pm_agent_list(const char *socket_path, pm_agent_list_cb cb, void *user_data);

/* Ask the agent to forget the key and stop. */
int pm_agent_stop(const char *socket_path);

#endif /* PASSMAN_AGENT_H */
