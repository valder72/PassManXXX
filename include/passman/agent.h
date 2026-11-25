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
    pm_status status; /* carries pm_status on PM_MSG_ERR, PM_OK otherwise */
    char site[PM_IPC_FIELD_LEN];
    char email[PM_IPC_FIELD_LEN];
    char username[PM_IPC_FIELD_LEN];
    char phone[PM_IPC_PHONE_LEN];
    char password[PM_MAX_SECRET_LEN];
    char error[PM_IPC_ERR_LEN];
} pm_msg_t;

/*
 * Resolve the Unix socket path shared by both the agent and the CLI:
 *   1. $PASSMAN_SOCKET if non-empty
 *   2. $XDG_RUNTIME_DIR/passman.sock if owned by the current user and writable
 *   3. /run/user/<uid>/passman.sock if owned by the current user and writable
 *   4. /tmp/passman-<uid>/passman.sock (directory created with mode 0700)
 * Returns 0 on success, -1 on error or if out_size is too small.
 */
int pm_socket_path(char *out, size_t out_size);

/* Securely wipe a message struct (clears passwords/secrets). */
void pm_msg_wipe(pm_msg_t *msg);

/* Start the agent: bind the socket and serve requests until stopped. Returns 0 on clean exit, -1 on setup error. */
int pm_agent_run(const char *vault_path, unsigned idle_timeout_sec);

/*
 * Send one request to a running agent and receive its reply into `resp`.
 * `resp` is wiped before use. Caller is responsible for calling pm_msg_wipe()
 * on `req` and `resp` when they contain secrets.
 * Returns 0 if the round-trip succeeded (even when resp->type == PM_MSG_ERR),
 * or -1 on socket/IPC failure.
 */
int pm_agent_request(const char *socket_path, const pm_msg_t *req, pm_msg_t *resp);

/* Callback invoked for each site name returned by pm_agent_list. Return 0 to continue, non-zero to stop. */
typedef int (*pm_agent_list_cb)(const char *site, void *user_data);

/*
 * Request the list of site names from an unlocked agent (no secrets sent).
 * Returns 0 after all items and PM_MSG_LIST_END are received, or -1 on IPC error,
 * agent error (e.g. locked vault), or if `cb` returns non-zero.
 */
int pm_agent_list(const char *socket_path, pm_agent_list_cb cb, void *user_data);

/* Ask the agent to wipe its key and stop. Returns 0 if PM_MSG_OK was received, -1 otherwise. */
int pm_agent_stop(const char *socket_path);

#endif /* PASSMAN_AGENT_H */
