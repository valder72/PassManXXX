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

/* Start the agent: bind the socket, drop to serving. Blocks until stopped. */
int pm_agent_run(const char *vault_path, unsigned idle_timeout_sec);

/* Send one request to a running agent. Returns 0 on success. */
int pm_agent_request(const char *socket_path, const char *request,
                     char *reply, size_t reply_size);

/* Ask the agent to forget the key and stop. */
int pm_agent_stop(const char *socket_path);

#endif /* PASSMAN_AGENT_H */
