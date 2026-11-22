#include "passman/agent.h"

int pm_agent_run(const char *vault_path, unsigned idle_timeout_sec) {
    (void)vault_path; (void)idle_timeout_sec;
    return -1;
}

int pm_agent_stop(const char *socket_path) {
    (void)socket_path;
    return -1;
}
