#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/resource.h>

#include "passman/agent.h"
#include "passman/crypto.h"

int main(int argc, char **argv) {
    const char *prog = (argc > 0 && argv && argv[0]) ? argv[0] : "pm-agentd";

    struct rlimit no_core = {0, 0};
    (void)setrlimit(RLIMIT_CORE, &no_core);
#ifdef PR_SET_DUMPABLE
    (void)prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif

    pm_status st = pm_crypto_init();
    if (st != PM_OK) {
        fprintf(stderr, "%s: %s\n", prog, pm_strerror(st));
        return 1;
    }

    if (argc < 3) {
        fprintf(stderr, "usage: %s <vault> <idle-timeout-seconds>\n", prog);
        return 2;
    }

    char *end;
    errno = 0;
    unsigned long timeout = strtoul(argv[2], &end, 10);
    if (end == argv[2] || *end != '\0' || errno == ERANGE || timeout > 86400) {
        fprintf(stderr, "%s: bad idle timeout '%s'\n", prog, argv[2]);
        return 2;
    }

    return pm_agent_run(argv[1], (unsigned)timeout);
}
