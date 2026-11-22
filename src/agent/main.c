#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "passman/agent.h"

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <vault> <idle-timeout-seconds>\n", argv[0]);
        return 2;
    }

    char *end;
    errno = 0;
    unsigned long timeout = strtoul(argv[2], &end, 10);
    if (end == argv[2] || *end != '\0' || errno == ERANGE || timeout > 86400) {
        fprintf(stderr, "%s: bad idle timeout '%s'\n", argv[0], argv[2]);
        return 2;
    }

    return pm_agent_run(argv[1], (unsigned)timeout);
}
