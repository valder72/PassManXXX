#include <stdio.h>

#include "passman/agent.h"

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <vault> <idle-timeout-seconds>\n", argv[0]);
        return 2;
    }
    return pm_agent_run(argv[1], 0);
}
