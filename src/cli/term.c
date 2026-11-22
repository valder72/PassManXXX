#include <stddef.h>

#include "passman/cli.h"

int pm_read_password(const char *prompt, char *buf, size_t buf_size) {
    (void)prompt; (void)buf; (void)buf_size;
    return -1;
}
