#include <string.h>

#include "passman/crypto.h"

void pm_wipe(void *buf, size_t len) {
    if (buf == NULL) return;
    volatile unsigned char *p = buf;
    while (len--) *p++ = 0;
}
