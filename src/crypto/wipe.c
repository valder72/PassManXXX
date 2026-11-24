#include <sodium.h>

#include "passman/crypto.h"

void pm_wipe(void *buf, size_t len) {
    if (buf == NULL) {
        return;
    }

    sodium_memzero(buf, len);
}
