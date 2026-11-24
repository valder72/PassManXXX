#include <sodium.h>

#include "passman/crypto.h"

void pm_random(uint8_t *buf, size_t len) {
    if (buf == NULL || len == 0) {
        return;
    }
    
    randombytes_buf(buf, len);
}