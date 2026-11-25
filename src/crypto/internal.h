#ifndef PASSMAN_CRYPTO_INTERNAL_H
#define PASSMAN_CRYPTO_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

// do [a, a + alen) and [b, b + blen) share at least one byte
static inline int pm_overlaps(const void *a, size_t alen, const void *b, size_t blen) {
    uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
    return alen != 0 && blen != 0 && x < y + blen && y < x + alen;
}

#endif