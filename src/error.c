#include "passman/error.h"

const char *pm_strerror(pm_status st) {
    switch (st) {
        case PM_OK: return "ok";
        case PM_ERR_ARG: return "invalid argument";
        case PM_ERR_NOMEM: return "out of memory";
        case PM_ERR_CRYPTO: return "cryptographic library failure";
        case PM_ERR_IO: return "input/output error";
        case PM_ERR_FORMAT: return "vault file is not a valid PassManXXX vault";
        case PM_ERR_WRONG_PASS: return "wrong password";
        case PM_ERR_CORRUPT: return "vault is corrupted or was tampered with";
        case PM_ERR_NOT_FOUND: return "no such entry";
        case PM_ERR_TOO_BIG: return "value is too large";
        case PM_ERR_INTR: return "interrupted";
        case PM_ERR_EOF: return "unexpected end of input";
    }
    return "unknown error";
}