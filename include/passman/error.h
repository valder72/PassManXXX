#ifndef PASSMAN_ERROR_H
#define PASSMAN_ERROR_H


// Status codes for the whole project. When function ends with error, use these values instead of "-1"
// For fail check use "if (st != PM_OK)" or "if (st < 0)".

typedef enum {
    PM_OK = 0, // all good
    PM_ERR_ARG = -1, // bad parameter (in any way)
    PM_ERR_NOMEM = -2, // no memory
    PM_ERR_CRYPTO = -3, // libsodium failed to init
    PM_ERR_IO = -4, // writing/reading/renaming/opening etc. to the vault file or terminal has failed
    PM_ERR_FORMAT = -5, // bad version, truncated file, bad magic
    PM_ERR_WRONG_PASS = -6, // wrong password duh
    PM_ERR_CORRUPT = -7, // password is correct but vault is corrupted
    PM_ERR_NOT_FOUND = -8,
    PM_ERR_TOO_BIG = -9,
    PM_ERR_INTR = -10,
    PM_ERR_EOF = -11,
    PM_ERR_LOCKED = -12
} pm_status;

// human readable error message with given status. Always string, never NULL
const char *pm_strerror(pm_status st);

#endif