#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sodium.h>

#include "passman/vault.h"
#include "passman/crypto.h"
#include "passman/error.h"

#define OFF_VERSION 8u
#define OFF_OPS     12u
#define OFF_MEM     20u
#define OFF_SALT    28u
#define OFF_CHECK   44u
#define HDR_BYTES   76u

#define MAGIC_BYTES (sizeof PM_MAGIC - 1)
_Static_assert(MAGIC_BYTES == OFF_VERSION, "magic is 8 bytes");
_Static_assert(OFF_SALT + PM_SALT_BYTES == OFF_CHECK, "salt ends where check starts");
_Static_assert(OFF_CHECK + PM_CHECK_BYTES == HDR_BYTES, "check ends the header");

static void put_le(uint8_t *p, uint64_t v, size_t n) {
    for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(v >> (8 * i));
}

static uint64_t get_le(const uint8_t *p, size_t n) {
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++) v |= (uint64_t)p[i] << (8 * i);
    return v;
}

static pm_status read_file(const char *path, uint8_t **out, size_t *out_len) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return PM_ERR_IO;

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {close(fd); return PM_ERR_IO;}

    if ((uint64_t)st.st_size > PM_VAULT_MAX_FILE) {close(fd); return PM_ERR_TOO_BIG;}

    size_t len = (size_t)st.st_size;
    uint8_t *buf = malloc(len ? len : 1);
    if (!buf) {close(fd); return PM_ERR_NOMEM;}

    size_t got = 0;
    while(got < len) {
        ssize_t n = read(fd, buf + got, len - got);

        if (n < 0 && errno == EINTR) continue;

        if (n <= 0) {
            free(buf);
            close(fd);
            return PM_ERR_IO;
        }

        got += (size_t)n;
    }

    close(fd);

    *out = buf;
    *out_len = len;
    return PM_OK;
}

static int write_all(int fd, const uint8_t *p, size_t len) {
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0 && errno == EINTR) continue;

        if (n <= 0) return -1;

        p += n;
        len -= (size_t)n;
    }

    return 0;
}

// fsync the directory so the rename/link itself survives a power loss
static int sync_parent_dir(const char *path) {
    const char *slash = strrchr(path, '/');
    char *dir = slash ? strndup(path, slash == path ? 1 : (size_t)(slash - path)) : strdup(".");
    if (!dir) return -1;

    int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    free(dir);

    if (fd < 0) return fd;
    int rc = fsync(fd);
    close(fd);

    return rc;
}

// Write a complete new file next to path, then put it in place in one step, so a crash leaves either the old vault or the new, never half of it; replace == 0: fail if path already exists (link() never overwrites)
static pm_status write_atomic(const char *path, const uint8_t *data, size_t len, int replace) {
    size_t plen = strlen(path);
    char *tmp = malloc(plen + sizeof ".tmp-XXXXXX");
    if (!tmp) return PM_ERR_NOMEM;

    memcpy(tmp, path, plen);
    memcpy(tmp + plen, ".tmp-XXXXXX", sizeof ".tmp-XXXXXX");

    int fd = mkstemp(tmp);
    if (fd < 0) {free(tmp); return PM_ERR_IO;}

    int ok = write_all(fd, data, len) == 0 && fsync(fd) == 0;
    ok = (close(fd) == 0) && ok;

    if (ok) {
        if (replace) {
            ok = rename(tmp, path) == 0;
        } else {
            ok = link(tmp, path) == 0;
            unlink(tmp);
        }
    }
    if (!ok) unlink(tmp);
    free(tmp);

    if (!ok || sync_parent_dir(path) != 0) return PM_ERR_IO;
    return PM_OK;
}

typedef struct {
    const uint8_t *name;
    size_t name_len;
    const uint8_t *secret;
    size_t secret_len;
} record_view;

// reads record and moves off to the next one
static pm_status next_record(const uint8_t *body, size_t len, size_t *off, record_view *r) {
    size_t o = *off;
    if (len - o < 2) return PM_ERR_CORRUPT;

    r->name_len = (size_t)get_le(body + o, 2);
    o += 2;
    if (r->name_len == 0 || r->name_len >= PM_MAX_NAME_LEN || len - o < r->name_len) return PM_ERR_CORRUPT;
    
    r->name = body + o;
    o += r->name_len;

    if (len - o < 2) return PM_ERR_CORRUPT;

    r->secret_len = (size_t)get_le(body + o, 2);
    o += 2;
    
    if (r->secret_len >= PM_MAX_SECRET_LEN || len - o < r->secret_len) return PM_ERR_CORRUPT;

    r->secret = body + o;
    o += r->secret_len;

    if (memchr(r->name, '\0', r->name_len) || memchr(r->secret, '\0', r->secret_len)) return PM_ERR_CORRUPT;

    *off = o;
    return PM_OK;
}

static pm_status validate_body(const uint8_t *body, size_t len) {
    if (len < 4) return PM_ERR_CORRUPT;
    
    uint64_t count = get_le(body, 4);
    size_t off = 4;
    record_view r;

    for (uint64_t i = 0; i < count; i++) {
        pm_status st = next_record(body, len, &off, &r);
        if (st != PM_OK) return st;
    }

    return off == len ? PM_OK : PM_ERR_CORRUPT;
}

typedef struct {
    uint8_t header[HDR_BYTES];
    uint8_t record_key[PM_KEY_BYTES];
    uint8_t *body;          // plain body, sodium_malloc: mlock-ed, wiped on free
    size_t body_len;
} vault_ctx;

static void ctx_free(vault_ctx *v) {
    pm_wipe(v->record_key, sizeof v->record_key);
    sodium_free(v->body);
    v->body = NULL;
    v->body_len = 0;
}

#define MAX_OPSLIMIT 64u
#define MAX_MEMLIMIT (1ull << 30) // 1 gb

static int params_in_range(const pm_kdf_params *p) {
    return p->opslimit <= MAX_OPSLIMIT && p->memlimit <= MAX_MEMLIMIT;
}

static pm_status parse_header(const uint8_t *file, size_t len, pm_kdf_params *params) {
    if (len < HDR_BYTES + PM_NONCE_BYTES + PM_TAG_BYTES) return PM_ERR_FORMAT;

    if (memcmp(file, PM_MAGIC, MAGIC_BYTES) != 0) return PM_ERR_FORMAT; // memcmp here is ok

    if (get_le(file + OFF_VERSION, 4) != PM_VERSION) return PM_ERR_FORMAT;

    params->opslimit = get_le(file + OFF_OPS, 8);
    params->memlimit = get_le(file + OFF_MEM, 8);
    if (params_in_range(params) == 0) return PM_ERR_FORMAT;

    return PM_OK;
}

static pm_status unlock(const uint8_t *file, size_t len, const uint8_t master[PM_KEY_BYTES], vault_ctx *v) {
    pm_kdf_params params;
    pm_status st = parse_header(file, len, &params);
    if (st != PM_OK) return st;

    uint8_t check_key[PM_KEY_BYTES];
    st = pm_derive_subkeys(master, check_key, v->record_key);
    if (st == PM_OK) {
        st = pm_key_check_verify(check_key, file, OFF_CHECK, file + OFF_CHECK);
    }
    pm_wipe(check_key, sizeof check_key);
    
    if (st != PM_OK) {
        ctx_free(v);
        return st;
    }

    memcpy(v->header, file, HDR_BYTES);
    v->body_len = len - HDR_BYTES - PM_NONCE_BYTES - PM_TAG_BYTES;
    v->body = sodium_malloc(v->body_len ? v->body_len : 1);
    if (!v->body) {
        ctx_free(v);
        return PM_ERR_NOMEM;
    }

    size_t plain_len = 0;
    st = pm_open(v->record_key, file + HDR_BYTES, len - HDR_BYTES, file, HDR_BYTES, v->body, v->body_len, &plain_len);
    if (st == PM_OK) st = validate_body(v->body, plain_len);
    if (st != PM_OK) {ctx_free(v); return st == PM_ERR_FORMAT ? PM_ERR_CORRUPT : st;}

    return PM_OK;
}

static pm_status load(const char *path, const uint8_t master[PM_KEY_BYTES], vault_ctx *v) {
    if (!path || !master) return PM_ERR_ARG;
    
    uint8_t *file = NULL;
    size_t len = 0;

    pm_status st = read_file(path, &file, &len);
    if (st != PM_OK) return st;

    st = unlock(file, len, master, v);
    free(file);

    return st;
}

// seal a new plain body under the existing header and write the file
static pm_status store(const char *path, const vault_ctx *v, const uint8_t *body, size_t body_len, int replace) {
    size_t total = HDR_BYTES + PM_SEALED_SIZE(body_len);
    uint8_t *file = malloc(total);
    if (!file) return PM_ERR_NOMEM;

    memcpy(file, v->header, HDR_BYTES);

    size_t sealed_len = 0;
    pm_status st = pm_seal(v->record_key, body, body_len, v->header, HDR_BYTES, file + HDR_BYTES, total - HDR_BYTES, &sealed_len);
    if (st == PM_OK) st = write_atomic(path, file, HDR_BYTES + sealed_len, replace);
    free(file);

    return st;
}

static int name_equals(const record_view *r, const char *name, size_t name_len) {
    return r->name_len == name_len && memcmp(r->name, name, name_len) == 0;
}

pm_status pm_vault_create(const char *path, const char *password, const pm_kdf_params *params) {
    if (!path || !password || password[0] == '\0') return PM_ERR_ARG;

    pm_kdf_params p;
    if (params) {
        p = *params;
    }
    else {
        pm_status cst = pm_kdf_calibrate(PM_VAULT_DEFAULT_MEMLIMIT, PM_VAULT_DEFAULT_TARGET_MS, &p);
        if (cst != PM_OK) return cst;
    }

    if (params_in_range(&p) == 0) return PM_ERR_ARG;

    vault_ctx v = {0};
    memcpy(v.header, PM_MAGIC, MAGIC_BYTES);
    put_le(v.header + OFF_VERSION, PM_VERSION, 4);
    put_le(v.header + OFF_OPS, p.opslimit, 8);
    put_le(v.header + OFF_MEM, p.memlimit, 8);
    pm_random(v.header + OFF_SALT, PM_SALT_BYTES);

    uint8_t master[PM_KEY_BYTES], check_key[PM_KEY_BYTES];
    pm_status st = pm_kdf_derive(password, strlen(password), v.header + OFF_SALT, &p, master);
    if (st == PM_OK) st = pm_derive_subkeys(master, check_key, v.record_key);
    if (st == PM_OK) st = pm_key_check_compute(check_key, v.header, OFF_CHECK, v.header + OFF_CHECK);
    
    pm_wipe(master, sizeof master);
    pm_wipe(check_key, sizeof check_key);

    if (st == PM_OK) {
        uint8_t empty[4] = {0};
        st = store(path, &v, empty, sizeof empty, 0);
    }
    ctx_free(&v);
    
    return st;
}

pm_status pm_vault_open(const char *path, const char *password, uint8_t key[PM_KEY_BYTES]) {
    if (!path || !password || !key) return PM_ERR_ARG;

    uint8_t *file = NULL;
    size_t len = 0;
    
    pm_status st = read_file(path, &file, &len);
    if (st != PM_OK) return st;

    pm_kdf_params params;
    st = parse_header(file, len, &params);

    if (st == PM_OK) {
        st = pm_kdf_derive(password, strlen(password), file + OFF_SALT, &params, key);
        if (st == PM_ERR_ARG) st = PM_ERR_FORMAT;
    }

    if (st == PM_OK) {
        vault_ctx v = {0};
        st = unlock(file, len, key, &v);
        ctx_free(&v);
    }
    free(file);

    if (st != PM_OK) pm_wipe(key, PM_KEY_BYTES);
    
    return st;
}

pm_status pm_vault_put(const char *path, const uint8_t key[PM_KEY_BYTES], const char *name, const char *secret) {
    if (!name || !secret) return PM_ERR_ARG;
    
    size_t name_len = strlen(name), secret_len = strlen(secret);
    if (name_len == 0) return PM_ERR_ARG;
    if (name_len >= PM_MAX_NAME_LEN || secret_len >= PM_MAX_SECRET_LEN) return PM_ERR_TOO_BIG;

    vault_ctx v = {0};
    pm_status st = load(path, key, &v);
    if (st != PM_OK) return st;

    size_t max_len = v.body_len + 2 + name_len + 2 + secret_len; // everyting other + this record
    if (HDR_BYTES + PM_SEALED_SIZE(max_len) > PM_VAULT_MAX_FILE) {ctx_free(&v); return PM_ERR_TOO_BIG;}

    uint8_t *nb = sodium_malloc(max_len);
    if (!nb) {ctx_free(&v); return PM_ERR_NOMEM;}

    uint64_t count = get_le(v.body, 4), kept = 0;
    size_t off = 4, out = 4;
    record_view r;
    for (uint64_t i = 0; i < count; i++) {
        size_t start = off;
        if (next_record(v.body, v.body_len, &off, &r) != PM_OK) {sodium_free(nb); ctx_free(&v); st = PM_ERR_CORRUPT; return st;}
        if (!name_equals(&r, name, name_len)) {
            memcpy(nb + out, v.body + start, off - start);
            out += off - start;
            kept++;
        }
    }
    put_le(nb + out, name_len, 2);
    out += 2;
    memcpy(nb + out, name, name_len);
    out += name_len;
    put_le(nb + out, secret_len, 2);
    out += 2;
    memcpy(nb + out, secret, secret_len);
    out += secret_len;
    put_le(nb, kept + 1, 4);

    st = store(path, &v, nb, out, 1);
    sodium_free(nb);
    ctx_free(&v);
    
    return st;
}

pm_status pm_vault_get(const char *path, const uint8_t key[PM_KEY_BYTES], const char *name, char *out, size_t out_size) {
    if (!name || !out || out_size == 0) return PM_ERR_ARG;

    vault_ctx v = {0};
    pm_status st = load(path, key, &v);
    if (st != PM_OK) return st;

    size_t name_len = strlen(name);
    uint64_t count = get_le(v.body, 4);
    size_t off = 4;
    record_view r;
    st = PM_ERR_NOT_FOUND;

    for (uint64_t i = 0; i < count; i++) {
        if (next_record(v.body, v.body_len, &off, &r) != PM_OK) {st = PM_ERR_CORRUPT; break;}
        if (name_equals(&r, name, name_len)) {
            if (r.secret_len >= out_size) {
                st = PM_ERR_TOO_BIG;
            } else {
                memcpy(out, r.secret, r.secret_len);
                out[r.secret_len] = '\0';
                st = PM_OK;
            }
            break;
        }
    }

    ctx_free(&v);
    return st;
}

pm_status pm_vault_list(const char *path, const uint8_t key[PM_KEY_BYTES], pm_vault_list_cb cb, void *user_data) {
    if (!cb) return PM_ERR_ARG;

    vault_ctx v = {0};
    pm_status st = load(path, key, &v);
    if (st != PM_OK) return st;

    uint64_t count = get_le(v.body, 4);
    size_t off = 4;
    record_view r;
    char name[PM_MAX_NAME_LEN];

    for (uint64_t i = 0; i < count; i++) {
        if (next_record(v.body, v.body_len, &off, &r) != PM_OK) {st = PM_ERR_CORRUPT; break;}
        memcpy(name, r.name, r.name_len);
        name[r.name_len] = '\0';

        if (cb(name, user_data) != 0) break;
    }

    ctx_free(&v);
    return st;
}
