#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "passman/crypto.h"
#include "passman/error.h"

static void init_is_idempotent(void **state) {
    (void)state;
    assert_int_equal(pm_crypto_init(), PM_OK);
    assert_int_equal(pm_crypto_init(), PM_OK); // two calls are safe
}

static void strerror_never_null(void **state) {
    (void)state;
    for (int st = PM_ERR_TOO_BIG; st <= PM_OK; st++) {
        assert_non_null(pm_strerror((pm_status)st));
    }
    assert_string_equal(pm_strerror((pm_status)-67), "unknown error");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(init_is_idempotent),
        cmocka_unit_test(strerror_never_null),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
