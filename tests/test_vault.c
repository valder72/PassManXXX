#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "passman/vault.h"

/* TODO(crypto): RFC 9106 KDF vectors and XChaCha20-Poly1305 round-trips */
static void placeholder(void **state) {
    (void)state;
    assert_true(1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(placeholder),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
