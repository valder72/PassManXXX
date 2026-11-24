#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>

#include "passman/cli.h"

static char err[160];

/* parse a NULL-terminated list of words; "passman" is prepended as argv[0] */
#define PARSE(args, ...)                                                                       \
    parse_words((args), (const char *[]){"passman", __VA_ARGS__, NULL})

static pm_status parse_words(pm_cli_args *args, const char **words) {
    int argc = 0;
    while (words[argc] != NULL) {
        argc++;
    }
    return pm_cli_parse(argc, (char **)words, args, err, sizeof err);
}

static void no_arguments_means_help(void **state) {
    (void)state;
    pm_cli_args a;
    const char *argv[] = {"passman", NULL};
    assert_int_equal(pm_cli_parse(1, (char **)argv, &a, err, sizeof err), PM_OK);
    assert_int_equal(a.cmd, PM_CMD_HELP);
    assert_int_equal(PARSE(&a, "get", "x", "--help"), PM_OK);
    assert_int_equal(a.cmd, PM_CMD_HELP);
    assert_int_equal(PARSE(&a, "--version"), PM_OK);
    assert_int_equal(a.cmd, PM_CMD_VERSION);
}

static void defaults(void **state) {
    (void)state;
    pm_cli_args a;
    assert_int_equal(PARSE(&a, "unlock"), PM_OK);
    assert_int_equal(a.cmd, PM_CMD_UNLOCK);
    assert_null(a.vault_path);
    assert_int_equal(a.timeout_sec, PM_CLI_DEFAULT_TIMEOUT);
    assert_int_equal(a.length, PM_CLI_DEFAULT_LENGTH);
    assert_false(a.generate);
    assert_false(a.password_only);
}

static void vault_option_forms(void **state) {
    (void)state;
    pm_cli_args a;
    assert_int_equal(PARSE(&a, "-v", "/tmp/a.pmx", "list"), PM_OK);
    assert_string_equal(a.vault_path, "/tmp/a.pmx");
    assert_int_equal(a.cmd, PM_CMD_LIST);

    assert_int_equal(PARSE(&a, "list", "--vault=/tmp/b.pmx"), PM_OK); // after the command too
    assert_string_equal(a.vault_path, "/tmp/b.pmx");

    assert_int_equal(PARSE(&a, "list", "--vault"), PM_ERR_ARG);
    assert_non_null(strstr(err, "needs a value"));
    assert_int_equal(PARSE(&a, "list", "--vault="), PM_ERR_ARG);
}

static void unlock_timeout(void **state) {
    (void)state;
    pm_cli_args a;
    assert_int_equal(PARSE(&a, "unlock", "-t", "60"), PM_OK);
    assert_int_equal(a.timeout_sec, 60);
    assert_int_equal(PARSE(&a, "unlock", "--timeout=0"), PM_OK); // 0 = never lock
    assert_int_equal(a.timeout_sec, 0);

    assert_int_equal(PARSE(&a, "unlock", "-t", "86401"), PM_ERR_ARG);
    assert_int_equal(PARSE(&a, "unlock", "-t", "-5"), PM_ERR_ARG);
    assert_int_equal(PARSE(&a, "unlock", "-t", "10s"), PM_ERR_ARG);
    assert_int_equal(PARSE(&a, "unlock", "-t", ""), PM_ERR_ARG);
    assert_int_equal(PARSE(&a, "unlock", "-t", "99999999999999999999999"), PM_ERR_ARG);
}

static void add_and_get(void **state) {
    (void)state;
    pm_cli_args a;
    assert_int_equal(PARSE(&a, "add", "github"), PM_OK);
    assert_int_equal(a.cmd, PM_CMD_ADD);
    assert_string_equal(a.name, "github");

    assert_int_equal(PARSE(&a, "put", "-g", "-l", "32", "--no-symbols", "-f", "mail"), PM_OK);
    assert_int_equal(a.cmd, PM_CMD_ADD);
    assert_true(a.generate);
    assert_true(a.no_symbols);
    assert_true(a.force);
    assert_int_equal(a.length, 32);
    assert_string_equal(a.name, "mail");

    assert_int_equal(PARSE(&a, "get", "github", "-p"), PM_OK);
    assert_int_equal(a.cmd, PM_CMD_GET);
    assert_true(a.password_only);

    // "--" lets a name start with '-'
    assert_int_equal(PARSE(&a, "get", "--", "-weird-"), PM_OK);
    assert_string_equal(a.name, "-weird-");
}

static void name_count_and_validity(void **state) {
    (void)state;
    pm_cli_args a;
    assert_int_equal(PARSE(&a, "get"), PM_ERR_ARG);
    assert_non_null(strstr(err, "needs a NAME"));
    assert_int_equal(PARSE(&a, "get", "a", "b"), PM_ERR_ARG);
    assert_int_equal(PARSE(&a, "list", "a"), PM_ERR_ARG);
    assert_int_equal(PARSE(&a, "get", "evil\x1b[2J"), PM_ERR_ARG); // terminal escape in a name
    assert_int_equal(PARSE(&a, "add", "totp:github"), PM_ERR_ARG); // reserved prefix
    assert_non_null(strstr(err, "reserved"));

    char longname[260];
    memset(longname, 'a', sizeof longname - 1);
    longname[sizeof longname - 1] = '\0';
    assert_int_equal(PARSE(&a, "get", longname), PM_ERR_ARG);
}

static void options_belong_to_commands(void **state) {
    (void)state;
    pm_cli_args a;
    assert_int_equal(PARSE(&a, "list", "-p"), PM_ERR_ARG);
    assert_non_null(strstr(err, "not valid for 'list'"));
    assert_int_equal(PARSE(&a, "get", "x", "-t", "5"), PM_ERR_ARG);
    assert_int_equal(PARSE(&a, "add", "x", "-l", "30"), PM_ERR_ARG); // -l without -g
    assert_int_equal(PARSE(&a, "gen", "-l", "7"), PM_ERR_ARG);       // below minimum
    assert_int_equal(PARSE(&a, "gen", "-l", "129"), PM_ERR_ARG);     // above maximum
    assert_int_equal(PARSE(&a, "gen", "--bogus"), PM_ERR_ARG);
    assert_non_null(strstr(err, "unknown option"));
    assert_int_equal(PARSE(&a, "-p=1", "get", "x"), PM_ERR_ARG); // flag with a value
    assert_int_equal(PARSE(&a, "frobnicate"), PM_ERR_ARG);
    assert_non_null(strstr(err, "unknown command"));
}

static void totp_subcommands(void **state) {
    (void)state;
    pm_cli_args a;
    assert_int_equal(PARSE(&a, "totp", "github"), PM_OK);
    assert_int_equal(a.cmd, PM_CMD_TOTP_SHOW);
    assert_string_equal(a.name, "github");

    assert_int_equal(PARSE(&a, "totp", "add", "github"), PM_OK);
    assert_int_equal(a.cmd, PM_CMD_TOTP_ADD);
    assert_string_equal(a.name, "github");

    assert_int_equal(PARSE(&a, "totp", "list"), PM_OK);
    assert_int_equal(a.cmd, PM_CMD_TOTP_LIST);

    assert_int_equal(PARSE(&a, "totp", "show", "add"), PM_OK); // a secret called "add"
    assert_int_equal(a.cmd, PM_CMD_TOTP_SHOW);
    assert_string_equal(a.name, "add");

    assert_int_equal(PARSE(&a, "totp"), PM_ERR_ARG);
    assert_int_equal(PARSE(&a, "totp", "add"), PM_ERR_ARG);
    assert_int_equal(PARSE(&a, "totp", "list", "x"), PM_ERR_ARG);
}

static void bad_parameters(void **state) {
    (void)state;
    pm_cli_args a;
    const char *argv[] = {"passman", "list", NULL};
    assert_int_equal(pm_cli_parse(2, (char **)argv, NULL, err, sizeof err), PM_ERR_ARG);
    assert_int_equal(pm_cli_parse(2, NULL, &a, err, sizeof err), PM_ERR_ARG);
    assert_int_equal(pm_cli_parse(2, (char **)argv, &a, NULL, 0), PM_OK); // err is optional
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(no_arguments_means_help),
        cmocka_unit_test(defaults),
        cmocka_unit_test(vault_option_forms),
        cmocka_unit_test(unlock_timeout),
        cmocka_unit_test(add_and_get),
        cmocka_unit_test(name_count_and_validity),
        cmocka_unit_test(options_belong_to_commands),
        cmocka_unit_test(totp_subcommands),
        cmocka_unit_test(bad_parameters),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
