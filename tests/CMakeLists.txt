pkg_check_modules(CMOCKA REQUIRED IMPORTED_TARGET cmocka)

# RFC 9106 / RFC 8439 test vectors for the crypto core
add_executable(test_crypto test_crypto.c)
target_link_libraries(test_crypto PRIVATE pm_crypto PkgConfig::CMOCKA)
add_test(NAME crypto COMMAND test_crypto)

add_executable(test_vault test_vault.c)
target_link_libraries(test_vault PRIVATE pm_vault PkgConfig::CMOCKA)
add_test(NAME vault COMMAND test_vault)
set_tests_properties(vault PROPERTIES TIMEOUT 120)

add_executable(test_cli test_cli.c)
find_package(Threads REQUIRED)
# openpty (libutil) and a helper thread drive pm_read_password through a real pty
target_link_libraries(test_cli PRIVATE pm_cli PkgConfig::CMOCKA Threads::Threads util)
add_test(NAME cli COMMAND test_cli)

add_executable(test_ipc test_ipc.c)
target_include_directories(test_ipc PRIVATE ${CMAKE_SOURCE_DIR}/src/agent)
target_link_libraries(test_ipc PRIVATE pm_agent PkgConfig::CMOCKA)
target_link_options(test_ipc PRIVATE -Wl,--wrap=pm_wipe)
add_test(NAME ipc COMMAND test_ipc)

add_executable(test_agent test_agent.c)
target_link_libraries(test_agent PRIVATE pm_agent PkgConfig::CMOCKA)
target_link_options(test_agent PRIVATE
    -Wl,--wrap=pm_wipe
    -Wl,--wrap=pm_vault_open
    -Wl,--wrap=pm_vault_put
    -Wl,--wrap=pm_vault_get
    -Wl,--wrap=pm_vault_list
)
add_test(NAME agent COMMAND test_agent)

# TOTP: RFC 4226 / RFC 6238 / RFC 4648 / RFC 2202 vectors
add_executable(test_totp test_totp.c)
target_link_libraries(test_totp PRIVATE pm_cli PkgConfig::CMOCKA)
add_test(NAME totp COMMAND test_totp)

# CLI argument parser (pure function)
add_executable(test_cli_args test_cli_args.c)
target_link_libraries(test_cli_args PRIVATE pm_cli PkgConfig::CMOCKA)
add_test(NAME cli_args COMMAND test_cli_args)

# CLI commands against a fake agent and scripted input
add_executable(test_cli_cmd test_cli_cmd.c)
target_link_libraries(test_cli_cmd PRIVATE pm_cli PkgConfig::CMOCKA)
target_link_options(test_cli_cmd PRIVATE
    -Wl,--wrap=pm_agent_request
    -Wl,--wrap=pm_agent_list
    -Wl,--wrap=pm_agent_stop
    -Wl,--wrap=pm_read_password
    -Wl,--wrap=pm_read_line
    -Wl,--wrap=pm_cli_spawn_agent
    -Wl,--wrap=pm_vault_create
    -Wl,--wrap=time
)
add_test(NAME cli_cmd COMMAND test_cli_cmd)
