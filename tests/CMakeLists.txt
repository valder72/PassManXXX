pkg_check_modules(CMOCKA REQUIRED IMPORTED_TARGET cmocka)

# RFC 9106 / RFC 8439 test vectors for the crypto core
add_executable(test_crypto test_crypto.c)
target_link_libraries(test_crypto PRIVATE pm_crypto PkgConfig::CMOCKA)
add_test(NAME crypto COMMAND test_crypto)

add_executable(test_vault test_vault.c)
target_link_libraries(test_vault PRIVATE pm_vault PkgConfig::CMOCKA)
add_test(NAME vault COMMAND test_vault)

add_executable(test_cli test_cli.c)
find_package(Threads REQUIRED)
# openpty (libutil) and a helper thread drive pm_read_password through a real pty
target_link_libraries(test_cli PRIVATE pm_cli PkgConfig::CMOCKA Threads::Threads util)
add_test(NAME cli COMMAND test_cli)
