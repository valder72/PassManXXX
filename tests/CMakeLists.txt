pkg_check_modules(CMOCKA REQUIRED IMPORTED_TARGET cmocka)

# RFC 9106 / RFC 8439 test vectors for the crypto core
add_executable(test_crypto test_crypto.c)
target_link_libraries(test_crypto PRIVATE pm_crypto PkgConfig::CMOCKA)
add_test(NAME crypto COMMAND test_crypto)

add_executable(test_vault test_vault.c)
target_link_libraries(test_vault PRIVATE pm_vault PkgConfig::CMOCKA)
add_test(NAME vault COMMAND test_vault)
set_tests_properties(vault PROPERTIES TIMEOUT 120)