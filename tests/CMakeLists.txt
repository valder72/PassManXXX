pkg_check_modules(CMOCKA REQUIRED IMPORTED_TARGET cmocka)

# RFC 9106 / RFC 8439 test vectors for the crypto core
add_executable(test_crypto test_crypto.c)
target_link_libraries(test_crypto PRIVATE pm_crypto PkgConfig::CMOCKA)
add_test(NAME crypto COMMAND test_crypto)

add_executable(test_vault test_vault.c)
target_link_libraries(test_vault PRIVATE pm_vault PkgConfig::CMOCKA)
add_test(NAME vault COMMAND test_vault)

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
