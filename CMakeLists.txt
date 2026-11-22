cmake_minimum_required(VERSION 3.16)
project(PassManXXX VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_compile_options(-Wall -Wextra -Wpedantic -Werror)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
pkg_check_modules(CMOCKA REQUIRED IMPORTED_TARGET cmocka)

# ---- crypto core: no I/O, no OS specifics besides libsodium ----
add_library(pm_crypto STATIC
    src/crypto/kdf.c
    src/crypto/aead.c
    src/crypto/wipe.c
    src/vault.c
)
target_include_directories(pm_crypto PUBLIC include)
target_link_libraries(pm_crypto PUBLIC PkgConfig::SODIUM)

# ---- agent: sockets, mlock, idle timer ----
add_library(pm_agent STATIC
    src/agent/agent.c
    src/agent/ipc.c
)
target_include_directories(pm_agent PUBLIC include)
target_link_libraries(pm_agent PUBLIC pm_crypto)

# ---- executables ----
add_executable(passman src/main.c src/cli/cli.c src/cli/term.c)
target_link_libraries(passman PRIVATE pm_agent pm_crypto)

add_executable(pm-agentd src/agent/main.c)
target_link_libraries(pm-agentd PRIVATE pm_agent pm_crypto)

# ---- tests ----
enable_testing()
add_subdirectory(tests)

# ---- hardening ----
add_link_options(-Wl,-z,relro,-z,now)
