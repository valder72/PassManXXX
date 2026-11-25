cmake_minimum_required(VERSION 3.16)
project(PassManXXX VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
# gnu11, not strict c11: mlock, sockets and termios are POSIX and hidden under -std=c11
set(CMAKE_C_EXTENSIONS ON)
# write build/compile_commands.json so clangd uses the same -I and flags as the compiler
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(PASSMAN_BUILD_TESTS "Build cmocka unit tests" ON)

add_compile_options(-Wall -Wextra -Wpedantic -Werror)
# add_link_options only affects targets defined after it, so it must stay above them
add_link_options(-Wl,-z,relro,-z,now)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)

# ---- crypto core: libsodium only, no file/socket/terminal I/O ----
add_library(pm_crypto STATIC
    src/crypto/kdf.c
    src/crypto/aead.c
    src/crypto/wipe.c
    src/crypto/init.c
    src/crypto/random.c
    src/crypto/keys.c
    src/error.c
)
target_include_directories(pm_crypto PUBLIC include)
target_link_libraries(pm_crypto PUBLIC PkgConfig::SODIUM)

# ---- vault: on-disk container format, file I/O on top of pm_crypto ----
add_library(pm_vault STATIC
    src/vault.c
)
target_link_libraries(pm_vault PUBLIC pm_crypto)

# ---- agent: sockets, mlock, idle timer ----
add_library(pm_agent STATIC
    src/agent/agent.c
    src/agent/ipc.c
)
target_link_libraries(pm_agent PUBLIC pm_vault)

# ---- cli library: argument parsing, terminal I/O ----
add_library(pm_cli STATIC
    src/cli/cli.c
    src/cli/args.c
    src/cli/term.c
    src/cli/totp.c
    src/cli/spawn.c
)
target_include_directories(pm_cli PUBLIC include)
# pthread_sigmask: POSIX leaves sigprocmask unspecified once a process has threads
find_package(Threads REQUIRED)
target_link_libraries(pm_cli PUBLIC pm_agent Threads::Threads)

# ---- executables ----
add_executable(passman src/main.c)
target_link_libraries(passman PRIVATE pm_cli)

add_executable(pm-agentd src/agent/main.c)
target_link_libraries(pm-agentd PRIVATE pm_agent)

# ---- tests (cmocka is only required when they are enabled) ----
if(PASSMAN_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
