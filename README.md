# PassManXXX

Local CLI secret manager with modern cryptography, no cloud.

| Role | Owner | Area |
|---|---|---|
| Crypto core | Vladyslav | Argon2id KDF, XChaCha20-Poly1305, vault format |
| Agent & IPC | Volodymyr | background agent, Unix socket, mlock |
| CLI & tests | Dmytro | terminal client (termios), TOTP, cmocka tests |

## Layout

```
include/passman/   public headers, one per module
src/crypto/        KDF, AEAD helpers, secure wipe   (no I/O)
src/vault.c        on-disk container format
src/agent/         socket server + request/response code
src/cli/           argument parsing, termios input
tests/             cmocka unit tests
docs/              architecture notes
scripts/           helper scripts (ci, demo)
```

`pm_crypto` has no OS dependencies beyond libsodium, so it can be unit-tested
and reviewed on its own. `pm_agent` adds sockets and memory locking. The CLI
never touches key material directly: it talks to the agent.

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Dependencies: `libsodium-dev`, `libcmocka-dev`, `cmake`, `pkg-config`.

## Status

Skeleton: headers and build are in place, implementations are stubs marked
`TODO(crypto)` / `TODO(agent)` / `TODO(cli)`.
