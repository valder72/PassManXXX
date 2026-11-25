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

## Usage

```bash
passman init                    # create the vault (asks for a master password twice)
passman unlock -t 600           # start pm-agentd if needed, unlock, auto-lock after 10 min idle
passman add github              # e-mail / username / phone (optional) + password
passman add wifi -g -l 32       # same, but generate a 32-character password
passman get github              # show the record
passman get github -p | wl-copy # only the password, for scripts
passman list
passman gen --no-symbols        # random password, no vault needed

passman totp add github         # paste the base32 secret or otpauth:// URI from the site
passman totp github             # current 6-digit code
passman totp list

passman lock                    # agent forgets the key
passman stop                    # agent forgets the key and exits
```

Exit codes: `0` ok, `1` error, `2` bad command line. The vault lives at
`$PASSMAN_VAULT`, else `$XDG_DATA_HOME/passman/vault.pmx`, else
`~/.local/share/passman/vault.pmx`; `-v PATH` overrides it.

When `passman unlock` starts `pm-agentd`, the agent is detached from the
terminal and its error messages go to the socket path plus `.log`, usually
`/run/user/<uid>/passman.sock.log` (rewritten on every start). If you see
"pm-agentd did not start", look there for the reason, for example `mlock`
failing because of `RLIMIT_MEMLOCK`.

## Status

Skeleton: headers and build are in place, implementations are stubs marked
`TODO(crypto)` / `TODO(agent)` / `TODO(cli)`.
