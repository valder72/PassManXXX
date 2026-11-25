# PassManXXX

Local command-line password and 2FA manager with no cloud or external servers.

| Role | Owner | Area |
|---|---|---|
| Crypto core & Vault | hyperGG32 | encryption, key derivation, vault file format |
| Agent & IPC | vlader72 | background daemon, local Unix socket, memory protection |
| CLI & tests | DimaProTinkerPlayer | terminal client, hidden password input, TOTP, unit tests |

---

## How It Works (Visual Overview)

```text
  User in Terminal
           │
           │  1. Types a command and password (hidden on screen)
           ▼
   ┌───────────────┐
   │  passman (CLI)│  ── never keeps the master key
   └───────┬───────┘
           │  2. Sends a request over a local Unix socket (owner-only access)
           ▼
   ┌──────────────────┐
   │pm-agentd (Agent) │  ── holds the key in locked RAM (mlock)
   └───────┬──────────┘     and wipes it automatically after idle timeout
           │  3. Reads or updates encrypted records
           ▼
   ┌───────────────┐
   │   vault.pmx   │  ── encrypted file on disk (unreadable without the password)
   └───────────────┘
```

### Simple Explanation of Each Part

- **CLI (`passman`)** — the program you run in your terminal. It reads your command (`init`, `add`, `get`, `totp`, etc.), asks for passwords without showing them on screen, sends the request to the agent, and prints the result. It never stores the master key itself.
- **Agent (`pm-agentd`) & IPC** — a small background helper started by `unlock`. It unlocks the vault once and keeps the key in protected RAM so you do not have to type your master password before every `get` or `add`. If you do nothing for the configured timeout (5 minutes by default), it wipes the key from memory automatically. Communication with the CLI happens locally over a socket file accessible only to your user.
- **Vault (`vault`) & Crypto Core (`pm_crypto`)** — handle safe storage on disk. They turn your master password into an encryption key and encrypt each record so nobody can read or silently tamper with the file without the password.

---

## Project Layout

```text
include/passman/   public headers with module interfaces
src/crypto/        key handling, encryption, memory wiping
src/vault.c        reading and writing the encrypted vault file
src/agent/         background daemon (pm-agentd) and socket messaging
src/cli/           command-line client (passman), TOTP, terminal input
tests/             cmocka unit tests
docs/              short architecture notes
```

---

## Setup & Build (Linux)

### 1. Install dependencies

```bash
sudo apt-get update
sudo apt-get install -y libsodium-dev libcmocka-dev cmake pkg-config build-essential
```

### 2. Build and run tests

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j
ctest --test-dir build --output-on-failure
```

After building, two binaries are created in `build/`:
- `build/passman` — the CLI tool you interact with;
- `build/pm-agentd` — the background agent started automatically by `passman unlock`.

To run them without typing `./build/` every time, add `build/` to your `PATH` or copy both binaries to `~/.local/bin/`:

```bash
mkdir -p ~/.local/bin
cp build/passman build/pm-agentd ~/.local/bin/
```

---

## Usage

### Getting Started

```bash
# 1. Create a new vault (asks for a master password twice)
passman init

# 2. Start the agent and unlock the vault (auto-locks after 10 min idle)
passman unlock -t 600
```

### Storing and Reading Passwords

```bash
# Add a record manually (site + optional email/username/phone + password)
passman add github

# Add a record with an auto-generated 32-character password
passman add wifi -g -l 32

# Show the full record
passman get github

# Print only the password (useful for copying to clipboard or scripts)
passman get github -p | wl-copy

# List stored record names (no passwords shown)
passman list

# Generate a random password without saving it to a vault
passman gen --no-symbols
```

### Two-Factor Codes (2FA / TOTP)

```bash
# Save a secret (base32 key or otpauth:// URI from the website)
passman totp add github

# Print the current 6-digit code
passman totp github

# List stored 2FA secret names
passman totp list
```

### Managing the Agent & Session

```bash
# Check if the agent is running
passman status

# Lock the vault (agent wipes the key from memory but stays running)
passman lock

# Stop the agent completely (wipes the key and exits)
passman stop
```

---

## Configuration & Defaults

- **Vault file path:** `$PASSMAN_VAULT`, else `$XDG_DATA_HOME/passman/vault.pmx`, else `~/.local/share/passman/vault.pmx`. Use `-v PATH` to override for a command.
- **Agent socket path:** `$PASSMAN_SOCKET`, else `$XDG_RUNTIME_DIR/passman.sock`, else `/run/user/<uid>/passman.sock`, or `/tmp/passman-<uid>/passman.sock` if `/run/user` is unavailable (for example, in containers).
- **Agent log file:** if `passman unlock` fails to start `pm-agentd`, the agent error output is saved to `<socket_path>.log`.
- **Exit codes (`passman`):** `0` ok, `1` error, `2` invalid command-line arguments.
