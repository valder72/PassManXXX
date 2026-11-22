# Architecture

```
    passman (CLI)                pm-agentd (agent)              vault file
  ┌────────────────┐   unix   ┌────────────────────┐   AEAD  ┌──────────────┐
  │ parse args     │  socket  │ key in mlock-ed    │ ──────► │ header       │
  │ termios input  │ ◄──────► │ memory, idle timer │         │ records      │
  │ no key material│  0600    │ vault read/write   │ ◄────── │ (encrypted)  │
  └────────────────┘          └────────────────────┘         └──────────────┘
```

- The agent is the only process that holds the derived key; the CLI gets
  plaintext only for the record it asked for.
- Key derivation is Argon2id (libsodium `crypto_pwhash_argon2id`); parameters
  live in the vault header so old vaults stay readable.
- Each record is encrypted separately with XChaCha20-Poly1305; the header is
  authenticated as associated data.
- `mlock` keeps the key and buffers out of swap; `pm_wipe` clears them on lock
  and on idle timeout.

## Module boundaries

| module | owns | must not |
|---|---|---|
| `pm_crypto` | key derivation, AEAD, wiping | do I/O, know about sockets |
| vault | file format, record framing | know about the agent |
| agent | socket protocol, session, mlock | parse CLI arguments |
| cli | args, terminal I/O | hold the key |
