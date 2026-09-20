# ADR 0021 — Client without a database: encrypted files with atomic commit

Date: 2026-09-20 · Status: accepted

## Context
ADR 0020 concentrated storage in a single `Store` in Rust, but the format was SQLCipher: compiling C and OpenSSL for Android and iOS, a separate crate just to isolate OpenSSL from the "libsodium only" rule, pragmas (`secure_delete`, `incremental_vacuum`, WAL, `busy_timeout`) and a C boundary that fuzzers do not cross. A channel's state is small (config, `sk_u`, counter, cursor, ≤ 550 peers, `outbox`) plus the live messages, which expire by TTL; the client makes no query that needs SQL.

## Decision
The client carries no database. Per channel, a directory `<data_dir>/<channel_id hex>/` with two files, both encrypted with `crypto_secretbox` under `K_db` (32 random bytes, wrapped in the Keystore / Secure Enclave, `docs/spec.md` §8):

- `state.bin` = `"PSTA"` ‖ `version` u8 ‖ `nonce` 24 ‖ `secretbox(CBOR(state))`, where `state` = config, `sk_u` seed, send counter, cursor, peers, `outbox`, `log_committed_len` u64 and `log_generation` u32. It is rewritten **atomically** on every commit: write `state.bin.tmp`, `fsync`, `rename` over `state.bin`, `fsync` of the directory.
- `messages.log` = sequence of records `len` u32 BE ‖ `nonce` 24 ‖ `secretbox(CBOR(record))`, append-only; `record` = `received_at`, `expires_local`, `sender_pk`, `counter`, `server_id`, payload or `Unreadable` mark, own or not.

Commit protocol: (1) `append` the new records to the log + `fsync`; (2) atomic write of `state.bin` with the new `log_committed_len`. On opening: read `state.bin`, truncate the log to `log_committed_len` (the surplus bytes belong to an unfinished commit). A corrupt record **within** the committed length → `StoreError::Corrupt`; recovery is re-importing the config and regenerating the identity. TTL purge = compaction: write `messages.log.new` without the expired ones, `state.bin` with the new length and `log_generation + 1`, `rename`. It is done on opening and on unlocking. Leaving the channel = deleting the directory. A `LOCK` file (advisory) in the `data_dir` prevents two processes. Log limit: 64 MiB, the same as the server's per-channel quota.

The server does carry plain SQLite (unencrypted: only opaque blobs, disk encrypted at rest) via `rusqlite` with `bundled`, without `sqlx`.

## Alternatives considered
- SQLCipher: mature, but C + OpenSSL on the client, a permanent exception to AGENTS 2, and atomicity depended on the `BEGIN` semantics of an external library.
- A single file per channel rewritten whole on every commit: trivially atomic, but rewriting up to 64 MiB per message is not acceptable.
- Server without SQLite (per-channel log files or memory only): viable, but swaps a mature dependency for own code with no security gain; memory alone loses up to 30 days of messages on restart.

## Consequences
- Zero C outside libsodium in the whole client. Gone are the `store-sqlite` crate, the OpenSSL exception in `deny.toml`, and all the SQLCipher configuration.
- The atomicity of `commit(WriteBatch)` comes from the file system's `rename`: it is the minimal WAL (~100 lines) and is tested with `FailingStore` and with a test that kills the process between steps (1) and (2).
- The same `Secret<32>` and the same `secretbox` encrypt state and messages; the whole path is fuzzable from Rust.
- Deleting a record is physical (compaction) just as with `secure_delete`; the cryptographic guarantee is the destruction of `K_db`. Per-channel key for cryptographic channel deletion: v2 (`docs/spec.md` §12).
- The client loads the channel into memory (a few MB); there are no queries or search in v1.
- Affected specs: 020-store-files, 023-ttl-purge, 025-identity-regen, 032-storage-ttl (server, `rusqlite`).
