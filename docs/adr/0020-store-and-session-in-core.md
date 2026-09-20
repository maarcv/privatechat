# ADR 0020 — Store and sans-I/O session in the Rust core

Date: 2026-09-20 · Status: accepted

## Context
The spec required persisting "message, anti-replay state and cursor in a single transaction", but storage was a trait implemented on each platform (Room on Android, GRDB on iOS, `rusqlite` on desktop): three different codes for the same transaction, no core test that could prove it, the DB key turned into a JVM/Swift `String` for the `PRAGMA key`, and all the state (plaintext, peers, counters) crossing the FFI boundary on every read. At the same time, the core API exposed nothing to implement the §6 protocol (`ack`, cursor, pagination, `hello → subscribe → ok → push`): the WebSocket state machine would have been written three times (review C, findings C6 and C10). The red team's verdict: "it will fail at the state, not at the cryptography".

## Decision
1. **A single `Store`**, in Rust, in the `store` crate, shared by the three platforms. The trait has a single write operation, `commit(WriteBatch)`, atomic. Kotlin and Swift only unwrap the 32 B key, call the store constructor (`docs/spec.md` §9, spec 027) once and zeroize their bytes; they never touch storage. `Channel` has no state that has not gone through `commit`. One directory, one process. The on-disk format is set by ADR 0021 (the initial version of this ADR said SQLCipher; replaced the same day).
2. **A sans-I/O `Session`** in the core: `on_connect`, `on_frame(bytes) → Vec<Event>`, `outgoing() → Vec<bytes>`. It parses `hello`/`ok`/`push`/`ack`/`error`, manages nonce, subscriptions, cursor and `outbox`, calls `decrypt` and notifies `acked`. The UI opens the TLS socket, passes frames in both directions and reconnects with backoff when it receives `Event::Reconnect`.

## Alternatives considered
- Native store per platform with "idiomatic integration" (Room, GRDB): three transactions, three `BEGIN` semantics, key outside Rust.
- SQLCipher via `rusqlite` in Rust: a single implementation, but C + OpenSSL on the client and a permanent exception to the "libsodium only" rule (see ADR 0021).
- Generic `KeyValue` trait with separate `put`/`get`: cannot express atomicity between message, counter and cursor.
- WS protocol implemented on each client over a flat core API: divergences almost certain in reconnection, pagination and dedupe.

## Consequences
- The critical transaction exists once and is tested once, including a `FailingStore` that fails at commit *n* and checks the state on reopening.
- `store` is a crate separate from `core` because it does I/O (AGENTS 10); it carries no cryptographic dependency of its own, it uses `core::crypto`.
- The storage key `K_db` never leaves Rust once unwrapped; it is exposed as `Secret<32>`.
- No widget or share extension in v1 (a single process opens storage).
- Affected specs: 020-store-files (replaces 020-store-trait), 021-channel-session, 027-core-api, 028-session-sans-io (new).
