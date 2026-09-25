# ADR 0035 — Bind every log entry to its place and name channel directories by a keyed hash

Date: 2026-09-25 · Status: accepted

## Context
ADR 0021 fixes the client storage: per channel, a `state.bin` rewritten atomically and an append-only `messages.log`, both sealed with `crypto_secretbox` under `K_db`, in a directory named by the `channel_id` in hex. Writing spec 020-store-files showed three gaps. Each log entry is sealed on its own, so someone who can write the disk without `K_db` could reorder, repeat or splice entries, or carry entries over from before a compaction, and every entry would still open. A compaction interrupted between writing the new state and renaming the new log has no way to tell the two logs apart. And the directory names reveal to a forensic copy of the device which channels it holds, which the server operator can link to the IPs that listen to them (`docs/spec.md` §2).

## Decision
`messages.log` starts with a 9-byte header `"PLOG"` ‖ `store_version` ‖ `generation` u32, every log record carries its file's `generation` and its own byte `offset` inside the box and is refused elsewhere, each channel directory is named by the first 16 bytes of `keyed_hash(K_db, "privatechat/dir/v1" ‖ channel_id)` in hex, and each directory's files are sealed under `keyed_hash(K_db, "privatechat/store/v1" ‖ name)` and the settings under `keyed_hash(K_db, "privatechat/settings/v1")`, never under `K_db` itself; the exact layout is spec 020-store-files.

## Alternatives considered
- A hash chain over the entries: it also detects truncation, but truncation to an earlier committed length together with an older `state.bin` is a rollback no per-file mechanism prevents, and a chain costs a hash per entry and a harder compaction.
- An AEAD with associated data instead of `secretbox`: the same binding, with a second primitive for storage and no gain over putting the two numbers inside the box.
- Keeping the plain `channel_id` as the directory name: simpler, but it leaks which channels a seized device belongs to.

## Consequences
- An entry opens only at its own offset in its own generation of its own directory; a state or log copied into another channel's directory does not open; a compaction interrupted after its state write completes on the next open.
- Rolling back both files to an older commit is still possible for whoever can write the disk; documented in spec 020-store-files as inside the desktop model and excluded by the mobile sandbox.
- Listing channels needs `K_db`, which the store holds whenever it is open.
- Refines ADR 0021. Affected specs: 020-store-files.
