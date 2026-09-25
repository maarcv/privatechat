# 025 — Identity regeneration and the pending retirement

Status: draft
Phase: 2
Related ADRs: 0007, 0016, 0019, 0029, 0033, 0034
Depends on: 021-channel-session, 024-key-retired
Blocks: 027-core-api, 028-session-sans-io
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

"Regenerate my key" replaces the user's key in one channel with a fresh one that has no link to the old (ADR 0007), and tells the others to stop trusting the old one with a `key_retired` signed by it (ADR 0016). It is the answer to the own-key alert, to an exhausted counter and to a read-only channel, so it must never be refused for lack of room. The retirement must arrive even when the user regenerates offline (ADR 0034): the old `sk_u` is kept only to re-seal that one message when it would otherwise leave stale, and is erased when the server acknowledges it in time. `docs/spec.md` §4 "Send counter" and §7 "Key regeneration" describe the flow; this spec implements it.

One's own old keys are not peers: they go to a short list of their own (`own_old_keys`, spec 020-store-files), so that later echoes of their blobs are `RetiredKey` (ADR 0029) without taking a place among the peers.

**In plain words.** You get a new key, and the old one writes one last message, "this key is retired", which waits in the queue behind any message the old key had not sent yet. The device keeps the old key for that single message: if it has been waiting so long that nobody would accept it, the device signs it again with a fresh date. Once the server confirms it arrived in time, the old key is wiped. Meanwhile the channel shows "retirement pending". The device remembers your last sixteen old keys, so their echoes are recognised.

## Requirements

- R1 `regenerate_identity(now)` MUST return `Error::RetirementPending` while `retiring_seed` is present, and otherwise commit, in one commit, first applying to the old key's state any own-key values or pending removal that spec 021-channel-session R19 holds in memory (overtaken entries removed with their records, outcomes queued as `NotDelivered`) and clearing them — when that fails with `LogFull`, retried once without the removal, the held current-key counter moving to `old_key_overtaken_through` since those entries become `under_retired_key`, so that regeneration is never refused for room — then: the old `pk_u` appended to `own_old_keys` with `retired_at = now`, dropping, when there are already 16, the oldest entry whose `retired_at + 2·(ttl_ms + 360 000) < now`, or else the oldest; `retiring_seed` = the old seed; a new `identity_seed` from `Secret::random`; `identity_epoch + 1`; `send_counter = 0`; `own_key_used_elsewhere` and `read_only` cleared; every ordinary `outbox` entry marked `under_retired_key`; and the `key_retired` entry of R2 appended at the end of the `outbox`. It MUST NOT be refused by any peer limit.
- R2 The `key_retired` entry MUST be sealed with the old key, `counter = KEY_RETIRED_COUNTER` (spec 013-wire-message), `sent_at = now − now mod 60 000`, a fresh nonce and a fresh `client_ref`, `kind` 1 and `under_retired_key` true, in the `outbox` slot kept for it (spec 020-store-files), so it never fails with `OutboxFull`.
- R3 From the commit of R1 on, the kept signatures of the old key MUST NOT be compared: spec 021-channel-session R13 compares only those of the current `identity_epoch`, and every echo of the old key is `RetiredKey` at step 5 (ADR 0029, 0034). They stay in the log, inert, until their `purge_at`.
- R4 `outbox(now, in_flight, withhold_current)` MUST, whatever `withhold_current`, before its stale check, re-seal the pending `key_retired` whenever `now − now mod 60 000` differs from its `sent_at`, earlier or later, with that `sent_at`, a fresh nonce and a fresh `client_ref`, replacing the entry in place, in the commit of that `outbox` call (except as spec 021-channel-session R22 says when that commit fails: stale entries counted as gone, one copy re-sealed in memory per minute under a fresh `client_ref`, so that only a committed copy completes the retirement); the entry MUST keep its position, a copy in flight MUST NOT be re-sealed, and `expire_outbox` (spec 021-channel-session R23) never re-seals, so that a device offline does not rewrite its state every minute. `outbox` MUST NOT hand out the `key_retired` while an ordinary entry `under_retired_key` is still in the `outbox` (entries covered by a held removal of spec 021-channel-session R19 counting as gone), so that the old key's messages always arrive before its retirement.
- R5 `acked` of the current `client_ref` of the stored `key_retired` entry MUST, when `|received_at − sent_at| ≤ ttl_ms + 360 000`, remove the entry and `retiring_seed` in one commit, keeping no signature, and return `AckOutcome::RetirementDelivered`; for a copy re-sealed only in memory (spec 021-channel-session R22) it MUST return `Ignored` with that copy's `sent_at` and commit nothing; outside that window, and for any earlier `client_ref` of it, it MUST change nothing, commit nothing and return `AckOutcome::Ignored`.
- R6 `status().retirement_pending` MUST be true exactly while `retiring_seed` is present, and `own_old_keys()` MUST return the list of R1 with each key's `retired_at`.
- R7 The old `sk_u` MUST be used for nothing but R2 and R4, and MUST be dropped from memory in the commit of R5.
- R8 `regenerate_identity`, the re-seal of R4 and the `acked` of R5 MUST each have a `FailingStore` test that fails its commit and checks the reopened state.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| Regeneration while a retirement is pending | not allowed | `RetirementPending` |
| `own_old_keys` | 0..=16 | one whose blobs nobody accepts any more dropped first, else the oldest |
| `outbox` | the reserved slot always free for the `key_retired` | not reachable |

## Interface

```
crates/core/src/session/regen.rs          R1–R8
crates/core/src/session/regen/tests.rs    s025_* tests
```

```rust
pub struct OldKey { pub pk: PeerId, pub retired_at: u64 }

impl Channel {   // pub(crate); spec 027-core-api exposes them through Device
    pub(crate) fn regenerate_identity(&mut self, now: u64) -> Result<(), Error>;
    pub(crate) fn own_old_keys(&self) -> Vec<OldKey>;
}
```

`core::Error` gains `RetirementPending`.

**PR slices** (AGENTS 14): (a) regeneration and the old keys (R1–R3, R6, R7; T01–T03, T06, T07 and the regeneration half of T08); (b) the pending retirement in `outbox` and its `ack` (R4, R5; T04, T05 and the rest of T08). Each test clause lands in the slice that implements the last behaviour it needs; the list above names where each requirement is implemented, and a test that spans slices is completed clause by clause.

## Security

- The new key has no link to the old (ADR 0007): the others see an unknown and must verify it again.
- The old `sk_u` outlives the regeneration only to re-seal its own retirement (ADR 0034); a thief already has it, so keeping it gives him nothing.
- A late `ack` changes nothing (R5), so a server that answers late cannot make the device drop the old key before the retirement has arrived in time; re-sealing happens at most once per minute of `now`, and in either direction of the clock (R4), so a clock corrected after the regeneration does not leave the copy stuck in the future.
- Regeneration is never refused for room (R1): the one remedy to a stolen key cannot be blocked by filling the peer list. An old key dropped from the sixteen of `own_old_keys` is, whenever possible, one whose blobs nobody accepts any more (R1); only sixteen regenerations within one TTL can drop a younger one, whose echoes then appear to this device as an unknown peer.
- A server that never acknowledges the retirement in time — or a device clock off by more than the margin — keeps it pending for ever; spec 028-session-sans-io holds it between re-seals so that it cannot flood the connection, and only `leave` ends it. Documented.
- Refusing a second regeneration while one is pending (R1) keeps a single old key in memory; the channel card shows why the button is disabled, and the client warns before leaving a channel with a retirement pending.

## Public API changes

None directly: spec 027-core-api exposes `regenerate_identity(now)` and `own_old_keys()` through `Device`, with `Error::RetirementPending`.

## Test cases

- T01 (covers R1): `s025_t01_r01_regeneration_commit`: one commit; the old `pk` in `own_old_keys`; epoch + 1; `send_counter` 0; the event and `read_only` cleared; with 550 peers it still succeeds; a second call → `RetirementPending`, `commits = 0`; a seventeenth regeneration drops the oldest old key whose blobs have all expired, or else the oldest; with values held in memory after a foreign `key_retired` (by `Io`, or by `LogFull` with room freed since) and entries 10 and 11 overtaken → the regeneration commit removes 10 and 11 as not delivered; with the log still full → regeneration succeeds, 10 and 11 kept as `under_retired_key` and held from `outbox` by `old_key_overtaken_through`, and the `key_retired` handed out while they are held; and the new key is neither `read_only` nor exhausted, with no alert; the full-log regeneration, then a reopen carrying `held_own_key()` → no alert.
- T02 (covers R2): `s025_t02_r02_retirement_sealed`: the entry opens with the old `pk` at counter `2^64 − 1` as a `key_retired`; with 31 ordinary entries it still fits, and is handed out only after the last of them leaves the `outbox`.
- T03 (covers R3): `s025_t03_r03_old_echoes_are_retired`: an echo of a blob sealed before regeneration → `RetiredKey`, no own-key event, `commits = 0`; after reopening, too.
- T04 (covers R4, R5): `s025_t04_r04_reseal`: `outbox` in the same minute hands out the same bytes; one minute later a new nonce, `sent_at` and `client_ref`, same position; with `now` one hour before `sent_at` it is re-sealed too; a copy in flight is not re-sealed; with `fail_commits`, a stale entry `under_retired_key` and a `key_retired` sealed two minutes ago → no commit, `store_error` set, the stale entry not handed out, the `key_retired` handed out re-sealed with a fresh nonce and a fresh `client_ref`, unchanged in memory; a second call in the same minute → the same copy, none while it is in flight; an `ack` of its `client_ref` → `Ignored` with its `sent_at`, the retirement still pending; with `fail_commits` and `old_key_overtaken_through` covering entries 300 and 301 → the `key_retired` handed out re-sealed in memory while they are held.
- T05 (covers R5): `s025_t05_r05_ack_erases_old_key`: in-time `ack` → `RetirementDelivered`, entry and `retiring_seed` gone; late `ack` → `Ignored`, `commits = 0`; an `ack` whose `received_at` is `sent_at − ttl_ms − 360 001` → `Ignored`, `commits = 0`, `retiring_seed` kept; `ack` of the previous copy → `Ignored`, `commits = 0`.
- T06 (covers R6): `s025_t06_r06_pending_flag_and_old_keys`: true after R1, false after R5, and after reopening the store in between; `own_old_keys` lists the old key with its time.
- T07 (covers R7): `s025_t07_r07_old_key_only_for_retirement`: after regeneration every ordinary `encrypt` is sealed with the new key; the state written by R5 holds no old seed.
- T08 (covers R8): `s025_t08_r08_failing_store`: `regenerate_identity`, a re-sealing `outbox` and the delivering `acked`, each under a `FailingStore` → the reopened state is the one before.

## Vectors

None of its own: the blob is the 013 `key_retired` layout; the flow is unit tests over state.

## Acceptance criterion

`cargo test -p privatechat-core s025_` green; clippy and the documentation lint green.

## Out of scope

- Receiving a retirement (spec 024-key-retired).
- The warning dialog before regenerating and the "retirement pending" wording (specs 050–052).

## Open questions

None.

## History

- 2026-09-25 draft
- 2026-09-25 revised after audit J round 1 (`docs/audit-log.md`): one's own old keys in their own list of eight, never refused for room; kept signatures dropped by epoch; re-seal in either direction and not while in flight; `AckOutcome`; a late `ack` changes nothing (`docs/spec.md` §4 reworded); `FailingStore` tests
- 2026-09-25 revised after audit J round 2 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 3 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 4 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 5 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 6 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 7 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 8 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 9 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 10 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 11 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 21 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 23 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 24 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 25 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 26 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 27 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 30 (`docs/audit-log.md`)
