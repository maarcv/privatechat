# 025 — Identity regeneration and the pending retirement

Status: implemented
Phase: 2
Related ADRs: 0007, 0016, 0019, 0029, 0033, 0034
Depends on: 021-channel-session, 024-key-retired
Blocks: 027-core-api, 028-session-sans-io, 055-verify-ui
Human reviewer: Marc Vilardebó · Accepted on: 2026-09-28

## Context

"Regenerate my key" replaces the user's key in one channel with a fresh one that has no link to the old (ADR 0007), and tells the others to stop trusting the old one with a `key_retired` signed by it (ADR 0016). It is the answer to the own-key alert, to an exhausted counter and to a read-only channel, so it must never be refused for lack of room. The retirement must arrive even when the user regenerates offline (ADR 0034): the old `sk_u` is kept only to re-seal that one message when it would otherwise leave stale, and is erased when the server acknowledges it in time. `docs/spec.md` §4 "Send counter" and §7 "Key regeneration" describe the flow; this spec implements it.

One's own old keys are not peers: they go to a short list of their own (`own_old_keys`, spec 020-store-files), so that later echoes of their blobs are `RetiredKey` (ADR 0029) without taking a place among the peers.

**In plain words.** You get a new key, and the old one writes one last message, "this key is retired", which waits in the queue behind any message the old key had not sent yet. The device keeps the old key for that single message: if it has been waiting so long that nobody would accept it, the device signs it again with a fresh date. Once the server confirms it arrived in time, the old key is wiped. Meanwhile the channel shows "retirement pending". The device remembers your last sixteen old keys, so their echoes are recognised.

## Requirements

- R1 `regenerate_identity(now)` MUST return `Error::RetirementPending` while `retiring_seed` is present, and otherwise commit, in one commit, which appends no log record and so is never refused for room (a `LogFull` from it is returned as `Error::Internal`, spec 021-channel-session R18): the old `pk_u` appended to `own_old_keys` with `retired_at = now`, dropping, when there are already 16, the first entry in the list (the order of regeneration, which a clock set back cannot reorder) whose `retired_at + 2·(ttl_ms + 360 000) < now`, or else the first; `retiring_seed` = the old seed; a new `identity_seed` from `Secret::random`; `identity_epoch + 1`; `send_counter = 0`; `own_key_used_elsewhere` and `read_only` cleared; every ordinary `outbox` entry marked `under_retired_key`; and the `key_retired` entry of R2 appended at the end of the `outbox`. It MUST NOT be refused by any peer limit.
- R2 The `key_retired` entry MUST be sealed with the old key, `counter = KEY_RETIRED_COUNTER` (spec 013-wire-message), `sent_at = now − now mod 60 000`, a fresh nonce and a fresh `client_ref`, `kind` 1 and `under_retired_key` true, in the `outbox` slot kept for it (spec 020-store-files), so it never fails with `OutboxFull`.
- R3 From the commit of R1 on, every echo of the old key MUST be `RetiredKey` at step 5 (ADR 0029, 0034), before the signature comparison of spec 021-channel-session R13; its kept signatures, which no blob of another key can match, stay in the log, inert, until their `purge_at`.
- R4 `outbox(now, in_flight, withhold_current)` MUST, whatever `withhold_current`, re-seal the pending `key_retired` whenever that call hands it out — no copy in flight, and no ordinary entry `under_retired_key` left after its stale removal — and `now − now mod 60 000` differs from its `sent_at`, earlier or later, with that `sent_at`, a fresh nonce and a fresh `client_ref`, replacing the entry in place, in the commit of that `outbox` call (when that commit fails, `outbox` hands out nothing, spec 021-channel-session R22); the entry MUST keep its position; a copy in flight or held back is not re-sealed, and `expire_outbox` (spec 021-channel-session R23) never re-seals, so that a device offline, or a retirement waiting behind the old key's entries, does not rewrite its state every minute. `outbox` MUST NOT hand out the `key_retired` while an ordinary entry `under_retired_key` is still in the `outbox`, so that the old key's messages always arrive before its retirement.
- R5 `acked` of the current `client_ref` of the stored `key_retired` entry MUST, when it was stored in time as spec 021-channel-session R17 judges an ordinary entry — `|received_at − sent_at| ≤ ttl_ms + 360 000` and `sent_at + ttl_ms ≥ now` (ADR 0044), since no member shows a `key_retired` past its life — remove the entry and `retiring_seed` in one commit, keeping no signature, and return `AckOutcome::RetirementDelivered`; outside that window, and for any earlier `client_ref` of it, it MUST change nothing, commit nothing and return `AckOutcome::Ignored`.
- R6 `status().retirement_pending` MUST be true exactly while `retiring_seed` is present, and `own_old_keys()` MUST return the list of R1 with each key's `retired_at`.
- R7 The old `sk_u` MUST be used for nothing but R2 and R4, and MUST be dropped from memory in the commit of R5; the key being retired is told by the last entry of `own_old_keys`, never from the old seed.
- R8 `regenerate_identity`, the re-seal of R4 and the `acked` of R5 MUST each have a `FailingStore` test that fails its commit and checks the reopened state.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| Regeneration while a retirement is pending | not allowed | `RetirementPending` |
| `own_old_keys` | 0..=16 | the first whose own blobs nobody accepts any more dropped, else the first |
| `outbox` | the reserved slot always free for the `key_retired` | not reachable |

## Interface

```
crates/core/src/session/channel/regen.rs          R1–R8 (R4 and R5 called from channel/outbox.rs)
crates/core/src/session/channel/tests/regen.rs    s025_* tests
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
- The old key's entries are never mixed with another key's, and no copy of the `key_retired` that left can overtake one of them: R4 hands out no copy while an entry `under_retired_key` is still in the `outbox`, no entry is marked after R1, and R1 refuses a second regeneration until R5 has removed the `key_retired`. So `under_retired_key` always means the key being retired (specs 021 R9 and R17 compare its counters alone), and the echo of a superseded copy, which step 5 reads as a thief's (spec 021 R9), finds no entry of the old key to remove (025-R1, 025-R2, closed).
- A retirement reaches only the members who fetch it within its life: its `sent_at` is the minute it is handed out, so in a channel whose TTL is a minute or two it reaches almost only the members online then, `ttl_ms − (now mod 60 000)` at the least. Documented, beside the warning of `docs/spec.md` §7.
- An old key is dropped from `own_old_keys` by its `retired_at`, while its delivered `key_retired` copy can be dated later, by up to one TTL and the margin: after sixteen regenerations, a retirement that took long can have its key dropped while that copy is still accepted, and its echo then reads as an unknown peer here. A thief holding a dropped old key can likewise send freshly dated blobs, which this device shows as an unknown peer under the user's old name (spec 026-peer-limits counts it). Accepted residuals: each needs sixteen regenerations.
- While a retirement stays pending for ever (above), R1 refuses a second regeneration, so a new key stolen meanwhile cannot be replaced either: only `leave`, or a new channel, remedies it. Documented.
- Refusing a second regeneration while one is pending (R1) keeps a single old key in memory; the channel card shows why the button is disabled, and the client warns before leaving a channel with a retirement pending.

## Public API changes

None directly: spec 027-core-api exposes `regenerate_identity(now)` and `own_old_keys()` through `Device`, with `Error::RetirementPending`.

## Test cases

- T01 (covers R1): `s025_t01_r01_regeneration_commit`: one commit; an ordinary entry left from before is marked `under_retired_key`, a later `encrypt` is not; after a delivered retirement a second regeneration finds no entry of the first old key, so only the second old key's entries are marked; the old `pk` in `own_old_keys`; epoch + 1; `send_counter` 0; the event and `read_only` cleared; with 550 peers it still succeeds; a second call → `RetirementPending`, `commits = 0`; a seventeenth regeneration drops the oldest old key whose blobs have all expired, or else the oldest; after a foreign `key_retired` on a full log → regeneration succeeds, and the new key is neither `read_only` nor exhausted, with no alert; a log planted exactly full (the `testing` builders of spec 020-store-files) → regeneration succeeds, since it appends no record.
- T02 (covers R2): `s025_t02_r02_retirement_sealed`: the entry opens with the old `pk` at counter `2^64 − 1` as a `key_retired`; with 31 ordinary entries it still fits, and is handed out only after the last of them leaves the `outbox`.
- T03 (covers R3): `s025_t03_r03_old_echoes_are_retired`: an echo of a blob sealed before regeneration → `RetiredKey`, no own-key event, `commits = 0`; after reopening, too.
- T04 (covers R4, R5): `s025_t04_r04_reseal`: `outbox` in the same minute hands out the same bytes; one minute later a new nonce, `sent_at` and `client_ref`, same position; with `now` one hour before `sent_at` it is re-sealed too; a new nonce; a copy in flight is not re-sealed; a copy held back behind an entry of the old key is not re-sealed, with no commit, and is re-sealed as it is handed out once the entry leaves; `expire_outbox` never re-seals; the echo of a superseded copy that was handed out → `RetiredKey`, nothing removed, `commits = 0`.
- T05 (covers R5): `s025_t05_r05_ack_erases_old_key`: in-time `ack` → `RetirementDelivered`, entry and `retiring_seed` gone, at both edges of the window and with `now = sent_at + ttl_ms`; late `ack` → `Ignored`, `commits = 0`; an `ack` stored at `sent_at + ttl_ms + 1`, or received when `sent_at + ttl_ms < now` → `Ignored`, `commits = 0`, and the next `outbox` re-seals and hands out the copy; an `ack` whose `received_at` is `sent_at − ttl_ms − 360 001` → `Ignored`, `commits = 0`, `retiring_seed` kept; `ack` of the previous copy → `Ignored`, `commits = 0`.
- T06 (covers R6): `s025_t06_r06_pending_flag_and_old_keys`: true after R1, false after R5, and after reopening the store in between, R5 delivered on the reopened channel; `own_old_keys` lists the old key with its time, and its `Debug` shows the 4-byte prefix of the key alone.
- T07 (covers R7): `s025_t07_r07_old_key_only_for_retirement`: after regeneration every ordinary `encrypt` is sealed with the new key; the state written by R5 holds no old seed.
- T08 (covers R8): `s025_t08_r08_failing_store`: `regenerate_identity`, a re-sealing `outbox` of a `key_retired` sealed two minutes earlier (`Store(Io)`, nothing handed out) and the delivering `acked`, each under a `FailingStore` → the state in memory and the reopened state are the ones before.

## Vectors

None of its own: the blob is the 013 `key_retired` layout; the flow is unit tests over state.

## Acceptance criterion

`cargo test -p privatechat-core s025_` green; clippy and the documentation lint green.

## Out of scope

- Receiving a retirement (spec 024-key-retired).
- The warning dialog before regenerating and the "retirement pending" wording (spec 055-verify-ui R14).

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
- 2026-09-28 revised after audit P (`docs/audit-log.md`): warning and "retirement pending" point to spec 055
- 2026-09-28 accepted (Marc Vilardebó)
- 2026-10-04 amended after audit AC (`docs/audit-log.md`): no own-key value held in memory to apply and no retry without it (R1); no `key_retired` copy re-sealed in memory when the `outbox` commit fails (R4, R5)
- 2026-10-04 amended after audit AC (`docs/audit-log.md`): the old key's kept signatures are no longer filtered out by epoch; step 5 stops its echoes first (R3)
- 2026-10-04 open questions 025-R1 and 025-R2 added from audit AD of spec 021 (`docs/audit-log.md`)
- 2026-10-09 amended after audit AH round 1 (`docs/audit-log.md`): an `ack` delivers the retirement only as one delivers an ordinary entry (R5, ADR 0044); the copy is re-sealed only as it is handed out (R4, `docs/spec.md` §4 and §7); the key being retired is told without the old seed (R7); "the first" of `own_old_keys` in the order of regeneration (R1); residuals in Security; T04–T06 and T08 clauses
- 2026-10-09 open questions 025-R1 and 025-R2 closed by the human reviewer: unreachable under R1 and R4 (Security), pinned by T01 and T04; Interface paths follow the channel module layout (`docs/audit-log.md`)
