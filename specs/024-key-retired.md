# 024 — Key retired: receiving a retirement and retiring a peer by hand

Status: draft
Phase: 2
Related ADRs: 0016, 0029, 0033
Depends on: 021-channel-session, 022-peers-tofu
Blocks: 025-identity-regen, 026-peer-limits, 027-core-api, 028-session-sans-io, 055-verify-ui
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

A stolen key must not stay "Alice ✓" forever (ADR 0016). Its owner signs a `key_retired` with it, sealed at the last counter so that no ordinary message of a thief can make it `Replay` (ADR 0033), and every receiver records the key as retired: from then on each blob of that key is `RetiredKey` at step 5, whatever its counter (`docs/spec.md` §4, §7). A member who lost the key cannot sign, so every peer card also has "Mark this key as retired". Sending a retirement is spec 025-identity-regen; this spec is what the receiving side does, and the manual action.

Only a key the user already trusts — labelled or verified — becomes a retired record by a message. A retirement from a stranger removes the stranger instead: otherwise anyone with the config could fill the channel with permanent retired records (audit J, J-B1).

**In plain words.** When a known person's key says "I am retired", the channel greys that key out for good: its old messages stay until they expire, and anything new it writes is refused. A retirement from a key you never named just makes the channel forget that key. A retirement from your own key that your device did not send means someone else has your key and has just silenced it: the channel stops letting you write with it until you make a new one.

## Requirements

- R1 A consumed, not stale `key_retired` from a peer with a label or `verified` MUST, in the commit of that message, set `retired_at = now` (unless already set), set `max_counter = 2^64 − 1`, keep the label and `verified`, and append the log record with `content` 1.
- R2 A consumed, not stale `key_retired` from a `pk` other than one's own `pk_u` (R3) with no record, or from an unknown peer (no label, not verified, not retired) that is not muted, MUST remove that record if there is one and append nothing else, in the commit of that message; from a muted unknown it MUST keep the record, muted, set its `max_counter = 2^64 − 1` and append no log record, so that muting stays durable and the key's later blobs are `Replay`; in every case of R2 `decrypt` returns `Ok(None)` (spec 021-channel-session R11) and no event follows.
- R3 A consumed, not stale `key_retired` from one's own `pk_u` that this device did not seal MUST set `read_only` in the commit of the own-key event (spec 021-channel-session R14); `read_only` MUST stay set until spec 025-identity-regen clears it.
- R4 `retire(peer, now)` MUST return `Error::UnknownPeer` for no record, commit nothing for a peer already retired, and otherwise commit `retired_at = now`, keeping the label.
- R5 Retiring a peer, received by R1 or by hand, MUST NOT be refused by a limit of spec 026-peer-limits, and no purge or eviction MUST remove a retired record; only `forget` of spec 026-peer-limits does, when the user asks.
- R6 `retire` MUST have a `FailingStore` test that fails its commit and checks the reopened state.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| `PeerId` for `retire` | a `pk` with a record | `UnknownPeer` |

## Interface

```
crates/core/src/session/retired.rs          R1–R6
crates/core/src/session/retired/tests.rs    s024_* tests
```

```rust
impl Channel {   // pub(crate); spec 027-core-api exposes it through Device
    pub(crate) fn retire(&mut self, peer: PeerId, now: u64) -> Result<(), Error>;
}
```

## Security

- The last counter (ADR 0033) makes the retirement immune to a thief's ordinary messages; a thief who writes first at `2^64 − 1` gets one message and then the key is dead for those receivers anyway (ADR 0033 "Consequences").
- R2: a stranger's retirement can neither plant a permanent record nor grow the list; the worst it does is remove itself. The price: when a member the receiver never named retires a stolen key, a thief who keeps writing with it reappears to that receiver as a new unknown, grey and marked, rather than as `RetiredKey`; the receiver never trusted that key, so nothing it trusted is lost. The retired records a message can create are bounded by the peers the user named or verified.
- R5: retiring can never fail for lack of room, and nothing automatic removes a retired record, so a thief cannot flood a key out of the retired list.
- A retirement expires on the server like any message (ADR 0034): a member who does not connect within the TTL never receives it, which is why the manual action exists.

## Public API changes

None directly: spec 027-core-api exposes `retire(peer, now)` through `Device`.

## Test cases

- T01 (covers R1): `s024_t01_r01_retirement_from_known_peer`: a labelled, verified peer's `key_retired` → retired, label and `verified` kept; its next message at any counter → `RetiredKey`, `commits = 0`; a second copy of the retirement → `RetiredKey`, `commits = 0`.
- T02 (covers R2): `s024_t02_r02_retirement_from_stranger`: from a `pk` with no record → no record, `Ok(None)`, `commits = 0` (only the cursor, by spec 021-channel-session R20); from an unknown peer → its record removed; from a muted unknown → the record kept, muted, and its next text → `Replay`; after 530 fresh keys each send a text and a `key_retired`, the peer list holds none of them.
- T03 (covers R3): `s024_t03_r03_own_key_retired_elsewhere`: `read_only` and the event set in one commit; `encrypt` → `RetiredKey`.
- T04 (covers R4): `s024_t04_r04_manual_retire`: an unknown `PeerId` → `UnknownPeer`, `commits = 0`; a peer → retired; again → `commits = 0`.
- T05 (covers R5): `s024_t05_r05_retire_is_never_refused`: with 500 labelled peers, retiring an unknown one succeeds; a purge leaves every retired record in place (eviction is tested by spec 026-peer-limits T03).
- T06 (covers R6): `s024_t06_r06_failing_store`: `retire` under a `FailingStore` → the reopened state is the one before.

## Vectors

None of its own: the `key_retired` blob is the 013 vector `key_retired`; the effects are unit tests over state.

## Acceptance criterion

`cargo test -p privatechat-core s024_` green; clippy and the documentation lint green.

## Out of scope

- Sending a retirement, the pending `key_retired` and its re-sealing (spec 025-identity-regen); the gap exclusion of a `key_retired` (spec 021-channel-session R24).
- `forget` and the limits (spec 026-peer-limits); the dialogs and their wording (specs 050–052).

## Open questions

None.

## History

- 2026-09-25 draft
- 2026-09-25 revised after audit J round 1 (`docs/audit-log.md`): a retirement from a stranger removes the stranger instead of planting a permanent record; `decrypt`'s result stated; `forget` may remove a retired record; duplicated rules left to their owners; `FailingStore` test
- 2026-09-25 revised after audit J round 2 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 3 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 4 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 5 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 6 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 7 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 8 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 9 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 10 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 13 (`docs/audit-log.md`)
