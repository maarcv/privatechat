# 026 — Peer limits: two budgets, eviction of unknowns and the ignored-keys count

Status: draft
Phase: 2
Related ADRs: 0006, 0036
Depends on: 021-channel-session, 022-peers-tofu, 024-key-retired
Blocks: 027-core-api
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

Anyone with the config can create keys without end (`docs/spec.md` §2, row "Intruder with the leaked config"). Without a limit, every new key would be a new record in `state.bin`, which is rewritten on every commit. `docs/spec.md` §7 "Peer limits" gives two budgets per channel: at most 500 labelled, verified or retired peers, a hard limit the user resolves, and at most 50 unknown peers, recycled by least-recent use; and it promises that nothing is ignored silently. This spec implements both budgets, the room check of step 5 (`docs/spec.md` §4) that spec 021-channel-session R9 calls, the eviction, the admission check that spec 022-peers-tofu R7–R9 call, the `forget` call the hard limit needs, and the peer counts that bound `state.bin` (spec 020-store-files); the label size is `MAX_NAME` of spec 020-store-files.

**In plain words.** The channel keeps at most 50 strangers. When a new one writes and there is no room, the stranger heard from longest ago is forgotten and may come back later as new — except the ones you muted: those stay, so a spammer you silenced does not return unmuted. People you have named, verified or retired go on a separate list of 500, which never forgets on its own; when it is full, you remove someone before you can name another. The channel card says how many keys were turned away.

## Requirements

- R1 A peer MUST be unknown when it has no label, is not verified and is not retired, muted or not; every other peer MUST be in the labelled budget. The peers in all MUST NOT exceed 550.
- R2 At step 5, a message from a `pk` with no record, other than one's own `pk_u` (never a peer), MUST find room when fewer than 50 peers are unknown and fewer than 550 exist, or when at least one unknown peer is not muted; otherwise it MUST be rejected with `Error::PeerLimit`.
- R3 When a consumed, not stale message creates a peer while 50 peers are unknown or 550 exist, the unknown peer that is not muted, other than the one being created, with the smallest `last_seen`, ties broken by the smallest `pk` in byte order, MUST be removed in the same commit, `max_counter` included.
- R4 A `label`, `verify` or `verify_scanned` that would move an unknown peer into the labelled budget, or create a verified peer, MUST return `Error::PeerLimit` and commit nothing when the labelled budget holds 500 peers or more, or when the call would create a record and 550 exist; retiring an existing peer moves it between budgets and MUST NOT be refused (spec 024-key-retired R5).
- R5 `forget(peer)` MUST return `Error::UnknownPeer` and commit nothing for no record, and otherwise remove the record in one commit, retired or not; a forgotten key that writes again is a new unknown.
- R6 `Channel` MUST keep in memory, from the moment it is loaded, the set of distinct `pk`s rejected with `PeerLimit` at step 5 or evicted by R3, at most 1 024 of them, and `status()` MUST return its size as `ignored_keys`, `unknown_limit_reached` when R2 would reject a new key, and `labelled_limit_reached` when the labelled budget holds 500 or more. The user's own calls of R4 do not count, and nothing of R6 is persisted (spec 027-core-api R14 carries the set over a silent reopen, spec 021-channel-session R1), because a rejection commits nothing but the cursor (AGENTS 23).
- R7 `forget` and the eviction of R3 MUST each have a `FailingStore` test that fails the commit and checks the reopened state.

## Limits

| Item | Range | Out of range |
| --- | --- | --- |
| Unknown peers | 0..=50 | eviction (R3), or `PeerLimit` when all are muted (R2) |
| Labelled, verified or retired peers | 0..=500 on admission; retirement may take it higher | `PeerLimit` on admission (R4) |
| All peers | 0..=550 | eviction (R3), `PeerLimit` (R2, R4) |
| Ignored keys counted | 0..=1 024 distinct | saturates |
| `label` | 1..=`MAX_NAME` B (spec 020-store-files), checked by spec 022-peers-tofu R7 | `BadPayload` |

## Interface

```
crates/core/src/session/limits.rs          R1–R7
crates/core/src/session/limits/tests.rs    s026_* tests
```

```rust
pub(crate) const MAX_UNKNOWN_PEERS: usize = 50;
pub(crate) const MAX_LABELLED_PEERS: usize = 500;
pub(crate) const MAX_PEERS: usize = 550;
pub(crate) const MAX_IGNORED_TRACKED: usize = 1_024;

impl Channel {   // pub(crate); spec 027-core-api exposes it through Device
    pub(crate) fn forget(&mut self, peer: PeerId) -> Result<(), Error>;
}
```

Retirement can take the labelled budget past 500, since R4 never refuses it, but never the total past 550: retiring moves an existing record between budgets, a received retirement from a stranger removes the record (spec 024-key-retired R2), R2 and R3 count the total, and one's own old keys are not peers (spec 025-identity-regen).

## Security

- R2 and R3 turn a flood of keys into churn among strangers, visible as `ignored_keys`, and never into lost state for known people: evictions touch unknowns only.
- Muted unknowns are never evicted, so muting is durable; the price is that 50 muted keys close the channel to new strangers, which `unknown_limit_reached` shows, and the user can `forget` some.
- The room check reads state only after the signature (step 5 of `docs/spec.md` §4), and the eviction happens only for a consumed, not stale message, so no unauthenticated header can evict anybody (ADR 0027).
- Nothing a message can do adds a permanent record without the user: a received retirement promotes only peers the user named (spec 024-key-retired R1, R2), so the 500 are the user's choices.
- The quota protects the device, not the channel: a leaked config can keep newcomers out; the answer is a new channel (ADR 0008).

## Public API changes

None directly: spec 027-core-api exposes `forget(peer)` and the `ChannelStatus` values through `Device`.

## Test cases

- T01 (covers R1): `s026_t01_r01_budgets`: a muted unlabelled peer is unknown; a labelled, a verified and a retired peer are in the labelled budget.
- T02 (covers R2): `s026_t02_r02_room_check`: 50 unknowns with one unmuted → room; all muted → `PeerLimit`, `commits = 0`, but a blob from one's own `pk_u` is not refused; 550 peers with one unmuted unknown → room.
- T03 (covers R3): `s026_t03_r03_lru_eviction`: a 51st key evicts the oldest unmuted unknown, never a retired record, and never itself even with `now` below every `last_seen`; the evicted key writing again is a new unknown at any counter.
- T04 (covers R4): `s026_t04_r04_labelled_budget`: with 500 labelled, `label` of an unknown, `verify` of an unknown with a label and a pre-verification → `PeerLimit`, `commits = 0`; with 501 (an unknown retired by hand) the same; `retire` succeeds.
- T05 (covers R5): `s026_t05_r05_forget`: a labelled peer and a retired one are removed; an unknown `PeerId` → `UnknownPeer`, `commits = 0`.
- T06 (covers R6): `s026_t06_r06_ignored_keys`: one key rejected ten times and one evicted key → 2; a `label` refused by R4 → still 2; after reopening → 0; the two flags as defined.
- T07 (covers R7): `s026_t07_r07_failing_store`: `forget` and an evicting `decrypt` under a `FailingStore` → the reopened state is the one before.

## Vectors

None: the limits are rules over state, checked by the unit tests.

## Acceptance criterion

`cargo test -p privatechat-core s026_` green; clippy and the documentation lint green.

## Out of scope

- How the channel card words the counts (specs 050–052).
- Limits on the server (spec 033-rate-limit-quotas).

## Open questions

None.

Decided with the human reviewer on 2026-09-25 (recommendations accepted, `docs/audit-log.md`, Audit J decisions): 026-R2, R3: `docs/spec.md` §7 says "Unknown peers (muted ones count): maximum 50, with LRU eviction by `last_seen`", with no exception for muted ones. This draft never evicts a muted unknown, so that a muted spammer does not come back unmuted, and rejects new keys with `PeerLimit` when all 50 unknowns are muted.; the recommendation taken: accept, and add the sentence to §7. 026-R6: §7 says the card "always shows X new keys ignored"; this draft counts distinct keys since the channel was opened in this session, and shows the two limit flags, which survive a restart because they are read from the peers.; the recommendation taken: accept; persisting the count would make every rejection a state write.

## History

- 2026-09-25 draft
- 2026-09-25 revised after audit J round 1 (`docs/audit-log.md`): `forget` also removes retired records; regeneration no longer checked here (one's own old keys are not peers); "500 or more"; the ignored count by distinct key and without the user's own calls; the flags defined by the rules they report; the muted exception raised as an open question; `FailingStore` tests
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
- 2026-09-25 revised after audit J round 13 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 33 (`docs/audit-log.md`)
- 2026-09-25 open questions decided with the human reviewer, recommendations accepted (`docs/audit-log.md`)
