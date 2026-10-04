# 023 — TTL purge: the message list and compaction

Status: accepted
Phase: 2
Related ADRs: 0009, 0014, 0021, 0029, 0044
Depends on: 020-store-files, 021-channel-session, 022-peers-tofu
Blocks: 027-core-api, 028-session-sans-io, 055-verify-ui, 056-chat-screens
Human reviewer: Marc Vilardebó · Accepted on: 2026-09-28

## Context

The TTL is part of the channel (ADR 0014) and the client enforces it without trusting the server (ADR 0009): a message is shown until its local expiry and physically removed from `messages.log` by compaction (ADR 0021, `docs/spec.md` §6 "TTL and expiry", §8 "Deletion"). Spec 021-channel-session R26 writes the `purge_at` of every record; this spec fixes the list of messages the UI shows, the purge call, and the compaction that spec 021's log headroom runs. `docs/spec.md` §9 had no call to paint a channel after it is reopened; `messages(now)` is that call.

**In plain words.** Every entry in the journal carries the moment it may be thrown away. The screen shows only messages still alive, in the order the server received them, with your own messages marked as waiting, delivered or not delivered. Throwing the dead ones away from the disk happens when the app opens, once a minute while it stays open if something has expired, and whenever the journal is nearly full.

## Requirements

- R1 `messages(now)` MUST return every message record whose display expiry is not below `now`, folded with the acked and not-delivered records that name its `client_ref`, and MUST NOT commit. The display expiry MUST be the record's `purge_at` for a peer's message and for a message from one's own key sealed elsewhere (`min(sent_at, t) + ttl_ms`, `t` the time it arrived, spec 021-channel-session R10 and R26), `sent_at + ttl_ms` for one's own delivered message (ADR 0044), and the record's `purge_at` (`sent_at + 2·ttl_ms + 420 000`, spec 021-channel-session R26) for one's own message pending or not delivered, so that a message that failed stays visible as failed.
- R2 The list MUST be in order of display time: the `received_at` of the record — `min(r, now)` of spec 021-channel-session R11, never later than its arrival and never earlier than its signed `sent_at` minus the margin — for a peer's message and for one from one's own key sealed elsewhere, the clamped `received_at` of its acked record for one's own delivered message, and the local `received_at` its record carries for one's own pending or not-delivered message (spec 021-channel-session R8), ties broken by log order; each `Message` carries that time as `received_at`, as `Received` does. So neither a signer's future `sent_at` nor a server's past or future `received_at` can pin a message to the bottom of the list or bury it in the scrollback.
- R3 Each `Message` MUST carry its `server_id` when known, its `client_ref` when it is one's own, the sender (`Sender::Peer`, `Sender::Own` for a record with `own` true, `Sender::OwnKeyElsewhere` for a record from one's own `pk_u` with `own` false), `received_at` as ordered by R2, `sent_at` when read, the content, the display expiry of R1 as `expires_at`, and for `Sender::Own` its delivery: `Delivered` when acked in time, `NotDelivered` when a not-delivered record names it, or when it is still pending and `sent_at + ttl_ms + 420 000 < now` (past the grace minute of spec 021-channel-session R22), `Pending` otherwise. `Sender::OwnKeyElsewhere` MUST be used for a record with `own` false whose `sender_pk` is one's own `pk_u` or one of `own_old_keys`. A `Message` from a `Sender::Peer` with no peer record (evicted, forgotten, or removed by its own retirement) MUST carry a `stranger` with the short identifier and the `claims_name_of`/`claims_own_name` of spec 022-peers-tofu R13 computed on its `display_name`, and is presented as an unknown sender. The client removes a row at its `expires_at`; `Received` of spec 021-channel-session carries the same `expires_at`.
- R4 `purge_expired(now)` MUST return 0 without touching the store when no record has a `purge_at` below `now`, and otherwise run the compaction step of spec 021-channel-session R18 — `Store::compact(state, now)`, then drop from memory the records whose `purge_at` is below `now` — whatever the amount expired, and return the number of message records dropped; kept signatures and delivery records dropped are not counted.
- R5 `Channel::open_stored` and `Channel::create` MUST NOT compact, since they have no `now`; `purge_due(now)` MUST return whether the rule below holds, from the expiry index of spec 021-channel-session R1, and `false` within 600 000 ms of the channel's last compaction attempt (spec 021-channel-session R18), an attempt recorded later than `now` holding nothing off (the `purge_expired` that follows records `now`), so that a compaction failing on every call, as on a disk with less free space than the log, is retried at most every ten minutes; `Device` of spec 027-core-api runs `purge_expired`, when it opens and from `on_tick` (spec 027-core-api R12), on a channel whose expired records take a quarter of its log or more, or whose oldest expired record expired more than 86 400 000 ms ago, so that a rewrite frees at least a quarter of what it writes; the headroom of spec 021-channel-session R18 compacts on its own when enough has expired to restore the room, at most once every ten minutes.
- R6 `purge_expired` MUST have a `FailingStore` test in which the compaction fails: the channel keeps its previous memory, and a reopened store gives the state and log before or after the compaction, never a mix (spec 020-store-files R11).
- R7 `message(client_ref, now)` MUST return the one `Message` of R1–R3 for one's own record with that `client_ref`, built without the rest of the list; it cannot fail, since an own row computes no `stranger`, and it returns `Some` for the `client_ref` of every committed `encrypt` while the row is listed.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| `now` | any u64 | saturating arithmetic |
| Purges from `on_tick` | when expired records reach a quarter of the log, or are a day old | skipped |

## Interface

```
crates/core/src/session/purge.rs          messages, purge_expired
crates/core/src/session/purge/tests.rs    s023_* tests
```

```rust
pub enum Delivery { Pending, Delivered, NotDelivered }
pub struct Message { pub server_id: Option<[u8; 16]>, pub client_ref: Option<ClientRef>, pub sender: Sender,
                     pub received_at: u64, pub sent_at: Option<u64>, pub expires_at: u64, pub content: MessageContent, pub delivery: Option<Delivery>,
                     pub stranger: Option<Stranger> }
pub struct Stranger { pub short: Vec<String>, pub claims_name_of: Option<PeerId>, pub claims_own_name: bool }

impl Channel {   // pub(crate); spec 027-core-api exposes them through Device
    pub(crate) fn messages(&self, now: u64) -> Result<Vec<Message>, Error>;
    pub(crate) fn message(&self, client_ref: ClientRef, now: u64) -> Option<Message>;   // one own row, for spec 027's Sent
    pub(crate) fn purge_expired(&mut self, now: u64) -> Result<u32, Error>;
    pub(crate) fn purge_due(&self, now: u64) -> bool;
}
```

`Sender`, `MessageContent` and `ClientRef` are spec 021-channel-session's. A client keys its rows by `server_id`, or by `client_ref` for its own messages until they are delivered, places each row — from `messages()`, `Event::Message` or `Event::Delivered` — by its `received_at` and then its arrival, moves an own row once when it is delivered, and applies no other order (architecture skill §7).

## Security

- The client never trusts the server to delete (ADR 0009): a message expires by its signed `sent_at`, at `min(sent_at, t) + ttl_ms` with `t` the time it arrived (spec 021-channel-session R26, ADR 0044), so no `received_at` the server chooses can extend or shorten its life on this device; `received_at` only orders the list (R2).
- An `Unreadable` with no readable `sent_at` expires by `received_at` alone, which the server chooses; the residual this leaves is in spec 021-channel-session Security.
- One's own delivered message keeps its plaintext on disk until `sent_at + 2·ttl_ms + 420 000` (spec 021-channel-session R26), up to one TTL and seven minutes after its row leaves the screen, because the record is written before its fate is known and the log is append-only; see Open questions.
- Kept signatures outlive the messages on purpose (ADR 0029); they are 64 bytes, a time and an epoch, and hold no content.
- An expired message leaves the screen at its `expires_at` (R1, R3); its plaintext leaves the disk once expired records reach a quarter of the log, or within a day at most (R5), at open, at unlock or while the app stays open, which bounds the flash writes a flood of short-lived messages can force (audit J, J2-B6) while keeping `docs/spec.md` §1 "deleted … on the client".
- Deletion is physical and does not resist older copies of the flash (`docs/spec.md` §2); the guarantee is the destruction of `K_db`.
- A device clock set ahead by more than a channel's TTL makes every message of that channel expire by the local clock, so the purge at open or at unlock removes them from `messages.log` for good, before any connection could raise `clock_off` (spec 021-channel-session); correcting the clock later brings back only what the server still holds. The behaviour is kept, since deleting early is the safe direction for privacy, and Help says to keep automatic time on (spec 056-chat-screens R18). Documented residual.

## Public API changes

None directly: spec 027-core-api exposes `messages(now)` and `purge_expired`, with `Message` and `Delivery`, through `Device`.

## Test cases

- T01 (covers R1): `s023_t01_r01_display_expiry`: an expired peer message is hidden before compaction; in a 60-second channel, one's own message written offline at 12:00:59 stays listed until its `purge_at`, `sent_at + 540 000`, as `NotDelivered` from `sent_at + 480 001`, and still so after `expire_outbox` removes it at `sent_at + 480 001`; after an in-time `ack` it is listed until `sent_at + 60 000`; `commits = 0`.
- T02 (covers R2): `s023_t02_r02_order`: a peer message at 12:00:40 and one's own sent at 12:00:50 are listed in that order before and after the `ack`; a peer message whose signed `sent_at` is a TTL ahead is placed at its arrival, not at the bottom; one the server dates six days back is placed at `sent_at − 360 000`; an own message acked with a `received_at` a day ahead is placed at the time of the `ack`, and one acked a TTL back at `sent_at − 360 000`, still listed.
- T03 (covers R3): `s023_t03_r03_message_fields`: `encrypt` → `Own`, `Pending`, its `client_ref` and `expires_at`; in-time `ack` → `Delivered` with the server's `server_id`; late `ack` → `NotDelivered`; a `display_name` with U+202E comes out cleaned (spec 022-peers-tofu R6); a message from one's own key sealed elsewhere → `OwnKeyElsewhere` with no delivery, and still so with its key moved to `own_old_keys` through the `testing` builders; a message whose sender was evicted carries a `stranger` whose `claims_name_of` names the labelled "Alice" its "ALlCE" collides with.
- T04 (covers R4): `s023_t04_r04_purge_counts_messages`: three expired messages and two expired signatures → 3; `messages` and a reopened store agree; nothing expired → 0 and no call to `compact`.
- T05 (covers R5): `s023_t05_r05_open_does_not_purge`: `open_stored` of a store with expired records commits nothing and `messages(now)` hides them; `purge_due` is true at a quarter of the log or a day after the oldest expiry, and not before; after a failed `purge_expired` (`Faults`), and after a failed headroom compaction, `purge_due` is false until 600 000 ms later, then true, and after a failed `purge_expired` `relieve_headroom` returns `Ok(false)` for those ten minutes; with the last attempt at `t` and the rule met, `purge_due(t − 86 400 000)` → true; `on_tick` is tested by spec 027-core-api T12.
- T06 (covers R6): `s023_t06_r06_failed_compaction`: a `FailingStore` failing the compaction → the error, memory unchanged, the reopened state before or after, never a mix.
- T07 (covers R7): `s023_t07_r07_single_message`: after `encrypt`, `message` of its `client_ref` equals the matching row of `messages`; an unknown `client_ref` → `None`.

## Vectors

None: the times are rules over the state, checked by the unit tests.

## Acceptance criterion

`cargo test -p privatechat-core s023_` green; clippy and the documentation lint green.

## Out of scope

- The `purge_at` of each record (spec 021-channel-session R26); the timer that calls `on_tick` (spec 042-connection-host R8).
- The server's purge (spec 032-storage-ttl).
- Local deletion of a single message by the user, and an unread marker: not in v1.

## Open questions

None.

Decided with the human reviewer on 2026-09-25 (recommendations accepted, `docs/audit-log.md`, Audit J decisions): 023-R1 with 021-R26: one's own delivered message leaves the screen at its `ack` time plus the TTL but stays on disk until `sent_at + 2·ttl_ms + 420 000`, which a pending or failed row needs; `docs/spec.md` §1 says expired messages are deleted on the client by the TTL. Shortening it means rewriting records at compaction (the core handing the survivors to `Store::compact`) or writing a second copy when the fate is known, both with new retention rules for the echo guard of spec 021 R13.; the recommendation taken: accept for v1 — the plaintext is the user's own, sealed under `K_db`, and bounded — and say so in §1; revisit with the lazy message list. 023-R5: `docs/spec.md` §8 "Deletion" compacts on every open and unlock. With the default lock timeout of a minute, that rewrites every channel's log at almost every unlock for a single expired record. This draft hides expired messages at once and removes them from the disk only at a quarter of the log or after a day, at open, unlock or tick.; the recommendation taken: accept, and reword §8 when this spec is accepted.

## History

- 2026-09-25 draft
- 2026-09-25 revised after audit J round 1 (`docs/audit-log.md`): `purge_at` moved to spec 021; own messages listed while they can still be published and ordered by their real times; `client_ref` and `OwnKeyElsewhere` in `Message`; periodic purge from `on_tick`; `FailingStore` test; client duties out of the requirements
- 2026-09-25 revised after audit J round 2 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 3 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 4 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 5 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 6 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 7 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 8 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 9 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 10 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 12 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 13 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 14 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 15 (`docs/audit-log.md`)
- 2026-09-25 revised after audit J round 16 (`docs/audit-log.md`)
- 2026-09-25 open questions decided with the human reviewer, recommendations accepted (`docs/audit-log.md`)
- 2026-09-28 revised after audit P (`docs/audit-log.md`): the `on_tick` timer points to spec 042; the residual of a clock set ahead
- 2026-09-28 accepted (Marc Vilardebó)
- 2026-10-04 amended after audit AC (`docs/audit-log.md`): an echo writes no acked record, so a not-delivered record is final (R3)
- 2026-10-04 amended after audit AC and ADR 0044 (`docs/audit-log.md`): display expiry from the signed `sent_at`, `received_at` only for the order (R1, Security)
