# ADR 0029 — Treat a message from one's own key as an echo only if this device sealed it

Date: 2026-09-24 · Status: accepted

## Context
`docs/spec.md` §7 promises the alert "Someone has written with your key in this channel" for "a valid message from its own `pk` that it did not send". §4 and ADR 0019 implemented that with the counter alone: any message from one's own key with `counter <` send counter was taken to be the server's echo and discarded as `Replay`. Audit H (`docs/audit-log.md`, H1) found that a thief holding the key gets past the alert in two ways:

- **Low counter to new readers.** Alice last wrote with counter 100, and her blobs have expired. The thief signs a fresh blob with counter 5. A member who joined later has no `max_counter` for Alice and accepts it as hers; Alice's device reads counter 5 < 101 as an echo, so no alert fires.
- **Winning the race.** Alice seals counter *c* while offline. The thief publishes his own counter *c* first. Everyone accepts his message; Alice reads it as an echo, and her own message later becomes `Replay` everywhere. She loses it and is never told.

The alert is the only key-compromise detector of the project (§2), so it must decide by what was sent, not by a number the thief also controls. Any exception based on the counter or on staleness can be dodged too, because staleness is judged by each receiver's clock: a blob stale for the victim can be fresh for a member whose clock is a few seconds behind.

## Decision
A message from one's own `pk_u` is an echo only if its 64-byte signature equals (`ct_eq`) the signature of a blob this device sealed and still holds; any other message from one's own key that verifies raises `OwnKeyUsedElsewhere`, whatever its counter and whether or not it is stale, unless its signed `sent_at` is so old that the device may already have dropped the signature. The exact rule, the retention window and the verdict table are `docs/spec.md` §4 "Messages from one's own key".

## Alternatives considered
- Keeping the counter rule and documenting the gap: the one detector the threat model relies on would miss the cheapest attack on it.
- Exempting stale messages below the send counter from the alert: a thief can date a message just past the TTL, which the victim reads as stale and a member with a slower clock reads as fresh.
- Comparing a hash of the whole blob instead of the signature: equivalent evidence, more bytes hashed; the signature is already a 64-byte digest of the signed range.
- Storing the counter of each sent message instead: the thief can reuse a counter, which is exactly the race above.

## Consequences
- The alert fires for every message the device did not seal, including a low counter, a lost race and a message dated to look stale to its victim.
- A blob is accepted only until `sent_at + 2·(ttl_ms + 360 000)`, whatever `received_at` the server claims; the device keeps each signature it sealed under its current key one more `ttl_ms + 360 000` beyond that (those under a key it retires are dropped, ADR 0034), so that a backward step of its clock by up to that much cannot turn a server replay of an old genuine blob into a false alarm. Retention is keyed on the signed `sent_at`, never on a `received_at`. The retention is independent of the display purge and of local deletion; if the store has no room for a new signature, sealing fails rather than dropping one.
- One's own `pk_u` is never a peer: it skips the retired-key and peer-limit checks and has no `max_counter`, and the undefined "send counter − 1" at send counter 0 disappears (audit H, H-B5).
- On regeneration the old `pk_u` is recorded locally as retired, so later echoes of blobs sealed under it are `RetiredKey` and never appear as an unknown peer.
- The alert needs the victim to receive the thief's blob while it is still acceptable, from a server that does not withhold it; a server colluding with the thief can suppress it, as it can suppress any message (§2, §6).
- Refines the consequence of ADR 0019 about one's own key, replaces ADR 0027's `counter ≥` send counter condition for stale messages, and keeps ADR 0027's rule that a stale message moves no counter.
- Affected specs: 013-wire-message, 020-store-files, 021-channel-session, 023-ttl-purge, 024-key-retired, 025-identity-regen.
