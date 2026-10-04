# ADR 0044 — Measure a message's life in the client from its signed send time alone

Date: 2026-10-04 · Status: accepted

## Context
ADR 0027 judges a message stale against `min(received_at, now)`, and ADR 0030 adds a bound for dates in the future. Two clocks therefore decide how long a message lives on a device: the signer's `sent_at`, which nobody can change, and the server's `received_at`, which the server chooses and the client may only clamp. Because the server's clock is the reference, a blob is acceptable while `now` lies in `[sent_at − T, sent_at + 2T]`, with `T = ttl_ms + 360 000` (ADR 0030, Consequences). Every window built on top of it doubles or triples:

- own-key blobs are accepted until `2T`, and kept signatures last until `3T`;
- seen records last until `2·ttl_ms + 360 000`;
- display expiry and purge come from `min(max(received_at, sent_at − 360 000), now) + ttl_ms`;
- a second check of the display expiry sits in spec 021-channel-session R10.

Audit AC (`docs/audit-log.md`, AC7) counted about ten requirements and their tests in specs 021-channel-session and 023-ttl-purge that only exist to carry this second clock. The server is the adversary the TTL rule exists for (ADR 0009), and every one of those values lets a server-chosen number change what the device accepts or how long it keeps it.

## Decision
The channel session measures every message's life from its signed `sent_at` and its own clock alone:

- **Stale.** A message is stale when `sent_at + T < now` or `now + T < sent_at`, and ADR 0027 then treats it as before.
- **Expiry.** A peer's message is shown and kept until `min(sent_at, the time it arrived) + ttl_ms`.
- **What `received_at` is still for.** The server's `received_at` only orders the list and moves the cursor. It decides nothing else, except for a blob with no readable `sent_at`.

Spec 013-wire-message keeps its own step 2 (`min(received_at, now) + T < now`) and its stale test against `min(received_at, now)`, with their vectors, which are frozen (AGENTS 18). Both reject only blobs the session would also reject. They remain as redundant, harmless checks, with no change to the wire format or to `proto_version`.

## Alternatives considered
- **Keep both clocks** (ADR 0027 and 0030 as applied): the 2T and 3T windows and the clamps stay. A server keeps some say over how long a device accepts and keeps a message.
- **Also remove step 2 and the `min(received_at, now)` reference from spec 013:** cleaner. But it rewrites the frozen vectors and needs a `proto_version` change for a check that rejects nothing the session would accept.
- **Use the server's `received_at` alone:** this trusts the server with the one promise it is not trusted with (ADR 0009).

## Consequences
- A blob is acceptable only while `now` lies in `[sent_at − T, sent_at + T]`.
- **Own-key blobs.** A blob from one's own key is accepted, and raises the alert, only until `sent_at + T`. Each kept signature lasts until `sent_at + 2T`, so the clock can step back by up to `T` without a server replay of a genuine old blob raising a false alarm, the same tolerance as before.
- **Seen records.** A peer's seen record lasts until `sent_at + ttl_ms`. A seen record from one's own key lasts until `sent_at + T`.
- **What `received_at` can no longer do.** No value the server chooses moves a message's acceptance, display or purge. A server that keeps a blob past its TTL cannot revive it for a member who has no counter for its sender, such as a new member or one restoring a lost device (`docs/spec.md` §2).
- **Delay is now spent.** A message that waited in the `outbox`, or on the server, for a time `d` is shown for `ttl_ms − d` from when it arrives, no longer a full TTL from the server's receipt. A reader who connects late can miss a message the server still holds. The TTL now means "gone a TTL after it was written".
- **Delivered.** An `ack` reports `Delivered` only while `sent_at + ttl_ms ≥ now`. The two-sided check of ADR 0034 on the `ack`'s `received_at` stays.
- **What stands.** The decisions of ADR 0027 and ADR 0030 stand. This ADR changes the reference clock of ADR 0027's stale test and the acceptance range in ADR 0030's Consequences, for the client session only.
- **Affected documents:** specs 021-channel-session and 023-ttl-purge; `docs/spec.md` §2, §4 and §6.
