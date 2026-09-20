# ADR 0019 — One key, one device: strictly increasing counter

Date: 2026-09-20 · Status: accepted

## Context
Review B introduced a 4 096-position anti-replay sliding window with a bitmap per sender, and kept identity export between devices (same `sk_u` in two places, with a +1 024 jump in the counter on import). Review C showed (finding C2) that the window only protects whoever saw the original: an intruder with the config can re-inject an old blob from Alice to a member who joined later, to one who was offline for more than one TTL, or to an evicted unknown, and the message reappears authenticated by Alice with the current time. In a system where each `sk_u` lives on a single device and the server delivers each channel in total order, a counter lower than the maximum seen has no legitimate cause. Identity export was the only reason for the window, and was at the same time the source of a class of failures (same key on two devices, counter reuse, "the destination confirms" with no protocol, deletion at the origin not enforceable).

## Decision
A key `sk_u` lives on a single device and is not exported. Changing device = re-importing the config and regenerating the identity (ADR 0007, 0016). Anti-replay is a strictly increasing counter per sender: `counter ≤ max_counter → Replay`; `counter > max_counter → accept`. No window, no bitmap. The server assigns a strictly increasing `received_at` per process, so that the delivery order is total. The sender reserves and persists the counter before emitting the blob, and drains its `outbox` in order.

## Alternatives considered
- Keeping the window and adding `first_counter` per peer (rejecting any counter earlier than the first accepted one): works, but keeps 512 B of state per peer, two error codes and identity export with its failure modes.
- Keeping identity export: a convenience (keeping "Verified" when changing phone) that the spec itself discouraged as the recommended path.

## Consequences
- Replay is also closed for receivers with no prior state for a sender (except the first message they see from them, which sets `max_counter`).
- Gone: the bitmap, `Error::TooOld`, the `PKEY` format, the "+1 024" rule, `export_identity`/`import_identity` from the API, the second password and the double installation as a failure mode.
- If the client receives a valid message from its own `pk` with a counter ≥ its own, the key is somewhere else: it advances the counter and alerts the user (`docs/spec.md` §4).
- Affected specs: 012-message-keys, 021-channel-session, 025-identity-regen, 032-storage-ttl.
