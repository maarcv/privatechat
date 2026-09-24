# ADR 0024 — Verify the signature before any state check, and expire by the signed send time

Date: 2026-09-24 · Status: superseded by 0027

## Context
The verification order of `docs/spec.md` §4 opened the encrypted header and then checked `RetiredKey`, `PeerLimit` and `Replay` before the signature. The header is a plain XChaCha20 XOR, so anyone on the path can flip chosen bits of `sender_pk` or `counter` without any key. Those checks then ran on unauthenticated values. This made the result of a mutated blob depend on the receiver's state, so the mutation table was not deterministic (audit E, findings A7, B9, C6). It also left room for side effects driven by forged values, such as evictions, the "new keys ignored" counter or a false "key may be compromised" alarm (B2).

Separately, client-side expiry used only `min(received_at, now_local)`, and the server supplies `received_at`. A malicious server could keep a blob past its TTL and deliver it months later, stamped as new, to anyone with no anti-replay state for that sender, and it would show as authentic and current (B1). That breaks the promise of §1 that expired messages are deleted on the client.

## Decision
The signature is checked immediately after the header is opened. No step before it reads state or has any effect. After the AEAD, a message whose signed `sent_at` satisfies `sent_at + ttl_ms + 360 000 < min(received_at, now)` is consumed and discarded as `Error::Expired`. The margin of 360 000 ms covers the rounding of `sent_at` to the minute plus five minutes of clock skew. The order and the rule are in `docs/spec.md` §4 "Verification on receive".

## Alternatives considered
- Keep the order, fix the receiver state for every vector and forbid side effects before the signature: secure, but the order stays harder to explain and the mutation table stays conditional.
- Expire only by `received_at`: trusts the server with the one promise the server is not trusted with (ADR 0009).
- Reject a stale `sent_at` without consuming it: the same blob would be retried against the signature on every reconnect.

## Consequences
- Nothing an attacker writes into an unauthenticated field can decide anything: every mutated byte of a well-formed blob yields `BadSignature`, whatever the receiver's state.
- The format functions of spec 013-wire-message become pure (phase 1). The state checks and the single commit stay in phase 2 (specs 021-channel-session, 022-peers-tofu, 026-peer-limits).
- One signature verification, tens of microseconds, is spent on duplicates after a reconnect before `Replay` discards them.
- A sender whose clock lags by more than five minutes loses its messages in channels whose TTL is shorter than the lag. The warning of §6 for a `sent_at` more than five minutes off already makes the skew visible.
- Affected specs: 013-wire-message, 021-channel-session, 022-peers-tofu, 023-ttl-purge, 026-peer-limits.
