# ADR 0033 — Seal every `key_retired` with the last counter

Date: 2026-09-24 · Status: accepted

## Context
ADR 0016 retires a stolen key with a `key_retired` message signed by that key. The message was sealed with the sender's next send counter, and every receiver checks replay (`counter ≤ max_counter` → `Replay`, `docs/spec.md` §4 step 6) before the AEAD, so before it knows the message type. Audit H (`docs/audit-log.md`, H43) found that a thief who holds the key and keeps writing with rising counters gets a blob delivered before the victim's `key_retired` with no help from the server. Every receiver then already holds a `max_counter` above the retirement's counter and discards it as `Replay`. The victim has erased the old `sk_u` in the same commit, so it cannot sign again. Nobody is told, the thief keeps writing as "Alice ✓" to everyone else, and the victim's own device, which has marked the key retired, no longer shows the thief's messages.

## Decision
A `key_retired` is always sealed with `counter = 2^64 − 1`, whatever the send counter; ordinary messages never use that counter, because `Channel::encrypt` refuses it with `CounterExhausted`. Receivers leave a `key_retired` out of the gap and anomalous-jump signals.

## Alternatives considered
- Letting a `key_retired` through the replay check: the receiver would need the type before step 6, so the AEAD would run before the replay check and the verification order of ADR 0027 would change.
- Keeping the old `sk_u` to retry with a higher counter: the thief can always write a higher one first.

## Consequences
- No ordinary message of a thief can make the retirement `Replay`: its counter is at most `2^64 − 2`.
- A thief who writes first with `2^64 − 1` himself still makes the retirement `Replay` for every receiver that saw his message first, and nobody is told: the victim's own device has already recorded the key as retired, so his message is `RetiredKey` there and raises no alert unless it arrived before the regeneration. His message is, however, the last the key can ever write to those receivers, since every later counter is `Replay`. The thief gains one message and the retirement fails only where the key is already dead.
- A receiver that consumes the retirement sets `max_counter = 2^64 − 1`, so a second copy of it is `Replay`.
- Refines ADR 0016 and the send-counter rule of ADR 0019. Affected specs: 013-wire-message, 021-channel-session, 024-key-retired, 025-identity-regen.
