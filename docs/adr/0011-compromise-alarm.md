# ADR 0011 — Compromise alarm

Date: 2026-09-19 · Status: deprecated

## Context
If a member sees a message signed with their key that they did not write, or suspects that the config has leaked, the rest need to know right away.

## Decision
A `compromise_alert` message type with a reason (`config_leaked`, `key_stolen`, `other`) and a note, signed like any other. The client shows it as a fixed red banner with the sender and the reason, switches the channel to read-only until the user acknowledges it and offers "Leave channel". The grouping rules, limits and the behaviour of "Leave channel" are in `docs/spec.md` §7.

## Alternatives considered
- No mechanism: the reaction would depend on someone saying so over another channel.

## Consequences
- **Review C (2026-09-20): withdrawn from v1.** A separate message type added a UI state machine (banner, read-only, once per 24 h, grouping, muting), a free-text note inside a system banner (phishing vector) and the possibility that a thief with `sk_u` could block the channel under the name of a verified victim. The only act with protocol semantics is key retirement (ADR 0016); "the config has leaked, new channel" is ordinary text. Stolen-key detection is done by the receiver of its own key (`docs/spec.md` §4 "Messages from one's own key"). It can be reintroduced in v1.x as a new CBOR key if usage calls for it.
- It gives no deniability (a valid signature still proves that the key holder wrote the message); it is a tool for reaction, not for denial.
- An alarm proves that whoever holds the key has it, not who the person is: a key thief can also emit one. The correct action is always to verify out of band.
- Alarms from unknowns do not block and are grouped; those from the same sender only block once per 24 h (defence against spam and social blocking).
- A `key_stolen` alarm links to key retirement (ADR 0016) and to the new channel (ADR 0008).
