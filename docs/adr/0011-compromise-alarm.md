# ADR 0011 — Compromise alarm

Date: 2026-09-19 · Status: deprecated

## Context
If a member sees a message signed with their key that they did not write, or suspects that the config has leaked, the rest need to know right away.

## Decision
A `compromise_alert` message type with a reason (`config_leaked`, `key_stolen`, `other`) and a note, signed like any other. The client shows it as a fixed red banner with the sender and the reason, switches the channel to read-only until the user acknowledges it and offers "Leave channel". The grouping rules and limits are no longer specified (rules removed from §7 in review C); "Leave channel" is in `docs/spec.md` §7.

## Alternatives considered
- No mechanism: the reaction would depend on someone saying so over another channel.

## Consequences
- **Review C (2026-09-20): withdrawn from v1.** A separate message type added a UI state machine (banner, read-only, once per 24 h, grouping, muting), a free-text note inside a system banner (phishing vector) and the possibility that a thief with `sk_u` could block the channel under the name of a verified victim. The only act with protocol semantics is key retirement (ADR 0016); "the config has leaked, new channel" is ordinary text. Stolen-key detection is done by the receiver of its own key (`docs/spec.md` §4 "Messages from one's own key"). It can be reintroduced in v1.x as a new payload key if usage calls for it.
