# ADR 0008 — No member removal: a new channel is created

Date: 2026-09-19 · Status: accepted

## Context
Removing a member from an encrypted group requires the rest to agree on a new key that the removed member does not know.

## Decision
There is no removal operation. To remove someone, the remaining members create a new channel and share its config out of band.

## Alternatives considered
- Selective rekey (MLS-style key tree): efficient for large groups, but incompatible with ADR 0001 (no member management on the server) and far more complex.

## Consequences
- Consistent with ADR 0001 and 0004.
- The UX of "create a new channel from this one" (same name, new `K_ch`, list of verified peers to re-invite) must be fast.
- If the leak comes from a member's device, the new channel will leak again by the same path: the UX asks "do you know where it came from?" and recommends excluding the suspected member.
