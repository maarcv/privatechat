# ADR 0016 — Key retirement with a `key_retired` message

Date: 2026-09-20 · Status: accepted

## Context
The scenario that motivates regenerating a key (suspected copy, lost device) is exactly the one in which someone else has `sk_u`. With ADR 0007 as it stood, on regenerating the key the other members kept the old peer as labelled or verified: the thief could keep writing as "Alice ✓" while the real Alice appeared as unknown, and her compromise alarm from the new key was "from an unknown" and did not block (finding B7). There was no retirement mechanism.

## Decision
New payload type `key_retired`, with an empty body, signed with the key being retired. The receiver marks the peer as **Retired**: it keeps the label as "Alice (key retired on DD/MM)" and rejects any message from this `pk` received after the retirement, whatever its counter. Presentation and regeneration flow in `docs/spec.md` §7.

## Alternatives considered
- No mechanism: the stolen key remains valid until each member erases it by hand, with nothing telling them to.
- Signed key change pointing to the new key: rejected in ADR 0007 (trail between identities; useless if the key has been lost).
- Retiring via compromise alarm: an alarm can also be emitted by the thief; explicit retirement is a different and unambiguous action.

## Consequences
- A thief who holds `sk_u` can also emit the victim's `key_retired`: the effect is to close the key, which is what the victim would want. They cannot revert it. If the client receives a `key_retired` for its own key, the channel becomes read-only until regeneration.
- `regenerate_identity` writes the `key_retired` to `outbox` in the same commit that erases the old key; this way it is not lost if the UI is offline (refined by ADR 0033, its counter, and ADR 0034, which keeps the old key until the retirement is acknowledged).
- New state in the peer diagram and `retired_at` column (`docs/spec.md` §7).
- The type is added to the v1 enum before freezing the format (spec 013).
- Affected specs: 022-peers-tofu, 024-key-retired, 025-identity-regen, 055-verify-ui.
