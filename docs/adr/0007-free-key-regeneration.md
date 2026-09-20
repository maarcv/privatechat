# ADR 0007 — Free key regeneration with no link to the old key

Date: 2026-09-19 · Status: accepted

## Context
A user may want to change their key for a channel (new phone, suspected copy). Announcing the change signed with the old key in order to keep the label was considered.

## Decision
The user can regenerate the key of a channel whenever they want, with no linking message between the old key and the new one. They reappear as unknown and the other members have to label and verify them again. The old key, if still held, is retired with `key_retired` (ADR 0016), which closes the old one without pointing to the new one.

## Alternatives considered
- Key change signed with the old key pointing to the new one: keeps continuity automatically, but requires having the old key (useless if the device has been lost) and leaves a trail between keys.

## Consequences
- Simplicity and no link between identities.
- UX cost: manual re-verification. Mitigated with a very visible "unknown" UI, QR pre-verification and labels that cannot be reused without verifying (§7).
- Social risk: "I changed my phone" as an impersonation vector. Mitigated in §7.
- There is no private key export: a key lives on a single device (ADR 0019). Changing device = re-importing the config and regenerating.
