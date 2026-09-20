# ADR 0013 — Message key derived directly from the counter

Date: 2026-09-20 · Status: accepted · Supersedes: 0003

## Context
ADR 0003 proposed a per-sender symmetric hash ratchet to obtain forward secrecy. Review B (finding B1, `docs/spec.md` §13) showed that it does not provide it: the root of each chain is derived from `K_ch` and `pk_u`, both available to whoever obtains the device, and therefore any key in the chain is recomputable. The ratchet only added chain state, a skipped-keys window, a forward skip limit (which desynchronised a sender forever after an offline period) and complexity in identity export.

## Decision
The key of each message is derived in O(1) from the sender and the counter with a single keyed PRF: `K_msg = KDF(K_ch, "msgkey__")` once per channel and `mk = BLAKE2b(key = K_msg, in = pk_u ‖ BE64(counter))` per message (`docs/spec.md` §4). There is no chain state nor any per-sender intermediate value. Anti-replay is a strictly increasing counter per sender (ADR 0019).

Review C (2026-09-20): the initial version of this ADR had two derivations (`K_send(u)` per sender and `mk_i` per counter). The "per-sender" indirection was a leftover from the ratchet and compartmentalised nothing, because everyone has `K_ch`; it has been merged into one.

## Alternatives considered
- Keeping the ratchet: cost without benefit, and the skip limit was an availability hole.
- Random per-sender seed distributed encrypted under `K_ch` and re-emitted periodically: falls just the same to "record traffic + steal `K_ch` later" and complicates member onboarding.
- Epoch jump with DH (real FS + PCS): v2, see ADR 0004 and §12.

## Consequences
- V1 has no cryptographic forward secrecy and says so (`docs/spec.md` §1). TTL deletion protects against an adversary who obtains the device **after** the messages have expired and has not recorded the traffic; nothing more.
- Smaller implementation: less local state, less fuzzing surface, simpler identity export.
- Per-message key and random nonce are two independent lifelines: if the random generator fails, the counter saves the day; if the counter were to repeat, the nonce saves it. It does not collapse to a single key per channel.
- Affected specs: 012-message-keys (replaces 012-ratchet), 020-store-files, 025-identity-regen.
