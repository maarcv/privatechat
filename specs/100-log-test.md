# 100 — Log test

Status: draft
Phase: 6
Related ADRs: —
Depends on: 021-channel-session
Blocks: 063-beta
Human reviewer: — · Accepted on: —

## Context

`docs/spec.md` §8 "Logging" promises two tests. The first one, the redacted `Debug` of every type in `SECRET_TYPES`, belongs to spec 010 and is written there. The second one, the log test — an in-memory `tracing` subscriber that watches a full flow and proves no key reaches it — cannot live in spec 010: that spec is the libsodium wrapper, it emits nothing, and no crate of the workspace has a log emitter until the session (spec 021-channel-session). §8 and `AGENTS.md` rule 19 pointed at spec 010 for it, which is a promise no test could keep.

This spec is the parking place for that obligation, and it is `draft` on purpose. It holds the requirements until a spec that does emit logs can adopt them; if none does, it is implemented on its own. `docs/spec.md` §10 makes phase 6 the deadline: the project does not close with this spec still `draft`.

## Requirements

- R1 A test MUST install an in-memory `tracing` subscriber at TRACE level, run a full encrypt and decrypt flow with known keys, and assert that the captured output contains neither the lowercase hex nor the base64 of `K_ch`, `sk_u`, `sk_ch`, `K_msg`, `K_hdr` and `mk`, and not the full `channel_id` (`docs/spec.md` §8 "Logging").
- R2 The same test MUST assert that every `channel_id` and every `pk` that reaches the captured output appears only as the 8 lowercase hex characters of its first 4 bytes (`AGENTS.md` rule 19).
- R3 `scripts/doc_lint.sh` MUST fail while any tracked `*.rs` file contains the token `tracing::` and this spec is `draft`, so the obligation cannot stay parked once there is something to log.

## Limits

No external input and no variable-length field: this spec adds a test, not code. Not applicable.

## Interface

No signature, public or crate-internal. The test lives in the crate that first emits `tracing` events; the doc-lint check of R3 lives in `scripts/doc_lint.py` as `check_s100_t03_r03_log_test_is_not_parked_forever`.

## Security

This spec is itself a security check: it is the mechanical proof of the §8 promise that no key, and no full identifier, ever reaches a log. It handles no secret of its own; the known keys it uses are test fixtures.

## Public API changes

None.

## Test cases

- T01 (covers R1): full flow with known keys under a TRACE subscriber → the captured output contains none of the six secrets in hex or base64, and not the full `channel_id`. Named `s100_t01_r01_no_secret_reaches_the_log` while the requirement lives under this number.
- T02 (covers R2): a log event that carries a `channel_id` and a `pk` → only the 8 leading hex characters of each appear in the output. Named `s100_t02_r02_identifiers_are_truncated_to_four_bytes`.
- T03 (covers R3): `check_s100_t03_r03_log_test_is_not_parked_forever` in `scripts/doc_lint.py`, with its own fixture: a tracked `*.rs` file containing `tracing::` plus this spec at `Status: draft` MUST fail the lint.

## Vectors

None: no format and no derivation.

## Acceptance criterion

`cargo test s100_` green and `scripts/doc_lint.sh` green, in whichever crate the test ends up living. Non-automatable criterion: phase 6 does not close while this spec is `draft` (`docs/spec.md` §10, exit criterion of phase 6).

## Out of scope

- The redacted `Debug` test of `SECRET_TYPES`: it is spec 010, R3, and it is already written.
- The production log level (`warn` and nothing else, `docs/spec.md` §8): that is the subscriber configuration of each client, and it belongs to the client specs.
- Choosing the log emitter, its dependency and where the events are declared: that is the spec that first emits, and it arrives before this one.

## Open questions

- [ ] 100-R1: the preferred outcome is that spec 021-channel-session adopts R1 and R2 under its own number and deletes this file in the same pull request, leaving no spec numbered outside the phases. Confirm when 021 is written.

## History

- 2026-09-21 draft, created to hold the log test that spec 010 could not carry (open question 010-R15)
