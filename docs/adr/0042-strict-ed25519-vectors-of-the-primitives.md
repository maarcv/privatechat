# ADR 0042 — Prove strict Ed25519 with published cases a lax verifier accepts

Date: 2026-10-01 · Status: accepted

## Context
Verification must be strict (`docs/spec.md` §4 "Primitives", spec 010-primitives-wrapper R10): a small-order or non-canonical key or `R`, or an `S` at or above the group order `L`, is a forgery, never a message. The server relies on it for the channel key of a subscription (spec 031-auth-channel-signature). Spec 010's Security section says the negative vectors of `010.json` prove it at test time. Audit Y found that four of the five did not (`docs/audit-log.md`, "Audit Y", AY1): they pair the signature of RFC 8032 TEST 1 with another key or a changed `R`, so the verification equation fails and a verifier without the strict checks rejects them too; and three names did not say what the points are (`pk_identity` is the point of order 4, `pk_small_order` is not on the curve, `r_small_order` is of large order). Only `signature_s_plus_l` caught a lax build. AGENTS 18 froze every file under `specs/vectors/` when phase 1 closed.

## Decision
`010.json`, which describes no format of the protocol and which no script produces, gains the twelve published cases of ed25519-speccheck (Chalkias, Garillot, Nikolaenko, "Taming the many EdDSAs", 2020) as `speccheck_0`–`speccheck_11`, the eleven libsodium rejects as negatives and case 3 as a positive, and its three misnamed vectors are renamed `pk_order_4`, `pk_not_on_curve` and `r_wrong_point`; `proto_version` stays 1, and a later addition of published primitive cases to `010.json` needs an ADR but no version change.

## Alternatives considered
- Keep `010.json` frozen and soften spec 010's Security text: strictness, which the server depends on, would stay untested, and a build of libsodium with `ED25519_COMPAT` or a later change of its checks would pass every test but one.
- Construct our own small-order and non-canonical cases with the reference script: values derived by this project prove less than a set other implementations already test against, and the script would gain curve code no format needs.
- Raise `proto_version`: no byte any client sends changes, so a version bump would announce a format change that does not exist.

## Consequences
- A verifier that skips the small-order, canonicity or `S < L` checks now fails T15 of spec 010 on the cases built to defeat it (0–2, 6, 7, 11 and `signature_s_plus_l`); one that uses the cofactored equation or does not compare `R`'s encoding fails cases 4, 5 and 8–10; one that rejects a valid mixed-order signature fails case 3.
- Only the Rust tests and the reference script's self-checks read `010.json`; no client platform does.
- AGENTS 18, spec 010 (R10, T15, Vectors, Security), `specs/vectors/README.md` and `docs/spec.md` §3 and §4 are amended; the 011–017 vector files stay frozen.
