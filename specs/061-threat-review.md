# 061 — External review of the cryptographic and threat model

Status: draft
Phase: 6
Related ADRs: 0004, 0012, 0013, 0014, 0018, 0032, 0041
Depends on: 010-primitives-wrapper, 011-config-format, 012-message-keys, 013-wire-message, 014-fingerprint, 017-record-encoding, 020-store-files, 021-channel-session, 027-core-api, 031-auth-channel-signature, 042-connection-host, 053-device-security
Blocks: 062-security-docs, 063-beta
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

Every audit so far (`docs/audit-log.md`, A to N) was made from inside the project. `docs/spec.md` §10 closes phase 6 only after an external review of the cryptographic and threat model, §12 lists "our own error in the format or in the key derivation" as the first risk, and `.github/SECURITY.md` tells users to treat the project as experimental until then. The human reviewer decided on 2026-09-27 that the review is requested from a funded programme for open-source privacy tools, the Open Technology Fund's Red Team Lab or an equivalent, and that the beta waits for its report (`docs/audit-log.md`, "Phase 6 drafts", Q12).

This spec fixes what the project hands to the reviewers, what the review must cover, how its findings are handled, and what is published. It does not choose the reviewer's method: that is the reviewer's.

**In plain words.** Before strangers use the app, people who do not work on it, and who review security for a living, read the design and the code and try to break them. The project applies to a programme that pays for such reviews for free and open privacy tools. It prepares a folder with everything the reviewers need, fixes the exact version they read, and promises to fix or explain every serious problem they find before the beta starts. Their report is then published.

## Requirements

- R1 The review MUST be requested from a programme that funds independent security reviews of open-source privacy software (the Open Technology Fund's Red Team Lab or an equivalent, Q12), by the human owner, with the package of R2; the date of the request, the programme and, once known, the firm that performs the review, MUST be recorded in `docs/audit-log.md` under a section "External review". The firm MUST have had no part in writing the specs or the code.
- R2 `docs/review/` MUST hold the package the reviewers receive, all in English:
  - `scope.md`: the frozen commit (R3), the parts under review (R4) with their paths, the parts out of scope (`landing/`, store listings, the platform UIs' layout), the threat model of `docs/spec.md` §2 with its "Outside the model" list, and the questions of R5;
  - `residuals.md`: every documented residual of the specs' Security sections, one line each with its spec, so that the reviewers judge what the project already accepts (spec 062-security-docs publishes the same list);
  - `status.md`: for each spec of phases 1 to 5, its status and test results at the frozen commit, the fuzzing hours of spec 016-fuzz-harness per target, and the vector files that `cargo test` and the Kotlin and Swift tests reproduce;
  - `build.md`: how to build and test at the frozen commit, from `.github/CONTRIBUTING.md`.
- R3 The review MUST read one frozen commit of the default branch, tagged `review-N` (N from 1) and signed as spec 060-reproducible-builds R1 signs release tags, taken only when every spec of phases 1 to 5 is `implemented` and CI is green. A change after it to `crates/core/src/crypto/`, `crates/core/src/proto/`, `specs/vectors/` or a spec of phase 1 MUST be listed in `docs/review/delta.md` with its reason before the reviewers' report is final, so that they can read it.
- R4 The scope in `scope.md` MUST include at least: the cryptographic model of `docs/spec.md` §4 and its ADRs; the wire format, the key derivations, the domain tags and the envelope signature (specs 011–014, 017, and their vectors); the primitive wrapper and every `unsafe` block (spec 010); the store's encryption and commit rules (spec 020); the session and trust rules (specs 021–026, 028); the server's authentication, quotas and logging (specs 031–035); the connection host's TLS, SOCKS5 and certificate checks (spec 042); and the device measures of spec 053. The code review MUST cover `crates/core/src/crypto/`, `crates/core/src/proto/` and `crates/core/src/session/` in full.
- R5 `scope.md` MUST ask the reviewers at least: whether the key schedule of §4 and ADRs 0012–0014, 0018 and 0032 gives the confidentiality and authenticity §1 promises; whether a server, a network observer or a member holding the config can learn or do more than §2 says; whether the trust-on-first-use flow of §7 and spec 055-verify-ui leads users to verify; whether any residual of `residuals.md` should not be accepted; and whether the store and device measures keep `K_db` and the channel keys as §8 says.
- R6 Every finding of the report MUST become a row of `docs/audit-log.md` "External review" with the reviewers' id and severity, and one of: a fix in the pull request that closes it, which cites the row; an ADR, when the fix changes a decision of §3–§6; or an explicit acceptance by the human reviewer, recorded in the row with its reason and added to `residuals.md`. A finding of critical or high severity MUST NOT be closed by acceptance alone: it is fixed, or the human reviewer records in an ADR why the model changes instead.
- R7 The beta (spec 063-beta) MUST NOT start while any finding of critical or high severity is open, and the reviewers MUST have confirmed each of their fixes, in writing, in a follow-up that `docs/audit-log.md` records.
- R8 The final report MUST be published in `docs/review/report-N.pdf`, with the reviewers' consent, as they wrote it, and linked from `.github/SECURITY.md`, whose "External review" section then names the firm, the frozen commit and the date, in place of "pending". A report the reviewers do not allow to be published is summarised in `docs/review/summary-N.md`, with their approval of the summary.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| Frozen commit | every spec of phases 1–5 `implemented`, CI green | no `review-N` tag |
| Open findings at the beta | none of critical or high severity | the beta does not start |
| Reviewer | independent of the specs and the code | not accepted |

## Interface

```
docs/review/scope.md, residuals.md, status.md, build.md, delta.md   R2, R3
docs/review/report-N.pdf or summary-N.md                               R8
docs/audit-log.md, section "External review"                           R1, R6, R7
.github/SECURITY.md, section "External review"                         R8
```

**PR slices** (AGENTS 14): (a) the package and its lint checks (R2, R4, R5); (b) the frozen tag and the delta file (R3); (c) each group of findings, one pull request per finding or per spec (R6); (d) the publication (R7, R8).

## Security

- The review exists because the authors cannot audit their own blind spots: every earlier audit was internal. Its scope names the cryptography and the code that holds keys first (R4), and it reads one frozen commit plus a listed delta (R3), so nothing reviewed changes behind the reviewers.
- Serious findings cannot be waved away: critical and high ones are fixed or change the model through an ADR, and the reviewers confirm the fixes before the beta (R6, R7).
- The report is published (R8), so users can judge the result themselves.

## Public API changes

None.

## Test cases

- T01 (covers R1): non-automatable: `docs/audit-log.md` "External review" names the programme and the request's date; `check_s061_t01_r01_review_section` fails when this spec is `implemented` and the section is missing.
- T02 (covers R2): `check_s061_t02_r02_package`: the four files of R2 exist; every spec whose Security section says "documented residual" appears in `residuals.md` by its id.
- T03 (covers R3): `check_s061_t03_r03_frozen_commit`: the tag named in `scope.md` exists and is signed; every commit after it that touches the paths of R3 appears in `delta.md`.
- T04 (covers R4): `check_s061_t04_r04_scope`: `scope.md` names every spec and path of R4.
- T05 (covers R5): `check_s061_t05_r05_questions`: `scope.md` holds the five questions of R5.
- T06 (covers R6): `check_s061_t06_r06_findings`: every row of "External review" has a severity and one of a pull request, an ADR or a recorded acceptance; a critical or high row closed only by acceptance fails.
- T07 (covers R7): `check_s061_t07_r07_beta_gate`: spec 063-beta cannot be marked `implemented` while a critical or high row is open or unconfirmed.
- T08 (covers R8): `check_s061_t08_r08_published`: once this spec is `implemented`, `docs/review/` holds a report or a summary and `.github/SECURITY.md` no longer says "pending".

## Vectors

None.

## Acceptance criterion

The documentation lint green with the checks of T01–T08; the package reviewed by the human reviewer before it is sent. Non-automatable: the programme accepts the request, the review takes place, and the report is received.

## Out of scope

- Choosing the reviewers' method and tools, and paying for a review outside the programme.
- A penetration test of the project's public server's hosting (spec 063-beta names the server; its operation is the operator's).
- Re-reviews after the beta: each later release that changes a phase 1 spec asks for one under a new `review-N`.

## Open questions

None.

## History

- 2026-09-27 draft (`docs/audit-log.md`, "Phase 6 drafts", Q12)
