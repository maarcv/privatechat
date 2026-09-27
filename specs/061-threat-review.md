# 061 — External review of the cryptographic and threat model

Status: draft
Phase: 6
Related ADRs: 0001, 0005, 0010, 0013, 0014, 0018, 0032, 0041
Depends on: 010-primitives-wrapper, 011-config-format, 012-message-keys, 013-wire-message, 014-fingerprint, 017-record-encoding, 020-store-files, 021-channel-session, 027-core-api, 031-auth-channel-signature, 042-connection-host, 053-device-security
Blocks: 062-security-docs, 063-beta, 064-public-release
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

Every audit so far (`docs/audit-log.md`, A to O) was made from inside the project. `docs/spec.md` §10 closes phase 6 only after an external review of the cryptographic and threat model, §12 lists "our own error in the format or in the key derivation" as the first risk, and `.github/SECURITY.md` tells users to treat the project as experimental until then. The human reviewer decided on 2026-09-27 that the review is requested from a funded programme for open-source privacy tools, the Open Technology Fund's Red Team Lab or an equivalent, and that the beta waits for its report (`docs/audit-log.md`, "Phase 6 drafts", Q12); and that a critical or high finding the project disputes closes only when the reviewers withdraw or downgrade it in writing (Q16).

This spec fixes what the project hands to the reviewers, what the review must cover, how the reviewed code is tied to what ships, how findings are handled, and what is published. It also owns `docs/residuals.md`, the list of every accepted limit, which the reviewers judge and spec 062-security-docs publishes. It does not choose the reviewers' method: that is theirs.

**In plain words.** Before strangers use the app, people who do not work on it, and who review security for a living, read the design and the code and try to break them. The project applies to a programme that pays for such reviews of free and open privacy tools. It prepares a folder with everything the reviewers need, fixes the exact version they read, lists every later change to the parts they read, and promises to fix every serious problem they find, or convince them in writing that it is not one, before the beta starts. Their report is published once the fixes are out.

## Requirements

**The request and the package**

- R1 The review MUST be requested from a programme that funds independent security reviews of open-source privacy software (the Open Technology Fund's Red Team Lab or an equivalent, Q12), by the human owner, with the package of R2. The request may go out before the freeze of R3, naming its planned date, since such programmes queue requests for months. The date of the request, the programme, the planned freeze and, once known, the firm that performs the review MUST be recorded in `docs/audit-log.md` under a section "External review". The firm MUST have had no part in writing the specs or the code.
- R2 `docs/residuals.md` MUST be the single list of the accepted limits of the system: one entry for each sentence of a spec's Security section that contains "documented residual", with the spec id, the audience (users, desktop users, phone users, server operators), and the residual in one plain sentence; and one entry for each finding the reviewers accepted as a residual (R6), with its "External review" row. `check_s061_t02_r02_residuals` in `scripts/doc_lint.py` MUST fail when the number of "documented residual" sentences of a spec differs from its number of entries, or an entry names a spec that has none. `docs/review/` MUST hold the package the reviewers receive, all in English:
  - `scope.md`: the frozen commit (R3) by its tag and its full commit SHA, the parts under review (R4) with their paths, the parts out of scope (`landing/`, store listings, the platform UIs' layout), the threat model of `docs/spec.md` §2 with its "Outside the model" list, the fingerprints of the release keys of `docs/release-keys.md` (spec 060-reproducible-builds R5), and the questions of R5;
  - `residuals.md`: `docs/residuals.md` as it stands at the frozen commit, copied by a script, so that the reviewers judge what the project already accepts;
  - `status.md`: for each spec of phases 1 to 5, its status and test results at the frozen commit, the fuzzing hours of spec 016-fuzz-harness per target, and the vector files that `cargo test` and the Kotlin and Swift tests reproduce;
  - `build.md`: how to build and test at the frozen commit, from `.github/CONTRIBUTING.md`.

**The frozen commit and its delta**

- R3 The review MUST read one frozen commit of the default branch, tagged `review-N` (N from 1) and signed as spec 060-reproducible-builds R1 signs release tags, taken only when every spec of phases 1 to 5 is `implemented` and CI is green. Every commit after it, up to the beta's release tag and during the beta, that touches a path or a spec of R4, a `Cargo.lock`, `vendor/`, `rust-toolchain.toml`, a `.cargo/config.toml` or any `unsafe` block, MUST be listed in `docs/review/delta.md` with its full SHA and its reason. The reviewers confirm the delta in writing before their report is final, and the report is final when the human owner records it in "External review"; the delta of `review-N` closes then. The beta's release tag MUST be `review-N` plus only delta rows the reviewers confirmed; any other change on the reviewed paths needs `review-N+1`, or a decision of the human reviewer recorded in "External review" with its reason.
- R4 The scope in `scope.md` MUST include at least: the cryptographic model of `docs/spec.md` §4 and its ADRs; the wire format, the key derivations, the domain tags and the envelope signature (specs 011–014, 017, and their vectors); the primitive wrapper and every `unsafe` block (spec 010); the store's encryption and commit rules (spec 020); the session and trust rules (specs 021–026, 028); the server's authentication, quotas and logging (specs 031–035); the connection host's TLS, SOCKS5 and certificate checks (spec 042); and the device measures of spec 053. The code review MUST cover `crates/core/src/crypto/`, `crates/core/src/proto/` and `crates/core/src/session/` in full.
- R5 `scope.md` MUST ask the reviewers at least: whether the key schedule of §4 and ADRs 0001, 0005, 0010, 0013, 0014, 0018 and 0032 gives the confidentiality and authenticity §1 promises; whether a server, a network observer or a member holding the config can learn or do more than §2 says; whether the trust-on-first-use flow of §7 and spec 055-verify-ui leads users to verify; whether any residual of `residuals.md` should not be accepted; and whether the store and device measures keep `K_db` and the channel keys as §8 says.

**Findings**

- R6 Every finding of the report MUST become a row of `docs/audit-log.md` "External review" with the reviewers' id and severity, and be closed by one of:
  - a fix, in the pull request that cites the row, confirmed by the reviewers in writing;
  - an ADR, when the fix changes a decision of §3–§6, confirmed by the reviewers in writing like a fix;
  - for a medium, low or informational finding, an acceptance by the human reviewer recorded in the row with its reason, whose sentence goes into the affected spec's Security section as a documented residual and into `docs/residuals.md`;
  - for a finding the project disputes, the project's response sent to the reviewers and their written withdrawal or downgrade of it (Q16); a critical or high finding is never closed by an ADR or an acceptance alone.
- R7 The beta (spec 063-beta) MUST NOT start while any finding of critical or high severity is open or its closing lacks the reviewers' written confirmation, and while the delta of R3 is unconfirmed. During the beta:
  - a fix of any finding, or of a security problem reported under `.github/SECURITY.md`, ships at once in a new release and is added to `delta.md`;
  - a follow-up review under the same programme is asked for when that fix changes a format, a derivation, a domain tag or a path of phase 1;
  - while a critical or high problem is open, the beta is paused, its testers told by mail to stop relying on it, and it cannot end (spec 063-beta R7).

**Publication**

- R8 The final report MUST be published in `docs/review/report-N.pdf`, with the reviewers' consent, as they wrote it, together with the project's responses to disputed findings, once every finding is fixed and released or closed as R6 allows, following the coordinated disclosure of `.github/SECURITY.md`. `.github/SECURITY.md`'s "External review" section then names the firm, the frozen commit's SHA and the date, in place of "pending", and links the report. A report the reviewers do not allow to be published is summarised in `docs/review/summary-N.md`, with their approval of the summary. The report's list of the release-key fingerprints (R2) is one of the out-of-band places spec 060-reproducible-builds names for them.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| Frozen commit | every spec of phases 1–5 `implemented`, CI green | no `review-N` tag |
| Changes after the freeze on the reviewed paths | listed in `delta.md` and confirmed by the reviewers | `review-N+1`, or a recorded decision |
| Open findings at the beta | none of critical or high severity, every closing confirmed | the beta does not start; during the beta, it pauses |
| A disputed critical or high finding | withdrawn or downgraded by the reviewers in writing | stays open |
| Reviewer | independent of the specs and the code | not accepted |

## Interface

```
docs/residuals.md                                                      R2, the single list
docs/review/scope.md, residuals.md, status.md, build.md, delta.md    R2, R3
docs/review/report-N.pdf or summary-N.md                              R8
docs/audit-log.md, section "External review"                          R1, R3, R6, R7
.github/SECURITY.md, section "External review"                        R8
scripts/doc_lint.py                                                   check_s061_* 
```

**PR slices** (AGENTS 14): (a) `docs/residuals.md` and its check (R2), which spec 062-security-docs then publishes; (b) the package (R2, R4, R5); (c) the frozen tag and the delta file (R3); (d) each group of findings, one pull request per finding or per spec (R6); (e) the publication (R7, R8).

## Security

- The review exists because the authors cannot audit their own blind spots: every earlier audit was internal. Its scope names the cryptography and the code that holds keys first (R4), and it reads one frozen commit plus a delta that lists every later change to what it read, dependencies and toolchain included, confirmed by the reviewers; the beta ships only that (R3). Nothing reviewed changes behind the reviewers.
- Serious findings cannot be waved away: a critical or high one is fixed, or changes the model, and the reviewers confirm the result in writing; a disputed one closes only with the reviewers' written agreement (R6, Q16). The beta waits for all of it and pauses if a new one appears (R7).
- The report is published with the project's responses once the fixes are out (R8), so users can judge the result without the report pointing at unfixed holes.
- The accepted limits are one list, `docs/residuals.md`, checked against the specs (R2), so nothing is accepted in one place and forgotten in another.

## Public API changes

None.

## Test cases

- T01 (covers R1): `check_s061_t01_r01_review_section`: when this spec is `implemented`, `docs/audit-log.md` has an "External review" section naming the programme, the request's date and the planned freeze; missing, the check fails.
- T02 (covers R2): `check_s061_t02_r02_residuals`: a fixture spec with two "documented residual" sentences and one entry fails; an entry for a spec with none fails; the real files pass; the four files of the package exist, and `docs/review/residuals.md` equals `docs/residuals.md` at the commit `scope.md` names.
- T03 (covers R3): `check_s061_t03_r03_frozen_commit`: the tag named in `scope.md` exists, is signed, and points at the SHA `scope.md` gives; every commit after it that touches a path of R3 appears in `delta.md` with its full SHA; a beta tag whose diff from `review-N` holds an unlisted or unconfirmed change fails.
- T04 (covers R4): `check_s061_t04_r04_scope`: `scope.md` names every spec and path of R4.
- T05 (covers R5): `check_s061_t05_r05_questions`: `scope.md` holds the five questions of R5 with the ADRs they name.
- T06 (covers R6): `check_s061_t06_r06_findings`: every row of "External review" has a severity and one closing of R6; a critical or high row closed by an ADR or an acceptance without a written confirmation fails, and a disputed row without the reviewers' withdrawal or downgrade fails; an accepted row whose sentence is not in the spec's Security section and in `docs/residuals.md` fails.
- T07 (covers R7): `check_s061_t07_r07_beta_gate`: the "Beta" start row of spec 063-beta cannot be written while a critical or high row is open or unconfirmed, or the delta unconfirmed; during the beta, a critical or high row opened after the start requires a "paused" row.
- T08 (covers R8): `check_s061_t08_r08_published`: once this spec is `implemented`, `docs/review/` holds a report or a summary, and `.github/SECURITY.md` names the frozen SHA and no longer says "pending"; a report published while a row is open fails.

## Vectors

None.

## Acceptance criterion

The documentation lint green with the checks of T01–T08; the package reviewed by the human reviewer before it is sent. Non-automatable: the programme accepts the request, the review takes place, and the report is received.

## Out of scope

- Choosing the reviewers' method and tools, and paying for a review outside the programme.
- A penetration test of the project's public server's hosting (spec 063-beta names the server; its operation is the operator's).
- Re-reviews after the public release, which each later release that changes a phase 1 spec asks for under a new `review-N`.

## Open questions

None.

## History

- 2026-09-27 draft (`docs/audit-log.md`, "Phase 6 drafts", Q12)
- 2026-09-27 revised after audit O round 1 (`docs/audit-log.md`): `docs/residuals.md` owned here, counted per residual sentence; the delta widened to every reviewed path, lock files, `vendor/`, toolchain and `unsafe`, confirmed by the reviewers, and the beta tag tied to it; the request allowed before the freeze; the report final when recorded; disputed findings closed only by the reviewers in writing (Q16) and ADR closings confirmed like fixes; fixes during the beta and the pause; publication after the fixes, with the project's responses; the key fingerprints in the package; the ADR list of R5
