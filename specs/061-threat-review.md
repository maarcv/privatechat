# 061 — External review of the cryptographic and threat model

Status: accepted
Phase: 6
Related ADRs: 0001, 0005, 0010, 0013, 0014, 0018, 0032, 0041
Depends on: 010-primitives-wrapper, 011-config-format, 012-message-keys, 013-wire-message, 014-fingerprint, 017-record-encoding, 020-store-files, 021-channel-session, 027-core-api, 031-auth-channel-signature, 040-uniffi, 041-desktop-bridge, 042-connection-host, 053-device-security, 060-reproducible-builds (its PR slice (c), the keys)
Blocks: 062-security-docs, 063-beta, 064-public-release, 065-release-maintenance
Human reviewer: Marc Vilardebó · Accepted on: 2026-09-28

## Context

Every audit so far (`docs/audit-log.md`, A to O) was made from inside the project. `docs/spec.md` §10 closes phase 6 only after an external review of the cryptographic and threat model, §12 lists "our own error in the format or in the key derivation" as the first risk, and `.github/SECURITY.md` tells users to treat the project as experimental until then. The human reviewer decided on 2026-09-27 that the review is requested from a funded programme for open-source privacy tools, the Open Technology Fund's Red Team Lab or an equivalent, and that the beta waits for its report (`docs/audit-log.md`, "Phase 6 drafts", Q12); and, during audit O, that a critical or high finding the project disputes closes only when the reviewers withdraw or downgrade it in writing ("Audit O", O-Q2).

This spec fixes what the project hands to the reviewers, what the review must cover, how the reviewed code is tied to what ships, how findings are handled, and what is published. It also owns `docs/residuals.md`, the list of every accepted limit, which the reviewers judge and spec 062-security-docs publishes. It does not choose the reviewers' method: that is theirs.

**In plain words.** Before strangers use the app, people who do not work on it, and who review security for a living, read the design and the code and try to break them. The project applies to a programme that pays for such reviews of free and open privacy tools. It prepares a folder with everything the reviewers need, fixes the exact version they read, lists every later change to the parts they read, and promises to fix every serious problem they find, or convince them in writing that it is not one, before the beta starts. Their report is published once the fixes are out.

## Requirements

**The request and the package**

- R1 The review MUST be requested from a programme that funds independent security reviews of open-source privacy software (the Open Technology Fund's Red Team Lab or an equivalent, Q12), by the human owner, with a draft of the package of R2. The request may go out before the freeze of R3, naming its planned date, since such programmes queue requests for months; the package itself is committed after the `review-N` tag of R3 exists and names it, and is what the reviewers receive. The date of the request, the programme, the planned freeze and, once known, the firm that performs the review MUST be recorded in `docs/audit-log.md` under a section "External review". The firm MUST have had no part in writing the specs or the code.
- R2 `docs/residuals.md` MUST be the single list of the accepted limits of the system: one entry for each sentence of a spec's Security section that contains "documented residual", matched without regard to case, with the spec id, the audience (users, desktop users, phone users, server operators), and the residual in one plain sentence; and one entry for each finding the reviewers accepted as a residual (R6), with its "External review" row. `check_s061_t02_r02_residuals` in `scripts/doc_lint.py` MUST fail when the number of "documented residual" sentences of a spec differs from its number of entries, or an entry names a spec that has none. The phrase is the contract: a limit that a spec states in other words ("§6 documents", "the help says so") is not a residual until its Security sentence says "documented residual", and no other source, `docs/spec.md` included, is harvested; each spec that accepts a limit words it so. `docs/review/` MUST hold the package the reviewers receive, all in English:
  - `scope.md`: the frozen commit (R3) by its tag and its full commit SHA, the parts under review (R4) with their paths, the parts out of scope (`landing/`, store listings, the platform UIs' layout), the threat model of `docs/spec.md` §2 with its "Outside the model" list, the fingerprints, in `SHA256:…` form, of every key listed in `docs/release-keys.md` (spec 060-reproducible-builds R5), which the reviewers are asked to print in their report together with the one-line check of spec 060-reproducible-builds R8, and the questions of R5;
  - `residuals.md`: `docs/residuals.md` as it stands at the frozen commit, copied by a script, so that the reviewers judge what the project already accepts;
  - `status.md`: for each spec of phases 1 to 5, its status and test results at the frozen commit, the fuzzing hours of spec 016-fuzz-harness per target, and the vector files that `cargo test` and the Kotlin and Swift tests reproduce;
  - `build.md`: how to build and test at the frozen commit, from `.github/CONTRIBUTING.md`.

**The frozen commit and its delta**

- R3 The review MUST read one frozen commit of the default branch, tagged `review-N` (N from 1) and signed as spec 060-reproducible-builds R1 signs release tags, taken only when every spec of phases 1 to 5 is `implemented`, CI is green, the keys slice of spec 060-reproducible-builds has landed (`docs/release-keys.md` and `.github/allowed_signers` exist), so that the tag can be signed and `scope.md` can list the fingerprints, and the app code that spec 060-reproducible-builds R2 (the versions and the "RC" flag derived from the tag) and spec 063-beta R3 (the beta label and expiry) require is implemented, so that the reviewers read it. Every commit after it, up to the "Public release" row of spec 064-public-release, that touches any of these MUST be listed in `docs/review/delta.md` with its full SHA and its reason:
  - a path or a spec of R4;
  - every lock file and release-infrastructure path of spec 060-reproducible-builds R2: each `Cargo.lock`, `pnpm-lock.yaml`, Gradle's verification metadata, `Package.resolved`, the release wrapper script, `deploy/release/Dockerfile` and `.github/workflows/`;
  - `vendor/`, `rust-toolchain.toml`, a `.cargo/config.toml`, or any `unsafe` block.
  The reviewers confirm in writing every row listed before their report is final, and the report is final when the human owner records it in "External review". The delta stays open after that, until the "Public release" row; after it, spec 065-release-maintenance R1 keeps listing, with rows marked `unreviewed`. A change on the other paths listed above, outside R4, may ship with a decision of the human reviewer recorded in its row, with its reason. Outside a pause of R7, every `-beta.N` tag MUST be `review-N` plus rows the reviewers confirmed, plus the security-fix rows of R7, plus rows with a human reviewer's decision on paths outside R4, plus commits that touch no path listed above, which need no row; a change on a path or a spec of R4 that is none of these needs `review-N+1`. The first public `vX.Y.Z` tag, that of spec 064-public-release, MUST be on the last `-beta.N` tag's commit, or add to it only rows the reviewers confirmed and commits that touch no listed path; every later tag follows spec 065-release-maintenance R1.
- R4 The scope in `scope.md` MUST include at least: the cryptographic model of `docs/spec.md` §4 and its ADRs; the wire format, the key derivations, the domain tags and the envelope signature (specs 011–014, 017, and their vectors); the primitive wrapper and every `unsafe` block (spec 010); the store's encryption and commit rules (spec 020); the session and trust rules (specs 021–026, 028); the server's authentication, quotas and logging (specs 031–035); the connection host's TLS, SOCKS5 and certificate checks (spec 042); the uniffi boundary where secrets cross to Kotlin and Swift (spec 040); the Rust side of the desktop, which holds the storage key and fixes what the web view can reach through its IPC capabilities (spec 041); and the device measures of spec 053. The code review MUST cover `crates/core/src/crypto/`, `crates/core/src/proto/` and `crates/core/src/session/` in full.
- R5 `scope.md` MUST ask the reviewers at least: whether the key schedule of §4 and ADRs 0001, 0005, 0010, 0013, 0014, 0018 and 0032 gives the confidentiality and authenticity §1 promises; whether a server, a network observer or a member holding the config can learn or do more than §2 says; whether the trust-on-first-use flow of §7 and spec 055-verify-ui leads users to verify; whether any residual of `residuals.md` should not be accepted; and whether the store and device measures keep `K_db` and the channel keys as §8 says.

**Findings**

- R6 Every finding of the report MUST become a row of `docs/audit-log.md` "External review" with the reviewers' id and severity, and be closed by one of:
  - a fix, in the pull request that cites the row, confirmed by the reviewers in writing;
  - an ADR, when the fix changes a decision of §3–§6, confirmed by the reviewers in writing like a fix;
  - for a medium, low or informational finding, an acceptance by the human reviewer recorded in the row with its reason, whose sentence goes into the affected spec's Security section as a documented residual and into `docs/residuals.md`;
  - for a finding the project disputes, the project's response sent to the reviewers and their written withdrawal or downgrade of it ("Audit O", O-Q2); a critical or high finding is never closed by an ADR or an acceptance alone.
  Every security problem reported under `.github/SECURITY.md` during the beta MUST also become a row, with the reporter's description and no personal data, and counts as high until the reviewers or the programme downgrade it in writing; it closes by the same rules.
- R7 The beta (spec 063-beta) MUST NOT start while any finding of critical or high severity is open or its closing lacks the reviewers' written confirmation, or while a row of the delta of R3 is unconfirmed, other than a row with a human reviewer's decision on a path outside R4. During the beta:
  - when a critical or high row opens, the beta is paused: the "Paused" row of spec 063-beta is written that day, and its testers are told by mail to stop relying on it;
  - while paused, a fix of that row ships at once in a new `-beta.N` build, with its delta row and a decision of the human reviewer recorded in it;
  - a follow-up review under the same programme is asked for when a fix changes a format, a derivation, a domain tag or a path of phase 1; spec 063-beta cites this rule;
  - the "Resumed" row of spec 063-beta is written only once every critical or high row is closed and the reviewers have confirmed each fix and each delta row shipped during the pause in writing; the beta cannot end while paused.

**Publication**

- R8 The final report MUST be published in `docs/review/report-N.pdf`, with the reviewers' consent, as they wrote it, together with the project's responses to disputed findings, once every finding is fixed and released or closed as R6 allows, following the coordinated disclosure of `.github/SECURITY.md`; a fix is released when it is in the beta's release tag. `.github/SECURITY.md`'s "External review" section then names the firm, the frozen commit's SHA and the date, in place of "pending", links the report and `docs/review/delta.md`, and keeps the line that the project is experimental until the public release, which spec 064-public-release removes. A report the reviewers do not allow to be published is summarised in `docs/review/summary-N.md`, with their approval of the summary. Only the copy of the report that the firm or the programme publishes on its own site counts as an out-of-band place for the release-key fingerprints of spec 060-reproducible-builds: the copy in the repository is for reading, since whoever controls the repository could change it.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| Frozen commit | every spec of phases 1–5 `implemented`, CI green | no `review-N` tag |
| Changes after the freeze on the reviewed paths | listed in `delta.md` until the "Public release" row, and confirmed by the reviewers | on a path of R4, `review-N+1`; on another listed path, a recorded decision |
| Open findings at the beta | none of critical or high severity, every closing confirmed | the beta does not start; during the beta, it is paused |
| A security report during the beta | high until the reviewers downgrade it | the beta is paused |
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

- The review exists because the authors cannot audit their own blind spots: every earlier audit was internal. Its scope names the cryptography and the code that holds keys first (R4), and it reads one frozen commit plus a delta that lists every later change to what it read, dependencies, release infrastructure and toolchain included, until the beta ends, confirmed by the reviewers; the beta ships only that and security fixes the reviewers confirm (R3, R7). Nothing on a reviewed path changes behind the reviewers; only lock files and release infrastructure may move on a recorded human decision.
- Serious findings cannot be waved away: a critical or high one is fixed, or changes the model, and the reviewers confirm the result in writing; a disputed one closes only with the reviewers' written agreement (R6, O-Q2). A security report during the beta counts as high until the reviewers say otherwise, so the project cannot avoid a pause by grading its own problem (R6). The beta waits for all of it and pauses if a new one appears (R7).
- The report is published with the project's responses once the fixes are out (R8), so users can judge the result without the report pointing at unfixed holes. The fingerprints it prints count only in the copy on the reviewers' own site (R8).
- The accepted limits are one list, `docs/residuals.md`, checked against the specs (R2), so nothing is accepted in one place and forgotten in another.

## Public API changes

None.

## Test cases

- T01 (covers R1): `check_s061_t01_r01_review_section`: when this spec is `implemented`, `docs/audit-log.md` has an "External review" section naming the programme, the request's date and the planned freeze; missing, the check fails; a package committed before its `review-N` tag exists fails.
- T02 (covers R2): `check_s061_t02_r02_residuals`: `scope.md` asks the reviewers to print the fingerprints and the one-line check of spec 060-reproducible-builds R8; a fixture spec with two "documented residual" sentences and one entry fails, and so does one whose sentence says "Documented residual"; an entry for a spec with none fails; a fixture sentence that says "§8 documents this" without the phrase is not counted; the real files pass; the four files of the package exist, and `docs/review/residuals.md` equals `docs/residuals.md` at the commit `scope.md` names.
- T03 (covers R3): `check_s061_t03_r03_frozen_commit`: the tag named in `scope.md` exists, is signed, points at the SHA `scope.md` gives, and was taken after `docs/release-keys.md` and `.github/allowed_signers` existed; every commit after it, until the "Public release" row, that touches a path of R3 appears in `delta.md` with its full SHA; a `-beta.N` tag outside a pause whose diff from `review-N` holds an unlisted change on a listed path, or an unconfirmed change on a path of R4, fails, while a commit that touches no listed path passes; a fixture change to `pnpm-lock.yaml` without its row fails; the first public `vX.Y.Z` tag, if it adds to the last beta tag an unconfirmed row, fails, and a later `vX.Y.Z` tag is not checked here (spec 065-release-maintenance T01); a `review-N` tag taken before the version derivation of spec 060-reproducible-builds R2 or the beta label and expiry of spec 063-beta R3 exist fails.
- T04 (covers R4): `check_s061_t04_r04_scope`: `scope.md` names every spec and path of R4, specs 040 and 041 included.
- T05 (covers R5): `check_s061_t05_r05_questions`: `scope.md` holds the five questions of R5 with the ADRs they name.
- T06 (covers R6): `check_s061_t06_r06_findings`: every row of "External review" has a severity and one closing of R6; a critical or high row closed by an ADR or an acceptance without a written confirmation fails, and a disputed row without the reviewers' withdrawal or downgrade fails; an accepted row whose sentence is not in the spec's Security section and in `docs/residuals.md` fails; a row from a `.github/SECURITY.md` report during the beta with a severity below high and no written downgrade fails.
- T07 (covers R7): `check_s061_t07_r07_beta_gate`: the "Start" row of spec 063-beta cannot be written while a critical or high row is open or unconfirmed, or a delta row unconfirmed other than one with a human reviewer's decision on a path outside R4; a critical or high row opened after the start without a "Paused" row dated that day fails; a "Resumed" or "End" row written while such a row is open, or while a fix or delta row of the pause lacks the reviewers' confirmation, fails.
- T08 (covers R8): `check_s061_t08_r08_published`: once this spec is `implemented`, `docs/review/` holds a report or a summary, and `.github/SECURITY.md` names the frozen SHA, links `delta.md`, keeps the "experimental until the public release" line until a "Public release" row of spec 064-public-release exists, and no longer says "pending"; a report published while a row dated before its publication is open fails; rows opened after the publication are not counted.

## Vectors

None.

## Acceptance criterion

The documentation lint green with the checks of T01–T08; the package reviewed by the human reviewer before it is sent. Non-automatable: the programme accepts the request, the review takes place, and the report is received.

## Out of scope

- Choosing the reviewers' method and tools, and paying for a review outside the programme.
- A penetration test of the project's public server's hosting (its operation is spec 066-public-server's).
- Re-reviews after the public release: when one is needed is spec 065-release-maintenance R1's rule.

## Open questions

None.

## History

- 2026-09-27 draft (`docs/audit-log.md`, "Phase 6 drafts", Q12)
- 2026-09-27 revised after audit O round 1 (`docs/audit-log.md`): `docs/residuals.md` owned here, counted per residual sentence; the delta widened to every reviewed path, lock files, `vendor/`, toolchain and `unsafe`, confirmed by the reviewers, and the beta tag tied to it; the request allowed before the freeze; the report final when recorded; disputed findings closed only by the reviewers in writing (O-Q2) and ADR closings confirmed like fixes; fixes during the beta and the pause; publication after the fixes, with the project's responses; the key fingerprints in the package; the ADR list of R5
- 2026-09-27 revised after audit O round 2 (`docs/audit-log.md`): the request with a draft package and the package committed after the tag; the keys slice of spec 060 before `review-1`; the delta over every lock file and release-infrastructure path, open until the beta's end, with security-fix rows during a pause and the human-decision escape limited to paths outside R4; specs 040 and 041 in scope; security reports during the beta as rows that count as high until downgraded; the "Paused" and "Resumed" rows; the report counted out of band only on the reviewers' site, with the fingerprints; SECURITY.md keeps the experimental line for spec 064; the residual match case-insensitive; the published-report check limited to earlier rows; O-Q2 cited from "Audit O"
- 2026-09-27 revised after audit O round 3 (`docs/audit-log.md`): commits outside the listed paths allowed in any beta tag; the version derivation and the beta label and expiry implemented before the freeze; the delta open until the public release, and the `vX.Y.Z` tag tied to the last beta; human-decided rows outside R4 in the beta formula and exempt from R7's gate; the experimental line checked only until the public release; the reviewers asked to print the one-line check; Depends on 040, 041 and 060's keys slice
- 2026-09-28 revised after audit P (`docs/audit-log.md`): the phrase "documented residual" is the contract of R2 and nothing else is harvested (D3); the server's operation points to spec 066 and later re-reviews to spec 065
- 2026-09-28 revised after audit P round 2 (`docs/audit-log.md`): R3 and T03's tie to the last beta tag hold for the first public `vX.Y.Z` tag only; later tags and their re-reviews follow spec 065-release-maintenance R1
- 2026-09-28 accepted (Marc Vilardebó)
