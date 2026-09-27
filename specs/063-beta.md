# 063 — Closed beta

Status: draft
Phase: 6
Related ADRs: 0017, 0041
Depends on: 016-fuzz-harness, 034-docker, 035-server-ops, 051-android-mvp, 052-ios-mvp, 050-desktop-mvp, 060-reproducible-builds, 061-threat-review, 062-security-docs
Blocks: —
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

The beta is the first time people outside the project use the app. The human reviewer decided on 2026-09-27 that it is closed, by invitation, for 20 to 50 known people, through TestFlight, a closed Google Play track and signed desktop installers sent by private link (`docs/audit-log.md`, "Phase 6 drafts", Q13). This spec fixes when it may start, how testers get it, what they are told, how feedback reaches the project with no telemetry, and when it ends. It is the last spec of the plan: `docs/spec.md` §10 closes phase 6, and the project's v1 plan, with "no spec left in `draft`".

**In plain words.** Once every earlier piece is built and tested, the outside review has found no serious problem left open, and the public pages exist, the project invites a few dozen people it knows. They install the app from Apple's and Google's test programmes or from a signed installer, use it for at least four weeks, and follow a short list of things to try. The app sends nothing about them back; they report problems by writing, and the project writes down what it learns without names.

## Requirements

- R1 The beta MUST NOT start until:
  - every spec of phases 0 to 5 is `implemented`, and every spec of phase 6 other than this one is `implemented`;
  - spec 061-threat-review R7 holds: no finding of critical or high severity open, and every fix confirmed by the reviewers;
  - a release has been built, signed and verified as spec 060-reproducible-builds R1–R9 say, and its hashes are on the "Check a download" page (spec 062-security-docs R1);
  - the open decisions of `docs/spec.md` §12 that a public build needs are closed by the human reviewer: the product name, and the value of `DEFAULT_SERVER_URL` with the server running at that address (spec 000-repo-layout R4), deployed from the reference deployment of spec 034-docker with the logging of spec 035-server-ops;
  - the store records and tracks of specs 051-android-mvp R10 and 052-ios-mvp R10 accept a build, with the privacy answers of spec 062-security-docs R1, and 052-R10 (export compliance) is answered.
  `check_s063_t01_r01_gate` in `scripts/doc_lint.py` MUST fail when this spec is marked `implemented` while any of the spec statuses above is not.
- R2 Testers MUST be invited by name by the human owner, 20 to 50 people, and receive the app only through: a TestFlight group with invitations by email (external testing, after Apple's beta review), a closed testing track of Google Play with a list of testers, and the desktop installers of spec 060-reproducible-builds sent by a private link with their `SHA256SUMS` and signature. No build of the beta is published where anyone can download it, and F-Droid is not used until the public release.
- R3 Every beta build MUST show "Beta" and its version next to the app name on the Locked and channel-list screens, and its Help (spec 056-chat-screens R18) MUST begin with "This is a test version. Do not rely on it for anything that must stay secret: the design has been reviewed from outside, but the app is new." The text is a string resource in the five languages.
- R4 Each tester MUST receive, before installing, a letter (`docs/beta/invitation.md`, English source and translations) that says: what the beta is and how long it lasts; that the app sends nothing about them to the project and that only the operating system's own crash reports, which they control, exist; the link to "Promises and limits" and "Accepted limits" (spec 062-security-docs); how to report a problem (R5); and that a security problem goes through `.github/SECURITY.md`, never a public channel.
- R5 Feedback MUST reach the project only by the testers' own action: a mailbox named in the letter, or a GitHub issue for a tester who wants a public one. The apps add no feedback form, no automatic report and no identifier. The project records, in `docs/beta/log.md`, each reported problem as a row with a date, the platform and version, what happened and what was done, and no name, address, channel name or message content.
- R6 Each tester MUST be asked to try, and report on, the scenarios of `docs/beta/plan.md`, which covers at least: creating a channel on each platform; inviting by QR in person and by file with the seven words; joining with the confirmation screen; chatting across the three platforms; verifying a peer by the 12 words and, on phones, by QR; locking and unlocking, the device's own lock included; setting a SOCKS5 proxy (Tor or Orbot) on at least one device; leaving a channel; and "Create new channel" after a pretended leak. `docs/beta/plan.md` records, per scenario and platform, how many testers completed it and how many reported a problem, with no names.
- R7 The beta MUST last at least 28 days from the first install and MUST end only when: no reported problem of the kinds "loses messages", "shows a message to the wrong channel or person", "accepts an unverified key as verified", "leaks content or a key outside the device" or "crashes at unlock" is open; every scenario of R6 was completed on every platform by at least three testers; and the human reviewer records the end in `docs/audit-log.md`, "Beta". A security problem found in the beta goes through `.github/SECURITY.md` and, when it touches a phase 1 spec, a new review under spec 061-threat-review.
- R8 No build of the beta MUST carry a switch the server or the project can use to disable, update or reconfigure the app remotely; a server that must stop the beta changes its protocol version, which the apps already show as an unsupported server (spec 042-connection-host R10, spec 056-chat-screens R10). Beta builds expire as their store programme sets (TestFlight after 90 days); the desktop installers are replaced by the public release.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| Testers | 20..=50, invited by name | no more invitations |
| Duration | ≥ 28 days from the first install | the beta cannot end |
| Scenario coverage at the end | ≥ 3 testers per scenario and platform | the beta cannot end |
| Data about testers kept by the project | none but their invitation address, outside the repository | removed |

## Interface

```
docs/beta/invitation.md    R4, English source and translations
docs/beta/plan.md          R6
docs/beta/log.md           R5
docs/audit-log.md, section "Beta"   R7
```

**PR slices** (AGENTS 14): (a) the gate check and the beta label and text in the three apps (R1, R3); (b) the invitation, the plan and the log (R4–R6); (c) the end record (R7). The distribution of R2 and the rule of R8 need no code of their own.

## Security

- The beta starts only after the outside review has no serious finding open and the release is reproducible and signed (R1), so testers run what was reviewed and can check it.
- Testers are known and few (R2), so a serious flaw found in the beta reaches a small group, and they are told plainly not to rely on the app for secrets yet (R3, R4).
- Nothing is collected about testers (R5): feedback is their own words, and the project's record holds no names or content. Adding telemetry "just for the beta" would contradict §8 "Telemetry" and is not allowed.
- No remote switch exists (R8): a switch the project could use, an attacker who took the project's server could use too.

## Public API changes

None.

## Test cases

- T01 (covers R1): `check_s063_t01_r01_gate`: with a spec of phase 5 still `draft`, marking this spec `implemented` fails; the real gate passes only when every listed status holds; non-automatable, the §12 decisions and the store acceptances are recorded in the pull request.
- T02 (covers R2): non-automatable: the invitations, the TestFlight group and the Play track are listed, without names, in `docs/beta/log.md`'s first row.
- T03 (covers R3): Compose, XCTest and Vitest checks: a beta build shows "Beta" and the version on the two screens, and Help begins with the text of R3 in each UI language; a release build shows neither.
- T04 (covers R4): `check_s063_t04_r04_invitation`: `docs/beta/invitation.md` holds each point of R4 and the links.
- T05 (covers R5): `check_s063_t05_r05_log`: `docs/beta/log.md` rows have the columns of R5 and hold no e-mail address, `@` handle or text in quotes longer than 40 characters.
- T06 (covers R6): `check_s063_t06_r06_plan`: `docs/beta/plan.md` lists every scenario of R6 with a count per platform.
- T07 (covers R7): `check_s063_t07_r07_end`: the "Beta" section exists, its end date is at least 28 days after its start, every scenario count is at least 3, and no row of the listed kinds is open.
- T08 (covers R8): a source check over the three apps and the connection host: no code path reads a remote flag, configuration or update instruction from a server response.

## Vectors

None.

## Acceptance criterion

The checks of T01, T04–T08 green, T03 green in each app's CI. Non-automatable: the testers' invitations sent and the beta held for 28 days; the human reviewer records its end. With this spec `implemented`, phase 6 and the v1 plan close (`docs/spec.md` §10).

## Out of scope

- The public release, its store listings and F-Droid inclusion, which follow the beta.
- Push notifications, attachments and the other v2 items of `docs/spec.md` §12.
- Running the project's public server beyond the reference deployment (hosting, monitoring, on-call), which is the operator's.

## Open questions

- [ ] 063-R1: the product name and the final `DEFAULT_SERVER_URL`, open decisions of `docs/spec.md` §12, are the human owner's before the beta; this spec only requires them.

## History

- 2026-09-27 draft (`docs/audit-log.md`, "Phase 6 drafts", Q13)
