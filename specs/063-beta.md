# 063 — Closed beta

Status: draft
Phase: 6
Related ADRs: 0017, 0041
Depends on: 016-fuzz-harness, 034-docker, 035-server-ops, 050-desktop-mvp, 051-android-mvp, 052-ios-mvp, 060-reproducible-builds, 061-threat-review, 062-security-docs
Blocks: 064-public-release
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

The beta is the first time people outside the project use the app. The human reviewer decided on 2026-09-27 that it is closed, by invitation, for 20 to 50 known people, through TestFlight on iOS and by private link for the desktop installers (`docs/audit-log.md`, "Phase 6 drafts", Q13), and, during audit O, that Android testers get the owner-signed, reproducible APK by the same private link, Google Play being left to the public release (`docs/audit-log.md`, "Audit O", O-Q1). This spec fixes when the beta may start, how testers get it, what they are told, how feedback reaches the project with no telemetry, what happens when a security problem is found during it, and when it ends. The public release that follows is spec 064-public-release.

**In plain words.** Once every earlier piece is built and tested, the outside review has found no serious problem left open, and the public pages exist, the project invites a few dozen people it knows. They install the iPhone app from Apple's test programme, and the Android and computer apps from a private link, each file signed by the owner and checkable against a fingerprint they receive in person or on paper. They use the app for at least four weeks and try a short list of things. The app sends nothing about them back; they are told what Apple sees, what the project's server sees, and how to report problems without sending anyone's messages. If a serious flaw appears, the fix ships at once and the beta pauses until the outside reviewers confirm it. A beta build stops working 90 days after it was made, so an old test version with a known flaw does not stay in use.

## Requirements

**Starting**

- R1 The beta MUST NOT start until:
  - every spec of phases 0 to 5 is `implemented`, and specs 060-reproducible-builds, 061-threat-review and 062-security-docs are `implemented`;
  - spec 061-threat-review R7 holds: no finding of critical or high severity open or disputed without the reviewers' written withdrawal or downgrade, and every fix confirmed by them;
  - a beta release has been built, signed and verified as spec 060-reproducible-builds says, from a tag of the form `vX.Y.Z-beta.N` (R3): the owner's local rebuild matched (spec 060-reproducible-builds R6), the owner started the `verify` job for the tag and it passed, and the release stays a draft (spec 060-reproducible-builds R6, R9); the run's URL goes in the "Start" row;
  - the open decisions of `docs/spec.md` §12 that a public build needs are closed by the human reviewer: the product name, and the value of `DEFAULT_SERVER_URL` with the server running at that address (spec 000-repo-layout R4), deployed from the reference deployment of spec 034-docker with the logging of spec 035-server-ops. The application and bundle identifiers are `org.privatechat.*`, fixed since phase 5 (specs 051-android-mvp, 052-ios-mvp), and do not change with the product name;
  - the TestFlight record of spec 052-ios-mvp R10 accepts a build, with the privacy answers of spec 062-security-docs R1, and 052-R10 (export compliance) is answered;
  - every account the release and the beta depend on is held by the human owner alone, with a hardware security key as its second factor: GitHub, the Apple Developer account, the domain registrar, the landing's host, the file host of R2, the project server's hosting, the Windows certificate authority's account, and the owner's mail account, which sends the letters and every update and pause notice.
  The start is recorded as a row "Start" in `docs/audit-log.md`, section "Beta", with its date and tag. `check_s063_t01_r01_gate` in `scripts/doc_lint.py` MUST fail while that row exists and any spec status above does not hold, and when this spec is marked `implemented` without it.

**Getting the app**

- R2 Testers MUST be invited by name by the human owner, 20 to 50 people, and receive the app only through: a TestFlight group with invitations by email (external testing, after Apple's beta review of the first build of each version); and, for Android and the desktop, the owner-signed artefacts of the beta release (spec 060-reproducible-builds R6), sent by a private link on a file host the owner names in the letter of R4, which sees each tester's address and download times. The beta release is a draft GitHub release, never published, and the CI run keeps only `unsigned-hashes.txt` as an artefact, for one day (spec 060-reproducible-builds R9), so that no beta build, the Linux ones with no signature of their own included, can be downloaded by anyone but the testers. Only `vX.Y.Z-beta.N` builds reach testers: an `-rc.N` build, which carries a visible "RC" flag and no production signature (spec 060-reproducible-builds R2, R7), is never sent. Each tester MUST receive the release key fingerprints, primary and backup, which the owner derives from the tokens themselves (`ssh-keygen -K`, or the public keys the owner holds offline) and compares with `docs/release-keys.md` before printing, on paper or in person, printed in the letter of R4 and never in the same message as a link; the tester checks every file against them with the one-line `ssh-keygen -Y verify` command of spec 060-reproducible-builds R8, printed next to them, before anything else, and then as the "Check a download" page says (spec 062-security-docs R1). Google Play is not used in the beta, and F-Droid's inclusion request stays unmerged until the public release (spec 051-android-mvp R10).
- R3 A beta build MUST be one built from a tag `vX.Y.Z-beta.N`, whose suffix the build reads from the tag and compiles in as the beta flag, an input of the reproducible build (spec 060-reproducible-builds R2); a tag without the suffix builds a release. Its version numbers come from the tag as spec 060-reproducible-builds R2 derives them, so that each `-beta.N` installs over the one before and the public release over every beta. A beta build MUST show "Beta" and its version next to the app name on the Locked screen (spec 056-chat-screens R20) and the channel list (spec 056-chat-screens R6), and its Help MUST begin, before its first section (spec 056-chat-screens R18), with "This is a test version. Do not rely on it for anything that must stay secret: the design has been reviewed from outside, but the app is new." A beta build MUST also compile in an expiry 90 days after its tag's time and, once the device's clock passes it, show at unlock a blocking notice, "This test version has expired. Install the newer build from the link you were sent.", with no other action than "Lock now"; the rule is local, read from the build, never from a server (R9). The texts are string resources in the five languages.

**What testers are told**

- R4 Each tester MUST receive, before installing, a letter whose English source is `docs/beta/invitation.md` and whose translations live in `landing/src/content/beta/` (AGENTS 11 keeps translated text out of `docs/`), a translation that no speaker has reviewed being sent in English (`docs/audit-log.md`, "Audit O", O-Q3). The letter MUST say:
  - what the beta is, how long it lasts, that each build stops working 90 days after it was made (R3), and that updates are announced by mail to the invitation address, never with a file attached and never with a fingerprint, so that every update is checked against the fingerprints on paper;
  - that the app sends nothing about them to the project;
  - what Apple shows the project for a TestFlight tester (their email address and name, device model, operating system version, installs, sessions, crash logs they allow, and the screenshots and comments they send with TestFlight's feedback), and that the project exports none of it;
  - that the project's server sees each tester's IP address and which connections read the same channel at the same time, so that its operator, who knows every tester by name, could tell who talks with whom; that the operator commits not to correlate this; and that Tor or Orbot hides the address (the "Tor" help of spec 056-chat-screens R18);
  - never to send the text of a message or a screenshot of a conversation, by mail, in TestFlight's feedback or in a GitHub issue, since it holds other people's words;
  - the links to "Promises and limits" and "Known residual risks" (spec 062-security-docs);
  - how to report a problem (R5), and that a security problem goes through `.github/SECURITY.md`, never a public channel;
  - the release key fingerprints and the one-line check command (R2), and the name of the file host of R2 with what it sees.
- R5 Feedback MUST reach the project only by the testers' own action: a mailbox named in the letter, TestFlight's feedback, or a GitHub issue for a tester who wants a public one. The apps add no feedback form, no automatic report and no identifier. A screenshot received is read, then deleted, and never enters the repository; the mailbox is kept for the beta's duration and 30 days after, then deleted. The project records each reported problem in `docs/beta/log.md` as a row with the week, the platform family (desktop, Android, iOS), the version, what happened and what was done, and no name, address, device model, channel name or message content. The log stays out of the repository until the beta ends, and is then committed in aggregate. Each beta build, and the week it was sent, is recorded there too.
- R6 Each tester MUST be asked to try, and report on, the scenarios of `docs/beta/plan.md`, which names for each scenario the platforms it applies to and covers at least: creating a channel on each platform; inviting by QR in person (phones) and by file with the seven words; joining with the confirmation screen; chatting across the three platforms; verifying a peer by the 12 words and, on phones, by QR; locking and unlocking, the device's own lock included; setting a SOCKS5 proxy (Tor or Orbot) on at least one device; leaving a channel; and "Create new channel" after a pretended leak. `plan.md` records, per scenario and per platform it applies to, how many testers completed it and how many reported a problem, with no names.

**During and after**

- R7 A security problem found during the beta MUST go through `.github/SECURITY.md` and become a row of `docs/audit-log.md`, "External review", that counts as high until the reviewers or the programme downgrade it in writing (spec 061-threat-review R6). While any critical or high row is open, the beta is paused: a row "Paused" in "Beta" names the date and the row, and testers are told by mail to stop relying on it. The fix ships at once in a new `-beta.N` build from a branch `release/vX.Y` cut from the beta's tag, recorded in `docs/review/delta.md` as a fix row with the human reviewer's decision (spec 061-threat-review R3), and forward-ported to the default branch. Whether the fix also needs a follow-up review is spec 061-threat-review R7's rule, which this spec does not restate. The pause lifts only when the reviewers have confirmed the fix rows in writing, with a row "Resumed" in "Beta".
- R8 The beta MUST last at least 28 days from the "Start" row, not counting the time between a "Paused" row and its "Resumed" row, and MUST end only when: no reported problem of the kinds "loses messages", "shows a message to the wrong channel or person", "accepts an unverified key as verified", "leaks content or a key outside the device" or "crashes at unlock" is open; no "Paused" row lacks its "Resumed" row; every scenario of R6 was completed on every platform it applies to by at least three testers; and the human reviewer records the end as a row "End" in `docs/audit-log.md`, "Beta".
- R9 A build of the beta MUST NOT carry a switch the server or the project can use to disable, update or reconfigure the app remotely; a server that must stop the beta changes its protocol version, which the apps already show as an unsupported server (spec 042-connection-host R10, spec 056-chat-screens R10). TestFlight builds expire after 90 days, and every beta build carries the local expiry of R3; the public release (spec 064-public-release) replaces them. Apple's update channel to TestFlight testers is a documented residual: an account that could publish a build could push it to testers, which R1's owner-only accounts with hardware keys guard against.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| Testers | 20..=50, invited by name | no more invitations |
| Beta tag | `vX.Y.Z-beta.N` | builds a release, not a beta |
| Duration | ≥ 28 days from the "Start" row, paused time excluded | the beta cannot end |
| A beta build's life | 90 days from its tag's time | the blocking notice of R3 |
| Scenario coverage at the end | ≥ 3 testers per scenario and per platform it applies to | the beta cannot end |
| Data about testers kept by the project | their invitation address, outside the repository; the mailbox until 30 days after the end; nothing Apple shows is exported; the file host's logs as its policy sets, named in the letter | removed |

## Interface

```
docs/beta/invitation.md                       R4, English source
landing/src/content/beta/                     R4, the letter's translations
docs/beta/plan.md                             R6
docs/beta/log.md                              R5, committed only after the end
docs/audit-log.md, section "Beta"             R1, R7, R8: rows "Start", "Paused", "Resumed" and "End"
```

**PR slices** (AGENTS 14): (a) the gate check, the beta flag and versions from the tag, the beta label, text and expiry in the three apps (R1, R3); (b) the invitation, the plan and the log (R4–R6); (c) the pause and end records (R7, R8). The distribution of R2 and the rule of R9 need no code of their own.

## Security

- The beta starts only after the outside review has no serious finding open, the release is reproducible and signed, and every account behind it is the owner's with a hardware key (R1), so testers run what was reviewed and can check it against fingerprints they received in person (R2).
- Testers are known and few (R2), and told plainly not to rely on the app for secrets yet (R3, R4), what Apple and the project's server can see about them (R4), and never to send anyone's messages (R4, R5).
- Nothing is collected about testers by the apps (R5): feedback is their own words, the public record holds no names, device models or content, and it is published only in aggregate after the end. Adding telemetry "just for the beta" would contradict §8 "Telemetry" and is not allowed.
- No remote switch exists (R9): a switch the project could use, an attacker who took the project's server could use too. The store's own update channel stays a documented residual. The expiry of R3 is read from the build, so an old beta with a known flaw stops on its own without the server deciding anything.
- Testers check every file against fingerprints the owner took from the tokens and handed over on paper, with a command that needs nothing from the repository (R2), so an attacker who controls GitHub, the landing or the owner's mail cannot pass a changed build or a changed fingerprint to them. A tester who skips the check is a documented residual.
- A security report during the beta counts as high until the reviewers say otherwise, so the project cannot avoid a pause by grading its own problem (R7).
- The project's server can map the testers' conversations by timing and address; the letter says so and recommends Tor (R4). A documented residual of §2, stated for this group.

## Public API changes

None.

## Test cases

- T01 (covers R1): `check_s063_t01_r01_gate`: with a "Start" row and a spec of phase 5 still `draft`, the check fails; a "Start" row without a `verify` run URL fails; with no "Start" row, marking this spec `implemented` fails; the real gate passes only when every listed status holds; non-automatable, the §12 decisions, the store acceptance and the accounts' second factors are recorded in the pull request that adds the "Start" row.
- T02 (covers R2): `check_s063_t02_r02_distribution`: the beta release of the "Start" row's tag is a draft (queried with `gh release view`); `docs/beta/invitation.md` holds the fingerprints of `docs/release-keys.md`, primary and backup, and the one-line `ssh-keygen -Y verify` command; the release workflow keeps only `unsigned-hashes.txt` as a run artefact, with a retention of one day; no mail template of `docs/beta/` holds both a URL and a fingerprint; non-automatable, the owner's comparison of the printed fingerprints with the tokens, and the TestFlight group and the private link are recorded, without names, in the pull request.
- T03 (covers R3): Compose `s063_t03_r03_beta_label`, Swift `s063_t03_r03_betaLabel` and Vitest `s063_t03_r03_beta_label`: a build with the beta flag shows "Beta" and the version on the two screens and Help begins with the text of R3 in each UI language; a build without it shows neither; a beta build whose expiry has passed shows the blocking notice at unlock and offers only "Lock now"; two consecutive `-beta.N` tags give increasing version codes, and `vX.Y.Z` a higher one than every `vX.Y.Z-beta.N`; `check_s063_t03_r03_flag_from_tag`: the flag is derived from the tag suffix in the build scripts and nowhere else.
- T04 (covers R4): `check_s063_t04_r04_invitation`: `docs/beta/invitation.md` holds each point of R4, the links and the fingerprints; every translation under `landing/src/content/beta/` records the hash of the English source it was reviewed against, or is absent.
- T05 (covers R5): `check_s063_t05_r05_log`: `docs/beta/log.md` rows have the columns of R5 and hold no e-mail address, `@` handle, device model name from a fixed list, full date or text in quotes longer than 40 characters; the file is absent before the "End" row.
- T06 (covers R6): `check_s063_t06_r06_plan`: `docs/beta/plan.md` lists every scenario of R6 with its platforms and a count per platform.
- T07 (covers R7): `check_s063_t07_r07_pause`: an open critical or high row in "External review" dated after "Start" without a "Paused" row fails; a "Resumed" row before the reviewers' written confirmation of the fix rows fails; a SECURITY.md report row with no severity counts as high; every security fix in the beta has a fix row in `docs/review/delta.md` and a commit on a `release/vX.Y` branch cut from the beta's tag, forward-ported to the default branch.
- T08 (covers R8): `check_s063_t08_r08_end`: the "End" row is at least 28 days after "Start", paused time excluded, no "Paused" row lacks its "Resumed" row, every scenario count is at least 3 on each of its platforms, and no row of the listed kinds is open.
- T09 (covers R9): `s063_t09_r09_no_remote_switch`, a source check over the three apps and the connection host: no code path reads a remote flag, configuration or update instruction from a server response or a store API.

## Vectors

None.

## Acceptance criterion

The checks of T01, T02, T04–T09 green, T03 green in each app's CI. Non-automatable: the testers' invitations sent and the beta held for 28 days; the human reviewer records its end.

## Out of scope

- The public release, its store listings, Google Play and F-Droid (spec 064-public-release).
- Push notifications, attachments and the other v2 items of `docs/spec.md` §12.
- Running the project's public server beyond the reference deployment (hosting, monitoring, on-call), which is the operator's.

## Open questions

- [ ] 063-R1: the product name and the final `DEFAULT_SERVER_URL`, open decisions of `docs/spec.md` §12, are the human owner's before the beta; this spec only requires them.

## History

- 2026-09-27 draft (`docs/audit-log.md`, "Phase 6 drafts", Q13)
- 2026-09-27 revised after audit O round 1 (`docs/audit-log.md`): Android by owner-signed APK and private link, Play left to spec 064 (O-Q1); the beta flag from a `-beta.N` tag; a draft GitHub release; fingerprints given in person; owner-only accounts with hardware keys; what Apple and the server see, stated in the letter; no message text or chat screenshots; a log without dates, devices or names, private until the end; the letter's translations under `landing/` with English fallback (O-Q3); scenarios per platform; security fixes during the beta pause it; a "Start" row checked by the gate; named tests
- 2026-09-27 revised after audit O round 2 (`docs/audit-log.md`): the gate names 060 whole, the owner's `verify` run and a draft release; the hardened accounts include the mail, the file host, the server's hosting and the certificate authority; fingerprints derived from the tokens, on paper, never with a link, and the one-line check command; the file host named; CI keeps only the unsigned hashes, for a day; no `-rc` build to testers; versions and a 90-day expiry from the tag; security reports count as high until downgraded; "Paused" and "Resumed" rows, pauses excluded from the 28 days, release branches from the beta tag, forward-ported fixes, and 061 R7's follow-up rule by reference; 056 R20 and R6 cited for the label
