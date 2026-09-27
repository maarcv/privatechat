# 064 — Public release

Status: draft
Phase: 6
Related ADRs: 0017, 0041
Depends on: 051-android-mvp, 052-ios-mvp, 060-reproducible-builds, 061-threat-review, 062-security-docs, 063-beta
Blocks: —
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

Spec 063-beta ends the closed beta, but something has to turn a beta into a version anyone can install: a release tag without the beta flag, the public downloads, the stores' production tracks and F-Droid. The human reviewer decided during audit O that this is a spec of its own, and that Google Play, left out of the beta, is decided here (`docs/audit-log.md`, "Audit O", O-Q1 and O-Q4). With this spec `implemented`, phase 6 and the v1 plan close (`docs/spec.md` §10).

Google Play requires an Android App Bundle for a new app and signs what it delivers with a key Google holds (Play App Signing). So a Play install is, like an iPhone install (spec 060-reproducible-builds R4), neither the reproducible APK nor signed by the owner. Android's code transparency lets the owner sign, with a key on the owner's token, a statement of the code the bundle holds, which a user can check on the installed app.

**In plain words.** After the beta, the project tags a normal version, builds and signs it as for the beta, and publishes it where anyone can get it: the project's download page, F-Droid, Google Play and the App Store. The page says which downloads are exactly the checkable build (the direct files and F-Droid) and which are repackaged by a store (Google Play and the App Store). The text that calls the project "experimental" is replaced by the result of the outside review.

## Requirements

- R1 The public release MUST NOT be made until: the "End" row of spec 063-beta R8 exists; no finding of spec 061-threat-review is open without a fix or a recorded acceptance, and none of critical or high severity is open or disputed without the reviewers' written withdrawal or downgrade (`docs/audit-log.md`, "Audit O", O-Q2); and a tag `vX.Y.Z`, without a suffix, has been built, signed and verified as spec 060-reproducible-builds R1–R9 say. That tag builds with no beta flag (spec 063-beta R3). The release is recorded as a row "Public release" in `docs/audit-log.md`, section "Beta", with its tag and date.
- R2 The GitHub release of that tag MUST be published, with the signed APKs and desktop installers, `SHA256SUMS` and its signature (spec 060-reproducible-builds R6), and the landing's "Check a download" page and a new download section link them; `landing/CONTENT.md`'s rule "no downloads … until they exist" is then amended to name what exists.
- R3 F-Droid's inclusion (spec 051-android-mvp R10) MUST be merged only now, with a `metadata/org.privatechat.yml` recipe in `fdroiddata` that: builds the tag with the wrapper of spec 060-reproducible-builds R2 (the same path remaps); declares one build block per ABI with the distinct `versionCode`s of spec 051-android-mvp R7; sets `Binaries:` to the signed APK URLs of R2; and sets `AllowedAPKSigningKeys` to the lowercase hexadecimal SHA-256 of the Android signing certificate of `docs/release-keys.md`, without colons. The Android build sets `dependenciesInfo { includeInApk = false; includeInBundle = false }`, whose encrypted block F-Droid refuses. F-Droid's reproducible-build check MUST report the APKs as verified: F-Droid's unsigned rebuild with the release's signature copied onto it by `apksigcopier` is byte-identical to the published APK.
- R4 Google Play production MUST receive the Android App Bundle built from the same tag, reproducibly (its hash in `SHA256SUMS`), uploaded with an upload key held on a hardware token like the others of spec 060-reproducible-builds R5, and carrying Android code transparency (`bundletool add-transparency`) signed with a key on the owner's token, whose certificate is listed in `docs/release-keys.md`. Play installs are signed by Google: a documented residual, stated on the "Check a download" page next to the iOS one. A Play install and an F-Droid or direct install cannot update each other, since their signers differ, and the page says so. A Play developer account created after 2023-11-13 for a person needs a closed test of at least 12 opted-in testers for 14 days before production; the project runs that closed track, with the same letter as spec 063-beta R4, if its account needs it.
- R5 The App Store production release MUST be the build that TestFlight already reviewed for that version, archived from the tag as spec 060-reproducible-builds R4 says, with its unsigned hash in `SHA256SUMS`.
- R6 The release key fingerprints MUST be published through channels outside GitHub and the landing's host before the downloads: the external review's report (spec 061-threat-review R8), the app's Help (spec 056-chat-screens R18), and the F-Droid recipe of R3.
- R7 In the same change, `.github/SECURITY.md` MUST replace "pending external review … treat the project as experimental" with the review's result and link (spec 061-threat-review R8), and `README.md`'s status line MUST name the released version and link the downloads.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| Release tag | `vX.Y.Z`, no suffix | not a public release |
| Open review findings | none without a fix or an acceptance; no critical or high one open or disputed without the reviewers' writing | the release waits |
| F-Droid signing key | the certificate of `docs/release-keys.md` | F-Droid refuses the build |

## Interface

```
docs/audit-log.md, section "Beta"              R1: row "Public release"
fdroiddata: metadata/org.privatechat.yml       R3 (outside this repository)
landing/src/content/download/                  R2
docs/release-keys.md                           R4: the Play upload and code-transparency certificates
```

**PR slices** (AGENTS 14): (a) the gate check and the download page (R1, R2); (b) the F-Droid recipe and the Android build settings (R3); (c) the Play bundle with code transparency (R4); (d) the App Store release, the fingerprints, SECURITY.md and README (R5–R7).

## Security

- The direct downloads and F-Droid ship the exact reproducible build, signed by the owner, and F-Droid checks it independently (R2, R3).
- Google Play and the App Store repackage and re-sign what they deliver; code transparency lets a Play user check the code against the owner's key, and the iOS residual is unchanged (R4, R5). Both are stated where users choose a download.
- The key fingerprints come from places an attacker who took the GitHub account does not control (R6).

## Public API changes

None.

## Test cases

- T01 (covers R1): `check_s064_t01_r01_gate`: a "Public release" row without an "End" row, or with an open critical or high finding, fails; the tag of the row has no suffix.
- T02 (covers R2): `check_s064_t02_r02_downloads`: the GitHub release of the tag is published and holds every file of `SHA256SUMS`; the landing links them; `landing/CONTENT.md` no longer forbids downloads.
- T03 (covers R3): `s064_t03_r03_fdroid`: a CI step rebuilds the APKs unsigned with the F-Droid recipe's settings, copies the release signature with `apksigcopier`, and compares them with the published APKs byte for byte; non-automatable, F-Droid's own check reports them verified.
- T04 (covers R4): `s064_t04_r04_play_bundle`: the AAB's hash is in `SHA256SUMS`, and `bundletool check-transparency` on it verifies against the code-transparency certificate of `docs/release-keys.md`.
- T05 (covers R5): `check_s064_t05_r05_app_store`: the iOS archive hash of the tag is in `SHA256SUMS`; non-automatable, the App Store build is the TestFlight one of that version.
- T06 (covers R6): `check_s064_t06_r06_fingerprints`: the Help string resources and the review report hold the fingerprints of `docs/release-keys.md`.
- T07 (covers R7): `check_s064_t07_r07_security_md`: `.github/SECURITY.md` no longer says "pending" or "experimental", and `README.md` names the released version.

## Vectors

None.

## Acceptance criterion

The checks of T01–T07 green. Non-automatable: the stores accept the builds and F-Droid publishes them. With this spec `implemented`, phase 6 and the v1 plan close (`docs/spec.md` §10).

## Out of scope

- Later releases: each follows spec 060-reproducible-builds, and one that changes a phase 1 spec asks for a new review (spec 061-threat-review).
- Store screenshots and marketing.
- The v2 items of `docs/spec.md` §12.

## Open questions

None.

## History

- 2026-09-27 draft (`docs/audit-log.md`, "Audit O", O-Q4)
