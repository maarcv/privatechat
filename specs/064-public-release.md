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

**In plain words.** After the beta, the project tags a normal version, builds and signs it as for the beta, and publishes it where anyone can get it: the project's download page, F-Droid, Google Play and the App Store. The page says which downloads are exactly the checkable build (the direct files and F-Droid) and which are repackaged by a store (Google Play and the App Store). The list of fingerprints of every public release is also written into a public, append-only log, so that nobody can be shown a forged release that the rest of the world does not see. The line that calls the project "experimental" goes, and the security page names the exact version the outside reviewers read.

## Requirements

- R1 The public release MUST NOT be made until: the "End" row of spec 063-beta R8 exists; no finding of spec 061-threat-review is open without a fix or a recorded acceptance, and none of critical or high severity is open or disputed without the reviewers' written withdrawal or downgrade (`docs/audit-log.md`, "Audit O", O-Q2); a tag `vX.Y.Z`, without a suffix, on the last `-beta.N` tag's commit or adding to it only what spec 061-threat-review R3 allows, has been built, signed and verified as spec 060-reproducible-builds says, its signed `SHA256SUMS` logged in Sigstore Rekor by `sign_release.sh` right after signing and before upload (spec 060-reproducible-builds R6, R8; `docs/audit-log.md`, "Audit O", O-Q6), and the owner's `verify` run, which checks that entry, passing (spec 060-reproducible-builds R9); and every account of spec 063-beta R1, together with the Google Play Console and the GitLab account used for `fdroiddata`, is the owner's alone with a hardware security key as its second factor. That tag builds with no beta flag (spec 063-beta R3). The release is recorded as a row "Public release" in `docs/audit-log.md`, section "Beta", with its tag, the `verify` run's URL, the Rekor entry and the date.
- R2 `sign_release.sh` leaves the release a draft (spec 060-reproducible-builds R6). Only after the "Public release" row exists MUST the owner, by hand: publish the GitHub release of that tag, with the signed APKs, the desktop installers, `SHA256SUMS` and its signature; and link them from the landing's "Check a download" page and a new download section; `landing/CONTENT.md`'s rule "no downloads … until they exist" is then amended to name what exists.
- R3 F-Droid's inclusion (spec 051-android-mvp R10) MUST be merged only now, in this order: the GitHub release of R2 is published, so that the recipe's `Binaries:` URLs exist; the merge request of the recipe is then merged; and F-Droid then builds. The recipe `metadata/org.privatechat.yml` in `fdroiddata`: builds the tag with the wrapper of spec 060-reproducible-builds R2 (the same path remaps); sets `UpdateCheckMode: Tags ^v[0-9]+\.[0-9]+\.[0-9]+$`, so that no `-beta` or `-rc` tag is ever built; declares one build block per ABI with the `versionCode`s that spec 060-reproducible-builds R2 derives from the tag and spec 051-android-mvp R7 uses; sets `Binaries:` to the signed APK URLs of R2; sets `AllowedAPKSigningKeys` to the lowercase hexadecimal SHA-256 of the Android signing certificate of `docs/release-keys.md`, without colons, updated before a tag signed after a key rotation ships (spec 060-reproducible-builds R5); and names, in the app's description written in that `fdroiddata` file (never in this repository's fastlane texts, which whoever controls the repository could change), the release key fingerprints of R6. The Android build sets `dependenciesInfo { includeInApk = false; includeInBundle = false }`, whose encrypted block F-Droid refuses. F-Droid's reproducible-build check MUST report the APKs as verified: F-Droid's unsigned rebuild with the release's signature copied onto it by `apksigcopier` is byte-identical to the published APK.
- R4 Google Play production MUST receive the Android App Bundle that spec 060-reproducible-builds R3 and R8 build and check from the same tag, carrying Android code transparency (`bundletool add-transparency`) signed with a separate code-transparency key on the owner's token and signed with an upload key held on a hardware token with its backup, both as the `vX.Y.Z` step of spec 060-reproducible-builds R6 does, with its `signed/` line in `SHA256SUMS`, and uploaded to the Play Console by hand; both keys' certificates are listed in `docs/release-keys.md`. Play's app-signing key MUST be one Google generates: the option to upload an existing app-signing key is never used, and its certificate, listed in `docs/release-keys.md`, MUST differ from the release certificate of R3, so that Google cannot sign an update that installs over a direct or F-Droid install. Code transparency covers the app's DEX code and native libraries, not its manifest or resources. A closed test of at least 12 opted-in testers for 14 days, which a Play developer account created after 2023-11-13 for a person needs before production, starts only after spec 063-beta's "End" row, with the `vX.Y.Z` bundle and a variant of spec 063-beta R4's letter that says what Google shows the project (the testers' Google accounts, their devices, Android vitals and crash data) and that the project exports none of it.
- R5 The App Store production release MUST be the `vX.Y.Z` build that `sign_release.sh` archives, signs and uploads (spec 060-reproducible-builds R3, R6), submitted to App Review, with its unsigned hash in `SHA256SUMS`; it is not a build TestFlight reviewed, since every beta build carries the beta flag.
- R6 The release key fingerprints MUST be published through channels outside GitHub and the landing's host before the downloads: the external review's report as the firm or the programme publishes it on its own site (spec 061-threat-review R8), the description of the F-Droid recipe of R3, and the one-line check of spec 060-reproducible-builds R8 (`ssh-keygen -Y check-novalidate -n privatechat-release -s SHA256SUMS.sig < SHA256SUMS`, whose printed `SHA256:` fingerprint is compared with them) printed next to them. A notice of a key rotation or compromise goes through the channels the owner controls: the landing, the GitHub release, the description in the `fdroiddata` file, and a signed `ROTATION-<date>.txt` (spec 060-reproducible-builds R5). The app's Help (spec 056-chat-screens R18) shows them too, but only as a check of later downloads from an install already verified.
- R7 In the same change, `.github/SECURITY.md` MUST remove the line "experimental until the public release" that spec 061-threat-review R8 left, name the commit the reviewers read (`review-N`, with its full SHA), and link `docs/review/delta.md` for everything changed since; and `README.md`'s status line MUST name the released version and link the downloads.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| Release tag | `vX.Y.Z`, no suffix | not a public release |
| Open review findings | none without a fix or an acceptance; no critical or high one open or disputed without the reviewers' writing | the release waits |
| F-Droid signing key | the certificate of `docs/release-keys.md` | F-Droid refuses the build |
| Tags F-Droid builds | `v` and three decimal numbers, no suffix | ignored |
| Play app-signing key | generated by Google, a certificate other than the release one | the Play upload waits |

## Interface

```
docs/audit-log.md, section "Beta"              R1: row "Public release"
fdroiddata: metadata/org.privatechat.yml       R3 (outside this repository)
docs/fdroid/org.privatechat.yml                R3: the copy the checks of T03 and T06 read
landing/src/content/download/                  R2
docs/release-keys.md                           R4: the Play upload and code-transparency keys and Google's app-signing certificate
```

**PR slices** (AGENTS 14): (a) the gate check and the download page (R1, R2); (b) the F-Droid recipe and the Android build settings (R3); (c) the Play bundle with code transparency (R4); (d) the App Store release, Rekor, the fingerprints, SECURITY.md and README (R2, R5–R7).

## Security

- The direct downloads and F-Droid ship the exact reproducible build, signed by the owner, and F-Droid checks it independently (R2, R3).
- Google Play and the App Store repackage and re-sign what they deliver; code transparency lets a Play user check the code against the owner's key, and the iOS residual is unchanged (R4, R5). Both are stated where users choose a download.
- The key fingerprints come from places an attacker who took the GitHub account and the landing's host does not control (R6), and every public manifest is in Rekor (R2), so a forged release shown to one person differs from the one the log holds.
- Play installs are signed by Google, not by the owner: a documented residual, stated on the "Check a download" page next to the iOS one (R4).
- A Play install and an F-Droid or direct install cannot update each other, since their signers differ: a documented residual, stated on the same page (R4).
- Code transparency does not cover a Play app's manifest or resources, so Google could change a permission or a manifest flag unseen: a documented residual (R4).
- Releases after this one change reviewed paths without a new review unless spec 061-threat-review asks for one; `.github/SECURITY.md` names the reviewed commit and links the delta (R7), so users see what changed since: a documented residual.

## Public API changes

None.

## Test cases

- T01 (covers R1): `check_s064_t01_r01_gate`: a "Public release" row without an "End" row, with an open critical or high finding, or without a `verify` run URL or a Rekor entry, fails; the tag of the row has no suffix; a Rekor entry whose time is later than the `verify` run's start fails; a tag that adds to the last beta tag an unconfirmed delta row fails; non-automatable, the accounts' second factors are recorded in the pull request that adds the row.
- T02 (covers R2): `check_s064_t02_r02_downloads`: the GitHub release of the tag is published after the "Public release" row's date and holds every file of the `signed/` lines of `SHA256SUMS`; the Rekor entry of the row holds that manifest's hash; the landing links the files; `landing/CONTENT.md` no longer forbids downloads.
- T03 (covers R3): `s064_t03_r03_fdroid`: a CI step rebuilds the APKs unsigned with the F-Droid recipe's settings, copies the release signature with `apksigcopier`, and compares them with the published APKs byte for byte; `check_s064_t03_r03_recipe` over a copy of the recipe kept in `docs/fdroid/`: the recipe's merge is dated after the release's publication; the `UpdateCheckMode` regex accepts `v1.2.3` and refuses `v1.2.3-beta.1` and `v1.2.3-rc.1`, `AllowedAPKSigningKeys` equals the certificate of `docs/release-keys.md`, and the description holds the fingerprints; non-automatable, F-Droid's own check reports them verified.
- T04 (covers R4): `s064_t04_r04_play_bundle`: the AAB's hash is in `SHA256SUMS`, and `bundletool check-transparency` on it verifies against the code-transparency certificate of `docs/release-keys.md`; `check_s064_t04_r04_play_keys`: Google's app-signing certificate is listed and differs from the release certificate, and the code-transparency key differs from the upload key; non-automatable, `bundletool check-transparency --mode=connected_device` on the app installed from a Play test track verifies, and the closed test's letter variant exists before the track opens.
- T05 (covers R5): `check_s064_t05_r05_app_store`: the iOS archive hash of the `vX.Y.Z` tag is in `SHA256SUMS`; non-automatable, the build submitted to App Review is that tag's.
- T06 (covers R6): `check_s064_t06_r06_fingerprints`: the Help string resources hold the fingerprints of `docs/release-keys.md`, and the copy of the F-Droid recipe holds them and the one-line check command; no fastlane text of this repository is the place the description's fingerprints come from; non-automatable, the report published on the firm's or programme's own site holds them.
- T07 (covers R7): `check_s064_t07_r07_security_md`: `.github/SECURITY.md` no longer says "pending" or "experimental", names a `review-N` tag with its full SHA that exists, and links `docs/review/delta.md`; `README.md` names the released version.

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
- 2026-09-27 revised after audit O round 2 (`docs/audit-log.md`): the release stays a draft until the gate row, then is logged in Rekor and published by hand (O-Q6); the owner's `verify` run in the row; Play Console and GitLab among the hardened accounts; F-Droid's order, tag regex, versions from the tag and fingerprints in its description; Play's bundle from 060, a Google-generated signing key, separate transparency and upload keys, what transparency does not cover, and the closed test after the beta with its own letter; the App Store build is the release tag's, not a TestFlight one; fingerprints from the reviewers' own site; SECURITY.md drops "experimental", names the reviewed commit and links the delta; Security residual sentences
- 2026-09-27 revised after audit O round 3 (`docs/audit-log.md`): Rekor logged by `sign_release.sh` before upload and checked by `verify`, so the gate row records it; the release tag tied to the last beta; the Play bundle's signing is spec 060 R6's step, uploaded by hand; F-Droid after publication, its description in `fdroiddata`; the one-line check with `check-novalidate`; rotation notices through the owner's channels; Help checked for the fingerprints only
