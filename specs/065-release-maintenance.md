# 065 — Release maintenance

Status: draft
Phase: 6
Related ADRs: 0041
Depends on: 042-connection-host, 053-device-security, 060-reproducible-builds, 061-threat-review, 066-public-server
Blocks: 064-public-release
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

Spec 064-public-release ships the first public version and stops there. Nothing then says how a security fix reaches people, how often the pinned toolchains and the stores' SDK floors are raised, or who notices a new advisory against a lock file that has not changed. The apps never update themselves (spec 060-reproducible-builds, Out of scope) and carry no remote switch (spec 063-beta R9), so a user who installed the direct download or the APK learns of a fix only from outside the app. `.github/dependabot.yml` covers only the root Cargo workspace, GitHub Actions and the landing, and CI runs only on push and pull request. The human reviewer decided during audit P that this is a spec of its own (`docs/audit-log.md`, "Audit P", P-Q2). Spec 064-public-release gates on this one, so that the feed, Dependabot and the advisory job run from the first public release; the age notice every build carries is spec 056-chat-screens's.

**In plain words.** After the first public version, only the newest version is fixed. When a security problem is fixed, the project makes a new version the same checkable way as before and announces it on a public list on its web site, which the app's Help names. The app asks no server whether it is out of date; instead, a version older than six months says so on its own screen, without stopping anything (spec 056-chat-screens), and the project releases at least every six months, so that only people who did not update see it. A robot proposes updates for every library the project uses and a weekly job checks them against the public lists of known flaws, and every update is reviewed and rebuilt like any other change. The dates by which Google and Apple require newer tools are kept in one file, so none is missed.

## Requirements

- R1 Only the latest `vX.Y.Z` MUST receive fixes. A security fix MUST ship as the next PATCH tag, from a branch `release/vX.Y` cut from the latest `vX.Y.Z` tag or from the default branch, built, signed, verified and published as spec 060-reproducible-builds R1–R9 and spec 064-public-release R2–R6 do, after the response and assessment times of `.github/SECURITY.md`; a fix that touches the server is also redeployed on the project's server (spec 066-public-server R7). A release that changes a phase 1 spec (011 to 017) or a path under `crates/core/src/crypto/` or `crates/core/src/proto/` MUST NOT be tagged before the reviewers of spec 061-threat-review have read it under a new signed tag `review-N+1` and their report on it is recorded. After the "Public release" row, every other commit of a release that touches a path of spec 061-threat-review R3 MUST be listed in `docs/review/delta.md` with its full SHA, its reason and the mark `unreviewed`, so that `.github/SECURITY.md`'s link (spec 064-public-release R7) stays true.
- R2 Every release that fixes a security problem MUST publish, once its fixed builds are available in Google Play, the App Store and F-Droid, or 7 days after its tag, whichever comes first, and never before its direct downloads: a GitHub Security Advisory naming the fixed tag, the affected versions and the severity; and an entry in `landing/public/security.atom`, an Atom 1.0 feed with one entry per such release (tag, date, affected versions, severity, the advisory's URL), linked from the landing's security page. A table "Security releases" of `docs/maintenance.md` records, per such release, the tag's date, the date each store and F-Droid made it available, and the advisory's date. The app's Help (spec 056-chat-screens R18) MUST show the feed's URL as text; the app never fetches it.
- R3 A new `vX.Y.Z` tag MUST be made before the newest one is 180 days old, so that the age notice of spec 056-chat-screens, which a build shows 180 days after its own tag, appears only to a user who did not update.
- R4 `docs/maintenance.md` MUST hold a table of the external deadlines the builds depend on, one row each with its date and the release that met it: Google Play's target API level for updates (spec 051-android-mvp R1's `targetSdk`), the minimum Xcode and iOS SDK App Store Connect accepts (spec 052-ios-mvp R7), the Rust toolchain's age (`rust-toolchain.toml` raised at least once every 180 days), the Windows code-signing certificate's expiry (spec 060-reproducible-builds R5), the next release under R3, the renewal of the domain of `DEFAULT_SERVER_URL`, and the 60 days after which GitHub disables the scheduled workflows of R6 and of spec 066-public-server R6 in a repository with no activity; each date is taken from the store's, the registrar's or GitHub's own page and the row cites it. A row is met by a release, except the domain row, met by its "renewed on" date, and the GitHub row, met by a commit to the default branch. The TLS certificate has no row: Caddy renews it and spec 066-public-server R6 probes it. A release that raises a toolchain, an SDK or a floor goes through spec 060-reproducible-builds like any other.
- R5 `.github/dependabot.yml` MUST cover every lock file, weekly, grouped per directory, with the prefix `chore`: `cargo` at `/`, `/crates/host`, `/bindings/uniffi`, `/clients/desktop/src-tauri` and `/crates/core/fuzz`; `npm` at `/clients/desktop` and `/landing`; `gradle` at `/clients/android`; `docker` at `/deploy` and `/deploy/release`; `github-actions` at `/`. The iOS app resolves no remote Swift package (spec 052-ios-mvp R7), so it has no entry. Dependabot does not rewrite `gradle/verification-metadata.xml` (spec 051-android-mvp R7), so a Gradle pull request MUST receive, before its CI can pass, a commit by the owner of the output of `./gradlew --write-verification-metadata sha256`, reviewed line by line, and never by a bot with write access. A Dependabot pull request passes the same CI as any other, `cargo deny` and the allowlists of spec 053-device-security R16 included; one that adds a name to an allowlist or a new crate to a lock file MUST carry the human reviewer's one-sentence justification (AGENTS 8) before merge.
- R6 A workflow `advisories.yml` MUST run weekly (`schedule`) and on `workflow_dispatch`, with `permissions: contents: read` and no secret, with a matrix whose `actions/checkout` steps check out the default branch and the `release/vX.Y` branch of the latest release, since a `schedule` alone runs on the default branch only; on each: `cargo deny check advisories` over every `Cargo.lock` of R5, `pnpm audit --prod` in `clients/desktop` and `npm audit --omit=dev` in `landing`. A failing run is triaged by the owner as a report of `.github/SECURITY.md`: an advisory that reaches a shipped artefact is fixed under R1, one that does not is recorded in `deny.toml` with its reason.
- R7 An update of libsodium, whether a new `libsodium-sys-stable` or a new stable archive, MUST change `Cargo.lock` and every file of `vendor/libsodium/` in one pull request, keeping every rule of spec 042-connection-host R15 (the five files, their minisign signatures, `LATEST.tar.gz` byte-identical to the crate's archive, and the hash recorded there); an advisory that R6's run reports against libsodium (`libsodium-sys-stable`), `rustls`, `tokio-tungstenite` or `tokio` in a shipped artefact MUST be fixed in the next PATCH tag (R1).

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| Versions that receive fixes | the latest `vX.Y.Z` | none |
| Time between `vX.Y.Z` tags | < 180 days | the deadline row fails (T04) |
| Rust toolchain age | ≤ 180 days at each release | the deadline row fails (T04) |
| `security.atom` entries | one per security release, never removed | — |
| Advisory and feed entry after a security tag | when the stores and F-Droid have it, at most 7 days | published at day 7 |
| Dependabot and `advisories.yml` | weekly | — |

## Interface

```
landing/public/security.atom           R2
docs/maintenance.md                     R2: "Security releases"; R4: deadlines table
.github/dependabot.yml                  R5 (changed)
.github/workflows/advisories.yml        R6
```

**PR slices** (AGENTS 14): (a) Dependabot, the advisories workflow and `docs/maintenance.md` (R4–R6); (b) the feed, the Help line and the release procedure in `.github/CONTRIBUTING.md` (R1–R3, R7).

## Security

- Fixes reach users without the app asking any server anything: the stores update their installs, the feed and the age notice of spec 056-chat-screens tell the others (R2, R3). A user who installed the direct download or the APK and reads neither runs a flawed version until the notice appears, up to 180 days after its tag: a documented residual.
- The advisory waits for the stores or at most 7 days (R2), so that disclosure does not run ahead of the fix for most users; a store that takes longer leaves its users exposed after disclosure: a documented residual.
- Only the latest release is fixed (R1): a user who stays on an older version keeps its flaws: a documented residual.
- The age notice reads the device clock; a clock set back hides it, a clock set ahead shows it early. Either harms nothing but the notice.
- Dependabot and the advisory databases are third parties; an update they propose is reviewed and rebuilt like any change, and a malicious release of a dependency is the residual spec 060-reproducible-builds already lists.
- A change to the cryptographic core after the public release is reviewed again before its tag (R1); any other change on a reviewed path ships marked `unreviewed` in `docs/review/delta.md`, read by no outside reviewer: a documented residual.

## Public API changes

None.

## Test cases

- T01 (covers R1): `check_s065_t01_r01_patch`: a `vX.Y.Z` tag later than the first public release sits on the default branch or on a `release/vX.Y` branch cut from the latest `vX.Y.Z` tag; a later tag whose diff from the previous one touches a spec 011–017 or a path under `crates/core/src/crypto/` or `crates/core/src/proto/` fails unless a signed `review-N+1` tag on its reviewed commit and a recorded report precede it; every other commit since the "Public release" row that touches a path of spec 061-threat-review R3 has a row in `docs/review/delta.md` marked `unreviewed`.
- T02 (covers R2): `check_s065_t02_r02_feed`: `security.atom` parses as Atom 1.0; every entry names a tag that exists and an advisory URL; each entry's date is not earlier than the "Security releases" row's store and F-Droid dates, unless it is 7 days after the tag's date, and never earlier than the tag's date; the security page links it; the Help string resources hold its URL in each UI language; no client source fetches it.
- T03 (covers R3): `check_s065_t03_r03_cadence`, run by `advisories.yml`: when the newest `vX.Y.Z` tag is 180 days old or more, the check fails; a fixture history with tags 179 days apart passes and one with a gap of 181 days fails.
- T04 (covers R4): `check_s065_t04_r04_deadlines`, run by `advisories.yml`: every row of `docs/maintenance.md` has a date and a source; a row whose date is past and that is not met as R4 says fails; a TLS row fails; `rust-toolchain.toml`'s version is at most 180 days older than the latest release's tag.
- T05 (covers R5): `check_s065_t05_r05_dependabot`: every lock file in the repository (`Cargo.lock`, `pnpm-lock.yaml`, `package-lock.json`, Gradle verification metadata, a `Dockerfile`) has a Dependabot entry for its directory with the prefix `chore`; the iOS `Package.resolved` names no remote package; a Gradle Dependabot pull request's verification-metadata change is in a commit by the owner, not by `dependabot[bot]`.
- T06 (covers R6): `check_s065_t06_r06_advisories`: `advisories.yml` has a weekly `schedule`, read-only permissions, no secret, a matrix that checks out both the default branch and the latest `release/vX.Y` branch, and runs `cargo deny check advisories` on every `Cargo.lock` of R5 and the two audits.
- T07 (covers R7): `check_s065_t07_r07_libsodium`: a change to the `libsodium-sys-stable` entry of `Cargo.lock` without a change to `vendor/libsodium/SHA256SUMS`, or the reverse, fails, and the checks of spec 042-connection-host R15 pass; non-automatable, each advisory R6 reported against the four crates of R7 names, in its triage, the PATCH tag that fixed it.

## Vectors

None.

## Acceptance criterion

The checks of T01–T07 green. Non-automatable: the first scheduled run of `advisories.yml` is green or triaged.

## Out of scope

- Updates inside the apps and any remote switch (spec 060-reproducible-builds, spec 063-beta R9).
- Fixes for versions other than the latest; long-term-support branches.
- Retiring a `proto_version` or a `config_version`: v1 has one of each.
- Running the project's server (spec 066-public-server).

## Open questions

- [ ] 065-R3: the 180 days of R3 and of the age notice of spec 056-chat-screens are a drafting choice; the human reviewer may choose another age or drop both.

## History

- 2026-09-28 draft (`docs/audit-log.md`, "Audit P", P-Q2)
- 2026-09-28 revised after audit P round 2 (`docs/audit-log.md`): the age notice moves to spec 056 and R3 becomes a release at least every 180 days; depends on 066 and blocks 064, which gates on it; R1 asks for `review-N+1` before a tag that changes the cryptographic core; R2 publishes the advisory once the stores have the fix or after 7 days; R4 drops the TLS row and adds the domain, next-release and GitHub inactivity rows; R5 the owner's Gradle verification commit and no Swift entry; R6 checks out both branches; R7 triggered by R6's advisories
