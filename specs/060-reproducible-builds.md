# 060 — Reproducible builds, signing and published hashes

Status: draft
Phase: 6
Related ADRs: 0017, 0041
Depends on: 034-docker, 040-uniffi, 041-desktop-bridge, 042-connection-host, 050-desktop-mvp, 051-android-mvp, 052-ios-mvp
Blocks: 062-security-docs, 063-beta, 064-public-release
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

A client whose code a server or a store could change silently would undo the model: `docs/spec.md` §2 answers a malicious server with "open source + reproducible builds", and §8 "Code integrity" asks for reproducible builds with published hashes on every platform. This spec defines how a release is built, how it is signed, and how anyone can check that the published artefacts come from the tagged source. The human reviewer decided on 2026-09-27 that the signing keys live on hardware tokens held by the human owner, and that CI builds while a local machine signs (`docs/audit-log.md`, "Phase 6 drafts", Q14); that the beta's Android build is the owner-signed APK sent by private link, Google Play being decided by spec 064-public-release (Q15); and that a spec 064 covers the public release (Q18).

Not every artefact can be bit-for-bit reproducible. The App Store re-signs and encrypts every iOS binary. A macOS or Windows signature cannot be removed back to the original bytes (measured on 2026-09-27: the linker already ad-hoc signs a Mach-O, and `codesign --remove-signature` leaves a file of another size), so those binaries are compared after stripping the signature from both copies. Installers that contain signed binaries are rebuilt around them. And macOS and Windows artefacts cannot be rebuilt in a Linux container, so only their own build hosts can compare them.

**In plain words.** The project builds each version twice in its CI and once more on the owner's own computer, and signs only when the three agree byte for byte. It then publishes a list of the files' fingerprints (hashes), signed with a key on a small hardware device the owner keeps, which needs a touch for every signature, with a spare device kept elsewhere. Anyone can rebuild the server, the Linux app and the Android app in a container and get the same files; the macOS, Windows and iPhone apps can be checked only in part, and the spec says which part. The key's fingerprint is published in places that do not depend on GitHub, so that taking over the project's GitHub account is not enough to pass off a changed app.

## Requirements

**Tags and inputs**

- R1 A release MUST be built only from an annotated tag signed with the owner's hardware-backed SSH key (`sk-ssh-ed25519`, `git tag -s` with `gpg.format = ssh`), of one of three forms: `vX.Y.Z` (a public release, spec 064-public-release), `vX.Y.Z-beta.N` (a beta build, spec 063-beta) and `vX.Y.Z-rc.N` (a CI trial, never published). The tag is on the default branch or on a branch `release/vX.Y` cut from a tag spec 061-threat-review reviewed (`git merge-base --is-ancestor`). A tag whose build failed is never moved or reused: the next PATCH or `N` follows. The CI jobs of R9 MUST run only for tags matching `v*`, re-fetch the tag (`+refs/tags/$T:refs/tags/$T`), fail unless `git cat-file -t $T` is `tag`, and verify it with `git verify-tag` against the `.github/allowed_signers` of the previous release tag (the tag's own copy for the first release), checking the exit status and never the output text (measured on 2026-09-27: a wrong key prints "Good" and exits 1).
- R2 Every build MUST be deterministic in its inputs:
  - the toolchains pinned: `rust-toolchain.toml`, the Node version of `.nvmrc`, the Android SDK, NDK and build-tools, the Xcode version, the MSVC toolset and the Windows SDK; base images pinned by digest (spec 034-docker R1) and Debian packages from `snapshot.debian.org` at a fixed date;
  - every lock file (the root, `crates/host/`, `bindings/uniffi/`, `clients/desktop/src-tauri/`, `pnpm-lock.yaml` with `ignore-scripts`, Gradle's verification metadata, `Package.resolved`) and `cargo build --locked`;
  - the tools that bundlers download at bundle time (Tauri's linuxdeploy, AppRun and its plugins, NSIS) committed with their SHA-256 under `vendor/bundler/` and placed in the bundler's cache before it runs;
  - `CARGO_INCREMENTAL=0`, and `--remap-path-prefix` of both the repository root and `$CARGO_HOME` to fixed names, set by `scripts/release_env.sh` since `.cargo/config.toml` cannot expand variables (measured: a different `CARGO_HOME`, or a path dependency outside the workspace, changes the binary without them; `trim-paths` is unstable on 1.98.1);
  - `SOURCE_DATE_EPOCH` set to the tag's commit time, for the tools that read it (buildkit, `dpkg-deb`, the zip and NSIS steps of R3); rustc and `cargo build` do not read it (measured);
  - `libsodium-sys-stable` without its `optimized` feature and with no `CFLAGS` in the environment, since that feature builds with `-march=native`;
  - the beta flag of spec 063-beta R3 compiled from the tag's `-beta.N` suffix, so a beta build is as reproducible as a public one;
  - no network access after dependency resolution, the vendored libsodium of spec 042-connection-host R15 included.
- R3 The job `release` MUST build each artefact twice, with the same pinned toolchain image or version and a different host, user, build path and `CARGO_HOME`, and fail unless the two are byte-identical; it writes `unsigned-hashes.txt`, one line `<sha256>  unsigned/<name>` per artefact, as a run artefact. The artefacts are:
  - the server's OCI image, built with buildkit, `SOURCE_DATE_EPOCH` as a build argument, `rewrite-timestamp=true`, `--no-cache`, `--provenance=false` and `--sbom=false`, compared by its per-platform manifest digest (measured identical with these flags and different without them), and its binary as spec 034-docker R1 builds it;
  - the desktop's unsigned Linux AppImage and `.deb`, the `.deb` repacked by `dpkg-deb --root-owner-group` with sorted entries and file times clamped to `SOURCE_DATE_EPOCH` (Tauri's own `.deb` records file times and directory order, source-read on 2026-09-27);
  - the desktop's unsigned macOS `.app`, hashed as the zip made by `touch -h` of every file to `SOURCE_DATE_EPOCH`, then `LC_ALL=C sort` of the file list and `TZ=UTC zip -X -y -D -@` (measured identical);
  - the desktop's unsigned Windows executable and NSIS installer, linked with `/Brepro` and with no PDB path, and the installer built with file times normalised (`SetDateSave off`);
  - the unsigned Android APK of each ABI (spec 051-android-mvp R7), with `dependenciesInfo { includeInApk = false; includeInBundle = false }`;
  - the unsigned iOS `.app` of `xcodebuild archive` with `CODE_SIGNING_ALLOWED=NO`, hashed as the macOS zip is.
  A differing byte fails the release; the only exceptions are the residuals of R4.
- R4 These MUST be documented residuals, listed with the release (Security): the App Store re-signs and encrypts the iOS binary, and its `Info.plist` carries the build Mac's `BuildMachineOSBuild` and `DTXcodeBuild`, so only the unsigned archive is compared; macOS and Windows artefacts cannot be rebuilt in a Linux container, so a third party compares them only with the platform's own build host; the Windows desktop links the signed libsodium binary of spec 042-connection-host R15, whose SHA-256 is listed as an input and not rebuilt.

**Keys and signing**

- R5 A signing key MUST NOT exist as a CI secret or in any file in the repository, the CI runners or a cloud service (Q14), and every key MUST have a backup token enrolled when the key is created and kept in a separate place. Each key and its backup MUST need a physical touch for every signature (the `sk-ssh` keys created without `no-touch-required`, PIV touch policy "always"). The keys are:
  - the release key: an `sk-ssh-ed25519` key and its backup, which sign tags (R1) and `SHA256SUMS` with `ssh-keygen -Y sign -n privatechat-release`;
  - the Android signing key, generated once on an offline machine and imported into two tokens (or kept as a pre-signed APK signature scheme v3 rotation lineage), used through PKCS#11 as `java -Djava.security.properties=<file naming SunPKCS11 and its config> -jar apksigner.jar sign --ks NONE --ks-type PKCS11` (measured: the `--provider-class` form fails on JDK 22), with signature schemes v2 and v3;
  - the Apple distribution and Developer ID identities, on a smart card that CryptoTokenKit exposes to `codesign` and Xcode;
  - the Windows Authenticode certificate, from an authority that ships it on a physical token (the CA/Browser Forum's code-signing rules require a hardware module since 2023, and several authorities now sell only cloud modules, which R5 forbids), renewed within its validity (currently at most about 460 days), used with `osslsigncode` and the token's PKCS#11 module.
  `docs/release-keys.md` MUST list every key and backup with its fingerprint, its creation date and, for a certificate, its history; `.github/allowed_signers` MUST hold the release keys' public halves with `namespaces="git,privatechat-release"`, and `check_s060_t05_r05_keys` fails when the two files disagree. A key is replaced only by a statement signed by a key that is still listed; a retired key's entry keeps a `valid-before` date and the list of `SHA256SUMS` it legitimately signed, and `verify_release.sh` rejects any other manifest signed by it.
- R6 Signing MUST happen on the owner's machine, a dedicated or live-booted macOS machine, with `scripts/sign_release.sh <tag>`, which:
  - verifies the tag (R1), rebuilds locally, in the pinned container of R8, every artefact a Linux container can rebuild, and on that macOS host the macOS and iOS artefacts, and refuses to go on unless each equals the matching line of `unsigned-hashes.txt` (a compromised CI then cannot pass a changed artefact, since the owner's rebuild does not match);
  - signs the APKs (R5), and `codesign`s, notarises and staples the macOS app, then rebuilds the macOS zip and dmg around the signed app; signs the Windows executable with `osslsigncode` and rebuilds the NSIS installer around it (Tauri's installer embeds and signs the executable and the uninstaller, so a signed installer is never the unsigned one plus a signature);
  - signs the iOS archive with the distribution identity, exports the IPA and uploads it to App Store Connect with Transporter;
  - writes `SHA256SUMS`: a first line `# <tag> <full commit SHA>`, then `<sha256>  unsigned/<name>` and `<sha256>  signed/<name>` for every artefact that shipped, the libsodium input of R4 and the iOS archive; prints its hash for the owner to read; signs it (R5) into `SHA256SUMS.sig`;
  - uploads the signed artefacts, `SHA256SUMS` and `SHA256SUMS.sig` to a draft GitHub release of the tag, published only for a `vX.Y.Z` tag, and left a draft for `-beta.N` and `-rc.N`.
  It makes no network request other than to GitHub, Apple's notary and timestamp services, App Store Connect, and the RFC 3161 timestamp service of the Windows authority. The App Store Connect API key and every other non-signing credential are held in the owner's keychain alone. A platform whose key is unavailable may be left out of a release; `SHA256SUMS` then lists only what shipped, and nothing is uploaded before every key present has signed.
- R7 The signed APK MUST be the rebuilt unsigned APK plus its signature block: the CI job `verify` rebuilds the APK and checks it with `apksigcopier compare` against the signed one. F-Droid's own rebuild and its `AllowedAPKSigningKeys` are spec 064-public-release's.

**Checking a release**

- R8 `scripts/verify_release.sh <tag> <release key fingerprint>` MUST let a third party, with Docker and nothing else, check a release: it verifies `SHA256SUMS.sig` with `ssh-keygen -Y verify -f <allowed signers built from the fingerprint> -I <principal> -n privatechat-release` and refuses a key whose fingerprint differs from the argument; checks that the first line names the tag and a commit that the tag points to; rebuilds, in the pinned container of `deploy/release/Dockerfile`, the server image and binary, the Linux desktop artefacts and the unsigned APKs, and compares them; checks every signed APK with `apksigcopier compare`; checks the Windows artefacts by stripping their signatures with `osslsigncode remove-signature` and comparing the inner executable with a rebuild when the host can make one; and prints, per artefact, `match`, `MISMATCH` or `unchecked` (for macOS, iOS and a Windows build it cannot rebuild), exiting non-zero on any mismatch. On a macOS host it also rebuilds the macOS app and compares both copies after stripping their signatures, and checks the Team ID and certificate fingerprints of `docs/release-keys.md` with `codesign --display --verbose`.
- R9 The CI MUST have two jobs, both on `v*` tags only, with `permissions: contents: read`, every Action pinned by commit SHA and no secret: `release` (R3), and `verify`, which runs on a third runner when a release or a draft release receives its assets, and runs `verify_release.sh` with the fingerprint written in the workflow. `.github/CONTRIBUTING.md` MUST describe cutting, signing and verifying a release, including the macOS OpenSSH that supports security keys (Homebrew's, or `SSH_SK_PROVIDER` and `gpg.ssh.program`).
- R10 The release key's fingerprint MUST be published outside GitHub and the landing's host: in the external review report of spec 061-threat-review R8, in the apps' Help screen (spec 056-chat-screens R18), in the letter to beta testers (spec 063-beta R4), and in F-Droid's metadata once the app is there (spec 064-public-release).
- R11 In the pull request that marks this spec `accepted`, the sentences about release signing in CI MUST be replaced by "CI builds; the owner signs on a local machine with hardware keys (spec 060-reproducible-builds)": in the architecture skill ("release signing happens in CI with the offline key"), the kotlin skill ("release signing happens in CI"), the swift skill ("… in CI with the offline certificate") and the typescript-svelte skill ("… in CI with offline keys"); and `docs/spec.md` §8 "Code integrity" MUST name the hashes of the unsigned and signed artefacts, the signed manifest and the residuals of R4, and §11 the files of the Interface.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| A release tag | `vX.Y.Z`, `vX.Y.Z-beta.N` or `vX.Y.Z-rc.N`, annotated, signed by a key of the previous release's `allowed_signers` | the jobs refuse to run |
| Two CI builds, and the owner's rebuild | byte-identical | the release fails, or `sign_release.sh` refuses |
| A signature | one touch of a token per signature | — |
| Keys in CI, the repository or a cloud service | none | a failing review; the key is revoked and replaced |
| A signing key without a backup token | none | the key is not used |

## Interface

```
.github/workflows/release.yml     the jobs release and verify (R1, R3, R7, R9)
.github/allowed_signers            the release keys (R1, R5)
docs/release-keys.md               every key and backup, fingerprints, dates, history (R5)
scripts/release_env.sh             the path remaps and deterministic settings (R2)
scripts/sign_release.sh            R6, run by the owner
scripts/verify_release.sh          R8, run by anyone
deploy/release/Dockerfile          the pinned build container of R6 and R8
vendor/bundler/                    the bundlers' tools with their SHA-256 (R2)
```

`unsigned-hashes.txt` (R3): one line `<sha256>  unsigned/<name>` per artefact. `SHA256SUMS` (R6): `# <tag> <full commit SHA>`, then `<sha256>  unsigned/<name>` and `<sha256>  signed/<name>` lines, then `<sha256>  input/libsodium-1.0.22-stable-msvc.zip`.

**PR slices** (AGENTS 14): (a) `release_env.sh`, the vendored bundler tools, the double build of the server and the Linux desktop (R2, R3 for them); (b) Android, macOS, Windows and iOS unsigned builds (R3 for them, R4); (c) the keys document, the allowed signers and `sign_release.sh` (R1, R5, R6); (d) `verify_release.sh`, the `verify` job and the APK check (R7–R9); (e) the fingerprint publication and the amendments (R10, R11).

## Security

- A changed binary cannot pass for a release. The owner signs only what matches his own rebuild from the signed tag (R6), so a compromised CI runner, Action or GitHub account cannot slip a different artefact past the signature, and the manifest names its tag and commit (R6), so an old signed manifest cannot be passed off as a new release. The signing keys are on tokens that need a touch per signature (R5), so malware on the owner's machine cannot sign in the background.
- Taking over the GitHub account lets an attacker change the repository's key files, but not the fingerprint published elsewhere (R10) that `verify_release.sh` takes as an argument (R8), nor the previous release's `allowed_signers` that the CI tag check reads (R1).
- Reproducibility proves that a binary matches its source and its pinned toolchain and dependencies. It does not prove they are honest: a compromised toolchain, or a malicious version of a locked dependency, builds the same wrong binary every time. Review of dependency changes is what covers that (AGENTS 8).
- Documented residuals: the iOS app installed from the App Store cannot be compared with a rebuild, only its unsigned archive (R4); macOS and Windows artefacts can be compared only on their own build hosts, and a Linux verifier reports them `unchecked` (R4, R8); the Windows desktop runs a libsodium binary built by libsodium's author (R4); a key lost with its backup cannot be replaced for Android installs in place, whose users would reinstall and lose their channels (spec 053-device-security), which the backup token and the v3 lineage exist to avoid; releases need the owner, so a client fix waits for them (`.github/SECURITY.md` says so).

## Public API changes

None.

## Test cases

- T01 (covers R1): `check_s060_t01_r01_tags` in CI: a tag signed by a key absent from the previous release's `allowed_signers` stops both jobs; a lightweight tag, a tag not on an allowed branch, and a `review-1` tag start no job; a real tag passes.
- T02 (covers R2): `check_s060_t02_r02_deterministic_inputs`: the workflow sources `release_env.sh`, builds with `--locked` and network disabled after resolution; the check fails when libsodium's `optimized` feature or `CFLAGS` is set, when a bundler tool lacks its SHA-256, or when a base image has no digest.
- T03 (covers R3): CI step `s060_t03_r03_double_build`: the two builds of each artefact compare equal and `unsigned-hashes.txt` lists them; a fixture artefact with one byte changed fails the step.
- T04 (covers R4): `check_s060_t04_r04_residuals`: `SHA256SUMS` of a test release lists the libsodium input and the iOS archive; the Security section names the three residuals.
- T05 (covers R5): `check_s060_t05_r05_keys`: no workflow references a signing secret; no private key or keystore file is in the repository; `docs/release-keys.md` lists the four keys, each with a backup and a fingerprint, and agrees with `.github/allowed_signers`; a manifest signed by a retired key and absent from its list is rejected by `verify_release.sh`.
- T06 (covers R6): `s060_t06_r06_sign_release`: with fake signers and a fake CI hash file, a local rebuild that differs from CI's stops the script before signing; the written `SHA256SUMS` starts with the tag and commit line, lists both hashes of every artefact, and verifies with the fake key; a `-beta.N` tag leaves the GitHub release a draft; a missing platform key omits that platform and nothing else.
- T07 (covers R7): CI step `s060_t07_r07_apksigcopier`: `apksigcopier compare` passes on the signed APK and the rebuild, and fails on an APK rebuilt from a changed source.
- T08 (covers R8): `s060_t08_r08_verify_release`: against a test release, the script prints `match` for every artefact it rebuilds and `unchecked` for macOS and iOS on Linux; a wrong fingerprint argument, a byte of `SHA256SUMS` changed, or a first line naming another tag fails; a swapped artefact prints `MISMATCH` and exits non-zero.
- T09 (covers R9): CI step `s060_t09_r09_jobs`: both jobs run only on `v*` tags, with read-only permissions, Actions pinned by SHA and no secret; `.github/CONTRIBUTING.md` has the release section.
- T10 (covers R10): `check_s060_t10_r10_fingerprint`: the Help string resources and the beta letter hold the fingerprint of `docs/release-keys.md`.
- T11 (covers R11): `check_s060_t11_r11_amendments`, once this spec is `accepted`: none of the four skills says that signing happens in CI; §8 and §11 say what R11 lists.

## Vectors

None.

## Acceptance criterion

The jobs `release` and `verify` green for a `vX.Y.Z-rc.1` tag, left as a draft release; `scripts/sign_release.sh` run by the owner with the tokens and `scripts/verify_release.sh` run by a second person from a clean clone both succeed. Non-automatable: the backup tokens are enrolled and stored apart, and the fingerprint is published as R10 says.

## Out of scope

- Google Play, F-Droid and the public release's distribution (spec 064-public-release).
- Automatic updates inside the apps: v1 is updated through the stores and by downloading a new installer.
- Building libsodium from source on Windows (a later change, spec 042-connection-host R15).

## Open questions

- [ ] 060-R3: whether `androidx.profileinstaller`'s baseline profile, the Android Gradle plugin's resource ordering, the NSIS installer with normalised times and the MSVC link with `/Brepro` are deterministic across two hosts; to be measured in PR slice (b). What is not is removed from the release build rather than listed as an exception.

## History

- 2026-09-27 draft (`docs/audit-log.md`, "Phase 6 drafts", Q14)
- 2026-09-27 revised after audit O round 1 (`docs/audit-log.md`): the owner rebuilds before signing; fingerprints published outside GitHub and passed to the verifier; the previous release's signers check the tag; backup tokens, touch per signature and rotation; `-beta.N` and `-rc.N` tags, draft releases and release branches; split `release` and `verify` jobs; the manifest names its tag and commit; the measured determinism settings (path remaps, buildkit, zip, `.deb`, `/Brepro`, vendored bundler tools, snapshot packages); signed installers rebuilt around signed binaries; the signing host and endpoints per step, and the iOS upload; apksigner's working PKCS#11 form; Play and F-Droid moved to spec 064
