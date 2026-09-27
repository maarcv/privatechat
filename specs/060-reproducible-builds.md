# 060 — Reproducible builds, signing and published hashes

Status: draft
Phase: 6
Related ADRs: 0017, 0041
Depends on: 034-docker, 040-uniffi, 041-desktop-bridge, 042-connection-host, 050-desktop-mvp, 051-android-mvp, 052-ios-mvp
Blocks: 062-security-docs, 063-beta
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

A client whose code a server or a store could change silently would undo the model: `docs/spec.md` §2 answers a malicious server with "open source + reproducible builds", and §8 "Code integrity" asks for reproducible builds with published hashes on every platform. This spec defines how a release is built, how anyone can check that the published artefacts come from the tagged source, and how they are signed. The human reviewer decided on 2026-09-27 that the signing keys live on hardware tokens held by the human owner, and that CI builds while a local machine signs (`docs/audit-log.md`, "Phase 6 drafts", Q14).

Not every artefact can be bit-for-bit reproducible. The App Store re-signs and encrypts every iOS binary, and a signature on macOS, Windows or Android changes the file. So the rule is: the unsigned artefact is reproducible and its hash is published, and the signed artefact is the unsigned one plus a signature that anyone can strip or check.

**In plain words.** Anyone can take the source of a version, build it on their own computer, and get exactly the same files the project publishes, byte for byte, before signatures. The project publishes a list of the files' fingerprints (hashes), signed with a key that never leaves a small hardware device the owner keeps. So nobody, not even someone who takes over the project's GitHub account, can publish a changed app that passes for the real one. The one exception is the iPhone app, which Apple re-packages: there the project publishes the fingerprint of what it sent to Apple.

## Requirements

**Building a release**

- R1 A release MUST be built only from a tag `vMAJOR.MINOR.PATCH` on the default branch, signed with the owner's hardware-backed SSH key (`sk-ssh-ed25519`, `git tag -s` with `gpg.format = ssh`); the CI job `release` MUST refuse to run for a tag whose signature does not verify against `.github/allowed_signers`, a committed file that lists the owner's public key alone.
- R2 Every build of a release MUST be deterministic in its inputs: the toolchain of `rust-toolchain.toml`, every lock file (the root, `crates/host/`, `bindings/uniffi/`, `clients/desktop/src-tauri/`, `pnpm-lock.yaml`, Gradle's verification metadata, `Package.resolved`), base images pinned by digest (spec 034-docker R1), `SOURCE_DATE_EPOCH` set to the tag's commit time, `CARGO_INCREMENTAL=0`, `--remap-path-prefix` mapping the build directory to `/build`, `cargo build --locked`, and no network access after dependency resolution (the vendored libsodium of spec 042-connection-host R15 included).
- R3 The job `release` MUST build each reproducible artefact twice, on two runners with different images or in two clean containers with different build paths, and MUST fail unless the two copies are byte-identical. The reproducible artefacts are: the server's Docker image (its OCI digest) and its static binary; the desktop's unsigned Linux AppImage and `.deb`, unsigned macOS `.app` (zipped with fixed timestamps) and unsigned Windows executable and installer; the unsigned Android APK of each ABI (spec 051-android-mvp R7). A non-reproducible byte is a failing release, never a documented exception, except those of R4.
- R4 The iOS app MUST be built with `xcodebuild archive` from the same inputs, and the hash of the unsigned `.app` inside the archive published; the App Store re-signs and encrypts the binary, so the installed app cannot be compared with it. This is a documented residual (Security). The Windows desktop links the signed libsodium binary of spec 042-connection-host R15, whose SHA-256 is published with the release as an input, not rebuilt: a documented residual.

**Signing**

- R5 No signing key MUST exist as a CI secret or in any file in the repository, the CI runners or a cloud service (Q14). The keys are:
  - the release manifest key: the owner's `sk-ssh-ed25519` key of R1, which signs `SHA256SUMS` with `ssh-keygen -Y sign -n privatechat-release`;
  - the Android release key, on a hardware token through PKCS#11 (`apksigner sign --ks NONE --ks-type PKCS11 --provider-class sun.security.pkcs11.SunPKCS11`), APK signature scheme v2 and v3;
  - the Apple Developer ID and distribution identities, on a smart card that macOS's CryptoTokenKit exposes to `codesign` and Xcode;
  - the Windows Authenticode certificate, on the hardware token its authority issued it on (`signtool` with that token's provider).
  Each key's public half or certificate MUST be listed in `docs/release-keys.md`, with its fingerprint and the date it was created.
- R6 Signing MUST happen on the owner's machine, after CI, with `scripts/sign_release.sh <tag>`, which: downloads the release's unsigned artefacts from the CI run of R3; recomputes their hashes and refuses to go on unless they equal those both CI builds reported; signs each artefact with its key of R5; notarises and staples the macOS app; computes the hashes of the signed artefacts; writes `SHA256SUMS` with both the unsigned and the signed hash of every artefact, plus the libsodium input of R4 and the iOS archive hash; signs it (R5); and uploads the signed artefacts, `SHA256SUMS` and `SHA256SUMS.sig` to the GitHub release of the tag. It makes no other network request.
- R7 An Android build that F-Droid rebuilds MUST verify as the same APK: the signed APK's signature block copied onto F-Droid's unsigned rebuild (`apksigcopier`) gives a byte-identical file. The F-Droid metadata of spec 051-android-mvp R10 declares the signing key's fingerprint of `docs/release-keys.md` as `AllowedAPKSigningKeys`.

**Checking a release**

- R8 `scripts/verify_release.sh <tag>` MUST let a third party, with Docker and nothing else, rebuild in a pinned container the server image and binary, the Linux desktop artefacts and the unsigned Android APKs, and compare their hashes with `SHA256SUMS`, after checking `SHA256SUMS.sig` against `docs/release-keys.md` with `ssh-keygen -Y verify`. For a signed APK it also checks with `apksigcopier compare` that the signed APK is the rebuilt one plus its signature. The Linux artefacts carry no signature of their own: the signed manifest covers them. The signed macOS and Windows artefacts cannot be rebuilt in Docker, so the script checks their signed hashes against the manifest, and their platform signatures (`codesign --verify`, `signtool verify`) where the host can run them. It prints one line per artefact, `match` or `MISMATCH`, and exits non-zero on any mismatch.
- R9 The CI job `release` MUST run `scripts/verify_release.sh` against the release it has just built, on a third runner, as its last step. The job runs only on tags, and `.github/CONTRIBUTING.md` MUST describe how to cut, sign and verify a release (AGENTS 17).
- R10 In the pull request that marks this spec `accepted`, the kotlin, swift and typescript-svelte skills MUST replace "release signing happens in CI with the offline key" with "CI builds; the owner signs on a local machine with hardware keys (spec 060-reproducible-builds)", and `docs/spec.md` §8 "Code integrity" MUST name the hashes of the unsigned and signed artefacts, the signed manifest and the iOS residual.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| A release tag | `v` and three decimal numbers, signed by the key of `.github/allowed_signers` | the job refuses to run |
| Two CI builds of one artefact | byte-identical | the release fails |
| Signing | on the owner's machine, after both hashes match | `sign_release.sh` refuses |
| Keys in CI, the repository or a cloud service | none | a failing review; a key found there is revoked and replaced |

## Interface

```
.github/workflows/release.yml     the job release (R1, R3, R9)
.github/allowed_signers            the owner's public key (R1)
docs/release-keys.md               every public key and certificate with its fingerprint (R5, R7)
scripts/sign_release.sh            R6, run by the owner
scripts/verify_release.sh          R8, run by anyone
deploy/release/Dockerfile          the pinned build container of R8
```

The release on GitHub holds, for a tag `vX.Y.Z`: the signed artefacts; `SHA256SUMS`, one line per file, `<sha256>  <name>` with `unsigned/` and `signed/` prefixes; and `SHA256SUMS.sig`.

**PR slices** (AGENTS 14): (a) the deterministic settings and the double build for the server and the Linux desktop (R2, R3 for them); (b) Android, macOS and Windows unsigned builds (R3 for them) and the iOS archive (R4); (c) `sign_release.sh`, the keys document and the allowed signers (R1, R5, R6); (d) `verify_release.sh`, the third-runner check and the F-Droid metadata (R7–R9); (e) the amendments (R10).

## Security

- A changed binary cannot pass for a release: the unsigned artefacts are rebuilt identically by anyone (R3, R8), and the manifest of their hashes is signed with a key that lives only on the owner's hardware token (R5). Taking over the GitHub account or a CI runner gives no signing key.
- The owner signs only what both CI builds agreed on (R6), so a compromised runner cannot slip a different artefact past the signature.
- Documented residuals: the App Store re-signs and encrypts the iOS app, so users cannot compare what they installed with a rebuild, only trust that Apple delivered what was sent (R4); the Windows desktop runs a libsodium binary built by libsodium's author (R4, spec 042-connection-host R15); a lost or stolen token needs a new key, published in `docs/release-keys.md` with the reason, and Android apps signed with a lost key cannot be updated in place (store key upgrade rules apply).
- The build toolchains (rustc, the Android and Apple SDKs, Node) are trusted inputs pinned by version; a compromised toolchain would build the same wrong binary twice. Reproducibility proves the binary matches the source and the toolchain, not that the toolchain is honest.

## Public API changes

None.

## Test cases

- T01 (covers R1): `check_s060_t01_r01_tag_signature` in CI: a tag signed with a key absent from `allowed_signers` stops the job before any build; the real tag passes.
- T02 (covers R2): `check_s060_t02_r02_deterministic_inputs`: the workflow sets `SOURCE_DATE_EPOCH`, `CARGO_INCREMENTAL=0` and the path remap, builds with `--locked`, and runs its build steps with network disabled.
- T03 (covers R3): CI step `s060_t03_r03_double_build`: the two builds of each artefact of R3 compare equal; a fixture artefact with one byte changed makes the step fail.
- T04 (covers R4): CI step `s060_t04_r04_ios_archive`: the archive is built and its unsigned `.app` hash lands in `SHA256SUMS`; the libsodium input hash is listed.
- T05 (covers R5): `check_s060_t05_r05_no_keys`: no workflow references a signing secret; a scan of the repository finds no private key or keystore file; `docs/release-keys.md` lists four keys with fingerprints.
- T06 (covers R6): `s060_t06_r06_sign_release`: with fake signers, a downloaded artefact whose hash differs from CI's makes the script stop before signing; the written `SHA256SUMS` has both hashes of every artefact and verifies with the fake manifest key.
- T07 (covers R7): non-automatable until F-Droid builds the app: F-Droid's reproducible-build check reports the APK as verified.
- T08 (covers R8): `s060_t08_r08_verify_release`: against a release built by the job, the script prints `match` for every artefact it rebuilds; with a byte of `SHA256SUMS` changed it fails the signature check; with an artefact swapped it prints `MISMATCH` and exits non-zero.
- T09 (covers R9): CI step `s060_t09_r09_release_job`: the job runs only on tags and ends with the third-runner verification; `.github/CONTRIBUTING.md` has the release section.
- T10 (covers R10): `check_s060_t10_r10_amendments`, once this spec is `accepted`: the three skills and §8 say what R10 lists.

## Vectors

None.

## Acceptance criterion

The job `release` green for a test tag (`v0.0.1-rc` built but not published); `scripts/verify_release.sh` reproduces it on a machine other than the runners. Non-automatable: the owner signs the test release with the hardware tokens and a second person verifies it with `verify_release.sh` from a clean clone.

## Out of scope

- Automatic updates inside the apps: v1 is updated through the stores and by downloading a new installer.
- Building libsodium from source on Windows (a later change, spec 042-connection-host R15).
- Store submission itself (spec 063-beta for the beta's tracks).

## Open questions

- [ ] 060-R3: whether `androidx.profileinstaller`'s baseline profile and the Android Gradle plugin's resource ordering are deterministic across two machines; to be measured in PR slice (b). If not, the profile is removed from the release build rather than listed as an exception.

## History

- 2026-09-27 draft (`docs/audit-log.md`, "Phase 6 drafts", Q14)
