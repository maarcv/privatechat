# 052 — iOS app: the SwiftUI client over `Core`

Status: draft
Phase: 5
Related ADRs: 0012, 0037, 0041
Depends on: 040-uniffi, 042-connection-host, 053-device-security, 054-qr-invite, 055-verify-ui, 056-chat-screens
Blocks: 060-reproducible-builds, 063-beta, 064-public-release
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

The iOS app reaches the core through `Core` of spec 040-uniffi, which wraps the connection host of spec 042-connection-host: the app opens no socket of its own, so App Transport Security does not apply to its server connections (spec 053-device-security R17). Specs 053–056 define what the three clients share, among them the Secure Enclave key, the lock, the privacy cover and the `Info.plist` (spec 053-device-security). This spec is the rest of the iOS app in `clients/ios/`: the Xcode project, how the app is wired at launch, how the host's events reach the views, the navigation, how the app tells the host that the network changed, its look, and its build, CI, tests and the start of its publication (`docs/spec.md` §10, phase 5).

**In plain words.** The iPhone app has the same screens as the other two, in SwiftUI. It keeps nothing of a channel outside the core, restores no screen after the system closes it, and locks whenever it goes to the background. When the phone changes network, it tells the shared host at once. Publication on the App Store starts in this phase; how to answer Apple's questions about encryption export is left for a human to decide.

## Requirements

**The project and the wiring**

- R1 `clients/ios/Privatechat.xcodeproj` MUST be an Xcode project with one app target `Privatechat` for iPhone and iPad, iOS 17 as the deployment target (spec 040-uniffi R9), Swift with strict concurrency checking complete and warnings as errors (swift skill), SwiftUI, and a local package dependency on `bindings/uniffi/swift/` (`PrivatechatCore`, spec 040-uniffi R9), whose XCFramework `scripts/build_bindings.sh ios` builds. The app MUST declare one scene only (`UIApplicationSupportsMultipleScenes` false), so that one lock covers every window.
- R2 One `AppGraph`, built by the `@main` app, MUST own the one `Core` of the process (`Core.create`, spec 040-uniffi R9), the `LockController` and `StorageKey` of spec 053-device-security, the pasteboard, privacy-cover and device-warning types of that spec, and the view models' factories, wired by hand (architecture skill §7). Until `Core.create` returns, the app shows the `Locked` view. Its `CoreListener` MUST hand every call to one `AsyncStream` with `.unbounded` buffering and return, and one task owned by the app state, on the main actor, MUST iterate that stream and route each event: by channel to the channel's view model and to the channel list, connection states to the app's state map of spec 056-chat-screens R21, whether or not the channel is listed yet, and `locked` to the app state, which drops every view model's data first (spec 053-device-security R21). The reader does not filter by generation: `Core` forwards nothing of an older generation (spec 040-uniffi R9). A `locked(fault)` that reaches the reader is current, and it moves `LockController` to locked (a lock the host started itself after a fault, spec 042-connection-host R7, included), so that its next `unlock` calls `Core.open` again and the path monitor of R4 is cancelled; after every unlock the app reads `Core.connectionStates()` into the map (spec 056-chat-screens R21). At the end of the app's own lock, once `Core.lock` has returned, the reader MUST drain and discard every element still in the stream and only then clear the state map, so that events `Core` forwarded before its floor rose never reach the next unlock. The fault count of spec 056-chat-screens R20 lives in the app state, outside every view model, and only a successful reset or a new process sets it back to zero.
- R3 Navigation MUST be one `NavigationStack` over a path of a `Hashable` route enum held by the app state in memory, with the screens of specs 053–056 and no `NavigationPath` encoding, `@SceneStorage` or state restoration, so that after the system ends the process the app opens on `Locked` (spec 053-device-security R21). Leaving a screen that shows a secret drops the secret first (specs 054-qr-invite R6, R10).
- R4 While the device is unlocked, the app MUST run one `NWPathMonitor`, created anew at each unlock (a cancelled monitor never reports again, measured on 2026-09-27), started on a serial queue it owns and cancelled at lock; its first report, delivered at start, only records the current path, and afterwards the app calls `core.networkChanged()` when the path becomes `.satisfied` after it was not, and when the set of interface types in use changes (Wi-Fi to cellular and back); the host merges calls closer than 10 000 ms (spec 042-connection-host R10). The queue is the one use of GCD this app makes, and the swift skill names it at the acceptance of this spec. The app opens no connection of its own to help the host: the host's native sockets bring up cellular and follow an active VPN by themselves (measured on 2026-09-27 on an iPhone 15 Pro Max with iOS 26 (`docs/audit-log.md`, "Audit N", measurement of 042-R10)).

**Look and language**

- R5 The app MUST use the system's semantic colours, with the primary and secondary text colours of spec 055-verify-ui R4–R7 defined once in the asset catalogue at a contrast of at least 4.5:1 in light and dark appearance, follow Dynamic Type up to the largest accessibility size without clipping a mark of spec 055-verify-ui R2, give every icon an accessibility label, and draw the verified icon from an image of the app, never a character a name could contain.
- R6 Strings MUST live in `Localizable.xcstrings` with English as the source and Spanish, French, Catalan and Italian; a test MUST fail when a key lacks a translated value in one of them or a placeholder differs from the English one. The project lists those five as its localisations, so that the system's per-app language setting offers them.

**Build, tests and publication**

- R7 The project MUST commit its `Package.resolved`, pin the Xcode version used in CI, add no build phase that fetches from the network, and embed no framework beyond the XCFramework of spec 040-uniffi and the system's; `clients/ios/dependencies.allow` (spec 053-device-security R16) MUST list `PrivatechatCore` alone.
- R8 A CI job `ios` MUST run on a macOS runner, after `scripts/build_bindings.sh ios`, SwiftLint and SwiftFormat in lint mode over `clients/ios/`, and `xcodebuild build test` on simulators of iOS 17 and of the newest release, together with `scripts/check_client_dependencies.sh` for iOS; `.github/CONTRIBUTING.md` MUST list the same commands (AGENTS 17). The job MUST also check, with `llvm-nm --defined-only` from rustup's `llvm-tools`, that the XCFramework it packages holds no symbol `uniffi_privatechat_ffi_fn_constructor_ffihost_with_fixed_clock` (spec 040-uniffi's `test-clock` feature) and does hold the symbol of `FfiHost`'s `open`, as a positive control, so that an empty or unreadable symbol list never passes.
- R9 The view models MUST be tested with Swift Testing over a protocol `ChatCore` of the app that `Core` conforms to through a thin adapter, and a fake of it; the UI flows of specs 054-qr-invite, 055-verify-ui and 056-chat-screens run as XCTest UI tests on the simulators of R8, over the fake, launched with a launch argument that the release configuration compiles out.
- R10 Publication MUST start in this phase (`docs/spec.md` §10): `clients/ios/fastlane/metadata/` MUST hold the App Store texts (name, subtitle, description, keywords) in the five UI languages, with no claim beyond `docs/spec.md` §1's lists, and the App Store privacy answers state "Data Not Collected". The export-compliance answer (`ITSAppUsesNonExemptEncryption`) and any declaration it needs are 052-R10, decided by a human before the first submission; the pull request that accepts this spec records that the developer account and the App Store Connect record were started.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| Deployment target | iOS 17 | — |
| Dynamic Type | up to the largest accessibility size | a failing snapshot test |
| `networkChanged` calls | as the path monitor reports | merged by the host within 10 000 ms |
| Events queued from `CoreListener` | unbounded, drained on the main actor | — |
| Scenes | one | — |

## Interface

```
clients/ios/Privatechat.xcodeproj
clients/ios/Privatechat/
  PrivatechatApp.swift       @main: AppGraph (R2)
  AppGraph.swift             Core, LockController, the view models' factories, the event stream (R2)
  AppState.swift             the route enum and the app state (R3)
  Platform/Network.swift     NWPathMonitor on its own queue (R4)
  Platform/ChatCore.swift    the protocol over Core (R9)
  Resources/Localizable.xcstrings, Assets.xcassets   R5, R6
clients/ios/PrivatechatTests/, PrivatechatUITests/   R9
clients/ios/fastlane/metadata/{en-US,es-ES,fr-FR,ca,it}/   R10
```

```swift
// Privatechat
enum Route: Hashable { case channel(ChannelId), card(ChannelId), settings, help /* the other screens of specs 053–056 */ }   // memory only (R3)
@MainActor protocol ChatCore { /* the Core methods the view models call, one to one (R9) */ }
```

The screens, their states and intents are those of specs 053-device-security, 054-qr-invite, 055-verify-ui and 056-chat-screens, in the files they name.

Test names: `@Test func s052_tTT_rRR_camelCase()`, as the swift skill gives.

**PR slices** (AGENTS 14): (a) the project, the look, the strings and the CI job (R1, R5, R6, R8); (b) the graph, the event stream and the navigation (R2, R3); (c) the path monitor (R4); (d) the build rules, the allowlist and the publication metadata (R7, R10); (e) the test setup (R9). The screens of 053–056 land in their own slices, inside this app.

## Security

- The app opens no connection of its own (spec 040-uniffi R10); its sockets are the host's, with the host's TLS and proxy (ADR 0041). A native socket from the host follows an active VPN like `NWConnection` does, over Wi-Fi and cellular (measured on 2026-09-27 on an iPhone 15 Pro Max with iOS 26 (`docs/audit-log.md`, "Audit N", measurement of 042-R10)).
- No route and no screen state is saved (R3), so a process the system ended shows nothing but `Locked` (spec 053-device-security R21), and one scene means one lock (R1).
- Events cross from the host's threads into one stream read on the main actor (R2); the listener never blocks the host (spec 042-connection-host R5).
- The UI-test launch argument is compiled out of the release configuration (R9), so no release build can start with a fake core.

## Public API changes

None.

## Test cases

- T01 (covers R1): `s052_t01_r01_project`: the built `Info.plist` has `UIApplicationSupportsMultipleScenes` false and a deployment target of 17.0; the target builds with strict concurrency complete and no warning.
- T02 (covers R2): `s052_t02_r02_events`: 1 000 events sent through the listener from 4 tasks all reach the main-actor reader, in order per task, and each listener call returns within 1 ms; `locked` empties every view model before the `Locked` view is drawn; a connection state for a channel not yet listed is shown once it is listed; before `Core.create` returns the app shows `Locked`; end to end over the real `Core`, a lock then an unlock within the grace with 2 s of calls queued leaves the app unlocked and showing only the new unlock's states; a `locked(fault: true)` the app did not start moves `LockController` to locked, and the next "Unlock" calls `Core.open`; after an unlock `connectionStates()` fills the map. Events yielded while `Core.lock` runs never reach the next unlock's state map, and the fault count survives a lock and an unlock.
- T03 (covers R3): `s052_t03_r03_navigation`: back from a channel gives the list; leaving the seven words zeroes them; the app declares no `@SceneStorage` and no restoration identifier (a source check), and a relaunch opens on `Locked`.
- T04 (covers R4): `s052_t04_r04_network`: with a fake path source, the report at start calls nothing; an unsatisfied then satisfied path and a Wi-Fi to cellular change each call `networkChanged` once; the same path again calls nothing; after lock the monitor is cancelled and the next unlock creates a new one; no source of the app creates an `NWConnection` or a `URLSession` task (a source check).
- T05 (covers R5): `s052_t05_r05_look`: snapshot tests of a channel in both appearances and at the largest accessibility size show every mark of spec 055-verify-ui R2 whole; the colours reach 4.5:1; every icon has an accessibility label.
- T06 (covers R6): `s052_t06_r06_strings`: a key untranslated in Catalan, or a changed placeholder, fails the test; the project lists the five localisations.
- T07 (covers R7): `s052_t07_r07_build_rules`: `Package.resolved` is committed and names `PrivatechatCore`'s path alone; the app bundle embeds no framework but the XCFramework's; `check_client_dependencies.sh` passes on the real list and fails with a package added.
- T08 (covers R8): CI job step `s052_t08_r08_ios_job`, which runs the commands of R8; the symbol check fails on a library built with `test-clock` and on an empty symbol list; `.github/CONTRIBUTING.md` lists them.
- T09 (covers R9): `s052_t09_r09_flows`: the three UI flows of R9 pass on both simulators; the release build rejects the launch argument (it is absent from the binary's strings).
- T10 (covers R10): `s052_t10_r10_store_texts`: the metadata exists in the five languages, within the store's length limits; non-automatable, the records started, noted in the pull request.

## Vectors

None.

## Acceptance criterion

The CI job `ios` green. Non-automatable: on an iPhone with iOS 17 and one with the newest release, a person unlocks with Face ID or the passcode, joins a channel by QR from an Android phone, chats with the desktop, switches between Wi-Fi and cellular while chatting and sees messages continue, locks by going to the home screen, and does a VoiceOver pass over the `Locked` view and a channel.

## Out of scope

- The storage key, the lock, the privacy cover, file protection, backups and the `Info.plist` keys (spec 053-device-security).
- The screens' rules (specs 054-qr-invite, 055-verify-ui, 056-chat-screens).
- Signing, notarisation and reproducible builds (spec 060-reproducible-builds); the store's screenshots.
- Share extensions, widgets, background modes and push: none is in v1 (`docs/spec.md` §9, one process per data directory).

## Open questions

- [ ] 052-R10: how to answer App Store Connect's export-compliance question for an app whose messages are end-to-end encrypted with libsodium (`ITSAppUsesNonExemptEncryption`, and whether a self-classification or a national declaration is needed where the app is distributed). A legal decision for the human owner before the first submission; the build carries whatever key that decision names.

## History

- 2026-09-27 draft (`docs/audit-log.md`, "Phase 5 drafts", Q9 and Q11)
- 2026-09-27 revised after audit N round 1 (`docs/audit-log.md`): states to the app's state map; a new path monitor per unlock whose first report is a baseline; the fallback connection never for `needs_proxy` or onion hosts
- 2026-09-27 revised after audit N round 2 (`docs/audit-log.md`): generations on the listener's calls and the lock state from `LockController`; `connectionStates()` after unlock; the fallback connections bounded to 5 000 ms, cancelled on waiting, lock and proxy change, and chosen without plans; the packaged library's symbol check
- 2026-09-27 revised after audit N round 3 (`docs/audit-log.md`): no generation filter in the reader, `Core`'s alone; a `locked` the host started moves `LockController` to locked; the fallback targets channels `Connecting` or `Retrying`, and also runs at unlock and on `Retrying` over cellular
- 2026-09-27 revised after audit N round 4 (`docs/audit-log.md`): the event queue drained and discarded at the end of the app's own lock before the map is cleared; the fault count kept outside the view models; the fallback after unlock and `Retrying` calls `retryNow`, only over cellular
- 2026-09-27 042-R10 measured on a device: the host's native sockets bring up cellular and follow an active VPN, so R4's data-free `NWConnection` fallback is removed
