# 051 — Android app: the Compose client over `Core`

Status: draft
Phase: 5
Related ADRs: 0012, 0037, 0041
Depends on: 040-uniffi, 042-connection-host, 053-device-security, 054-qr-invite, 055-verify-ui, 056-chat-screens
Blocks: 060-reproducible-builds, 063-beta, 064-public-release
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

The Android app reaches the core through `Core` of spec 040-uniffi, which wraps the connection host of spec 042-connection-host: the app opens no socket of its own. Specs 053–056 define what the three clients share, among them the Android storage key, the lock and the manifest (spec 053-device-security). This spec is the rest of the Android app in `clients/android/`: the Gradle project, how the app is wired at start, how the host's events reach the screens, the navigation, how the app tells the host that the network changed, its look, and its build, CI, tests and the start of its publication (`docs/spec.md` §10, phase 5).

**In plain words.** The Android app is one screen at a time, in Jetpack Compose, with the same screens as the other two apps. It holds nothing of a channel outside the core, remembers no screen across a restart, and locks whenever it leaves the foreground. When the phone changes network (from Wi-Fi to mobile data), it tells the shared host at once, so messages keep flowing without waiting for a timeout. It is built so that F-Droid can rebuild it, and publication starts in this phase.

## Requirements

**The project and the wiring**

- R1 `clients/android/` MUST be a Gradle project with the Kotlin DSL and a version catalog (`gradle/libs.versions.toml`), one application module `app` with the package `org.privatechat`, and a dependency on the library of `bindings/uniffi/kotlin/` (spec 040-uniffi R9) and on the `.so` files that `scripts/build_bindings.sh android` builds. It MUST set `minSdk 30` (spec 053-device-security R20), `compileSdk` and `targetSdk` to the newest stable API level at the time of the pull request, Kotlin 2 with `allWarningsAsErrors`, and Jetpack Compose with Material 3. The app has exactly one activity, `MainActivity`, a `FragmentActivity` (spec 053-device-security R6).
- R2 One `AppGraph`, built in `Application.onCreate`, MUST own the one `Core` of the process (`Core.create`, spec 040-uniffi R9), the `LockController` and `StorageKey` of spec 053-device-security, the clipboard and device-warning classes of that spec, and the state owners' factories, wired by hand with no dependency-injection library (architecture skill §7). A view model that must not lose a call's result when its screen goes away (`send`, the imports, `leave`, the settings setters) makes that call in the application's scope and applies the result through the unlock epoch of spec 056-chat-screens, since a caller cancelled inside `Core` loses the result though the call completes (spec 040-uniffi R9). `Core.create` suspends, so `Application.onCreate` launches it in the application's scope and the app shows the `Locked` screen until it returns. Its `CoreListener` MUST hand every call to one `kotlinx.coroutines.channels.Channel` with unlimited capacity through `trySend` and return, and one coroutine in the application's scope, on `Dispatchers.Main`, MUST read that channel and route each event: by channel to the channel's state owner and to the channel list, connection states to the app's state map of spec 056-chat-screens R21, whether or not the channel is listed yet, and `locked` to the app state, which drops every view model's data first (spec 053-device-security R21). The reader does not filter by generation: `Core` forwards nothing of an older generation (spec 040-uniffi R9). A `locked(fault)` that reaches the reader is current, and it moves `LockController` to locked (a lock the host started itself after a fault, spec 042-connection-host R7, included), so that its next `unlock` calls `Core.open` again and the network callback of R4 is unregistered; after every unlock the app reads `Core.connectionStates()` into the map (spec 056-chat-screens R21). At the end of the app's own lock, once `Core.lock` has returned, the reader MUST drain and discard every call still in the channel and only then clear the state map, so that events `Core` forwarded before its floor rose never reach the next unlock. The fault count of spec 056-chat-screens R20 lives in the app state, outside every view model, and only a successful reset or a new process sets it back to zero.
- R3 Navigation MUST be one `sealed interface Screen` held by the app state owner in memory, with the screens of specs 053–056, and a `BackHandler` for the system back: from a channel to the list, from a card to its channel, and from a screen that shows a secret it drops the secret first (specs 054-qr-invite R6, R10). No navigation library is used, so that no route, argument or back stack is saved: after a process restart the app opens on `Locked` (spec 053-device-security R21).
- R4 At each unlock the app MUST register a new `ConnectivityManager.registerDefaultNetworkCallback`, whose first `onAvailable` (which Android delivers at registration) only records the current network and calls nothing, and then call `core.networkChanged()` on `onAvailable` for a network other than the last one seen and on `onLost`, which also clears the last one seen, so that the same network returning after a loss calls it again, and unregister it at lock; the host merges calls closer than 10 000 ms (spec 042-connection-host R10). The app requests no network permission beyond `INTERNET` and `ACCESS_NETWORK_STATE`, which `clients/android/permissions.allow` lists (spec 053-device-security R17).

**Look and language**

- R5 The app MUST use a Material 3 theme that follows the system's dark setting, with the primary and secondary text colours of spec 055-verify-ui R4–R7 defined once in the theme at a contrast of at least 4.5:1 in both schemes, dynamic colour off (so that the secondary colour that marks an unknown key never depends on the wallpaper), 48 dp minimum touch targets, a content description on every icon, and text that scales with the system's font size up to 200 % without clipping a mark of spec 055-verify-ui R2. The verified icon is a vector drawable of the app.
- R6 Strings MUST live in `res/values/strings.xml` with English as the source and `values-es`, `values-fr`, `values-ca` and `values-it`; Android Lint's `MissingTranslation` and `ExtraTranslation` MUST be errors, and a test MUST fail on a placeholder that differs from the English one. The app sets `android:localeConfig` with those five locales, so that the system's per-app language setting offers them from API 33; on API 30–32 the app follows the system language, and Lint's `UnusedAttribute` for that attribute is suppressed with that reason.

**Build, tests and publication**

- R7 The release build MUST be minified with R8, with keep rules for JNA and the generated uniffi classes and nothing kept beyond them, and MUST pin the Gradle wrapper with its checksum, every dependency version in the catalog, and Gradle's dependency verification (`gradle/verification-metadata.xml` with SHA-256), so that F-Droid can rebuild it. It builds one APK per ABI of spec 040-uniffi R11, with the ABI index `A` of spec 060-reproducible-builds R2 (0 for `arm64-v8a`, 1 for `armeabi-v7a`, 2 for `x86_64`), and every `versionCode` and `versionName` derived from the release tag by that requirement, never written by hand. `clients/android/dependencies.allow` (spec 053-device-security R16) MUST list JNA's `aar`, `kotlinx-coroutines`, the Compose and AndroidX artefacts, `androidx.biometric`, and the ZXing and CameraX artefacts of spec 054-qr-invite, and their transitive dependencies as Gradle resolves them, and nothing else; the script of spec 053-device-security R16 prints what is missing.
- R8 A CI job `android` MUST run, in `clients/android/`, `./gradlew lintRelease ktlintCheck detekt test assembleRelease` and `connectedCheck` on emulators at API levels 30 and the `targetSdk`, after `scripts/build_bindings.sh android`, together with `scripts/check_client_dependencies.sh` for Android; `.github/CONTRIBUTING.md` MUST list the same commands (AGENTS 17). The job MUST also check, with `llvm-nm --defined-only` from rustup's `llvm-tools`, that the Rust library it packages holds no symbol `uniffi_privatechat_ffi_fn_constructor_ffihost_with_fixed_clock` (spec 040-uniffi's `test-clock` feature) and does hold the symbol of `FfiHost`'s `open`, as a positive control, so that an empty or unreadable symbol list never passes.
- R9 The view models MUST be tested with JUnit 5, `kotlinx-coroutines-test` and Turbine over a small interface `ChatCore` of the app that `Core` implements through a thin adapter, and a fake of it, since the native library does not load in a JVM unit test; the UI flows of specs 054-qr-invite, 055-verify-ui and 056-chat-screens run as Compose UI tests on the emulators of R8, over the fake.
- R10 Publication MUST start in this phase (`docs/spec.md` §10): `clients/android/fastlane/metadata/android/` MUST hold the store texts (title, short and full description) in the five UI languages, with no claim beyond `docs/spec.md` §1's lists, for F-Droid and Google Play, and the phone screenshots and the Play feature graphic in those languages, rendered by the screenshot tests of R5 (which draw the composables without a window, so `FLAG_SECURE` never has to be lifted) over the fake of R9 with invented names and messages, never a real person, a real config or a real server; the Google Play "Data safety" form states that no data is collected or shared, on the grounds `docs/release-legal.md` records for every store (spec 052-ios-mvp R10: end-to-end encrypted content, opaque blobs kept only until their TTL, addresses in memory only for the connection), the export-compliance answer is the one of spec 052-ios-mvp R10 (052-R10, recorded in `docs/release-legal.md`), and the pull request that accepts this spec records that the F-Droid inclusion request and the Play developer account were started. The F-Droid inclusion request, with its `fdroiddata` recipe `metadata/org.privatechat.yml`, is filed but not merged before the beta ends, since F-Droid publishes every tag it builds (spec 064-public-release R3); the Play record is for the public release (spec 064-public-release R4), and the beta reaches Android testers by the owner-signed APK (spec 063-beta R2). The application identifier `org.privatechat` does not change with the product name.
- R11 Every Google Play review submission MUST carry, in the Play Console's "App access" instructions kept in `clients/android/fastlane/metadata/android/review_notes.txt`, how to create a channel on the default server (spec 066-public-server) and invite a second device, since a file invitation lasts only 24 h (spec 011-config-format R18) and no account exists to hand over; and the standing answer on user-generated content that spec 052-ios-mvp R12 gives (end-to-end encrypted, no accounts; mute, forget, leave and create a new channel). The IARC content-rating questionnaire is answered once and recorded in the same folder, and the default server MUST be up for the whole review.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| `minSdk` | 30 | — |
| Font scale | up to 200 % | a failing screenshot test |
| `networkChanged` calls | as the network callback reports | merged by the host within 10 000 ms |
| Events queued from `CoreListener` | unbounded, drained on the main thread | — |

## Interface

```
clients/android/settings.gradle.kts, build.gradle.kts, gradle/libs.versions.toml, gradle/verification-metadata.xml
clients/android/app/build.gradle.kts, proguard-rules.pro
clients/android/app/src/main/kotlin/org/privatechat/
  App.kt                    Application: AppGraph (R2)
  AppGraph.kt               Core, LockController, the state owners' factories, the event channel (R2)
  MainActivity.kt           the FragmentActivity, the BackHandler (R3)
  AppState.kt               sealed interface Screen and the app state owner (R3)
  platform/Network.kt       the default-network callback (R4)
  platform/ChatCore.kt      the interface over Core (R9)
  ui/theme/                 Theme.kt, Color.kt (R5)
clients/android/app/src/main/res/values*/strings.xml, xml/locales_config.xml   R6
clients/android/fastlane/metadata/android/{en-US,es-ES,fr-FR,ca,it-IT}/        R10 (texts, screenshots, feature graphic)
clients/android/fastlane/metadata/android/review_notes.txt                      R11
```

```kotlin
// org.privatechat
sealed interface Screen {
    data object Locked : Screen
    data object SettingsNotice : Screen
    data object Channels : Screen
    data class Channel(val id: ChannelId) : Screen   // held in memory only (R3)
    // the other screens of specs 053–056
}
interface ChatCore { /* the Core methods the view models call, one to one (R9) */ }
```

The screens, their states and intents are those of specs 053-device-security, 054-qr-invite, 055-verify-ui and 056-chat-screens, in the files they name.

Test names: `s051_tTT_rRR_<name>` in snake_case, as the kotlin skill gives.

**PR slices** (AGENTS 14): (a) the project, the theme, the strings and the CI job (R1, R5, R6, R8); (b) the graph, the event channel and the navigation (R2, R3); (c) the network callback (R4); (d) the build rules, the allowlist, the publication metadata and the review notes (R7, R10, R11); (e) the test setup (R9). The screens of 053–056 land in their own slices, inside this app.

## Security

- The app opens no connection of its own (spec 040-uniffi R10); its sockets are the host's, with the host's TLS and proxy (ADR 0041). `INTERNET` and `ACCESS_NETWORK_STATE` are its only network permissions (R4).
- No screen state is saved and no route is kept (R3), so a restored process shows nothing but `Locked` (spec 053-device-security R21).
- Events cross from the host's threads into one channel read on the main thread (R2); the listener never blocks the host (spec 042-connection-host R5).
- Dynamic colour is off (R5), so an app or a wallpaper cannot make the secondary colour of an unknown key look like the primary one.
- The build is pinned and verified (R7), which reproducible builds (spec 060-reproducible-builds) and F-Droid need.

## Public API changes

None.

## Test cases

- T01 (covers R1): `s051_t01_r01_project`: the merged manifest has one activity, a `FragmentActivity`, and `minSdk` 30.
- T02 (covers R2): `s051_t02_r02_events`: 1 000 events sent through the listener from 4 threads all reach the main-thread reader, in order per thread, and the listener returns within 1 ms each; `locked` empties every view model before the Locked screen is drawn; a connection state for a channel not yet listed is shown once it is listed; until `Core.create` returns the Locked screen shows; end to end over the real `Core`, a lock then an unlock within the grace with 2 s of calls queued leaves the app unlocked and showing only the new unlock's states; a `locked(fault = true)` the app did not start moves `LockController` to locked, and the next "Unlock" calls `Core.open`; after an unlock `connectionStates()` fills the map. Events sent through the listener while `Core.lock` runs never reach the next unlock's state map, and the fault count survives a lock and an unlock.
- T03 (covers R3): `s051_t03_r03_navigation`: back from a channel gives the list; back from the seven words zeroes them; after the activity is recreated by a configuration change the app keeps its screen, and after a process death it opens on `Locked`, with nothing in the saved-state bundle but Compose's own keys.
- T04 (covers R4): `s051_t04_r04_network`: with a fake `ConnectivityManager`, the `onAvailable` delivered at registration calls nothing; a new network and a lost one each call `networkChanged` once; the same network again calls nothing, but after its `onLost` it calls once more; after lock no call follows, and the next unlock registers a new callback.
- T05 (covers R5): `s051_t05_r05_look`: screenshot tests of a channel in both schemes and at 200 % font scale show every mark of spec 055-verify-ui R2 whole; the theme's text colours reach 4.5:1; dynamic colour is off.
- T06 (covers R6): `s051_t06_r06_strings`: Lint with a missing Catalan string fails; a changed placeholder fails the test; `localeConfig` lists the five locales; `UnusedAttribute` is suppressed only for `localeConfig`.
- T07 (covers R7): `s051_t07_r07_release_build`: `assembleRelease` passes dependency verification; the release APK holds the uniffi classes and no class R8 should have removed (a mapping check); `check_client_dependencies.sh` passes on the real list, which holds the resolved transitive names (`kotlin-stdlib` among them), and fails with one name removed; the release build's `versionCode` for a test tag equals the value spec 060-reproducible-builds R2 gives.
- T08 (covers R8): CI job step `s051_t08_r08_android_job`, which runs the commands of R8; the symbol check fails on a library built with `test-clock` and on an empty symbol list; `.github/CONTRIBUTING.md` lists them.
- T09 (covers R9): `s051_t09_r09_flows`: the three UI flows of R9 pass on both emulators.
- T10 (covers R10): `s051_t10_r10_store_texts`: the metadata, the screenshots and the feature graphic exist in the five languages, the texts within the stores' length limits; the images come from the screenshot tests over the fake; non-automatable, the requests recorded in the pull request.
- T11 (covers R11): `check_s051_t11_r11_review_notes`: `review_notes.txt` exists, names the default server and says how to invite a second device, and holds the answer on user-generated content; the IARC answers exist.

## Vectors

None.

## Acceptance criterion

The CI job `android` green. Non-automatable: on a phone with Android 11 and one with the newest release, a person unlocks, joins a channel by QR from the desktop, chats with an iPhone, switches between Wi-Fi and mobile data while chatting and sees messages continue, locks by turning the screen off, and does a TalkBack pass over the Locked screen and a channel.

## Out of scope

- The storage key, the lock, the manifest's permissions and exports, and backups (spec 053-device-security).
- The screens' rules (specs 054-qr-invite, 055-verify-ui, 056-chat-screens).
- Signing and reproducible builds (spec 060-reproducible-builds).
- Tablets and foldables beyond one pane, widgets, and a background service: none is in v1.

## Open questions

- [ ] 051-R11: whether Google Play's user-generated-content policy for the Communication category accepts the standing answer of R11 for an app with no accounts and no one to report to; if Play refuses it, the owner decides, as for 052-R12.

## History

- 2026-09-27 draft (`docs/audit-log.md`, "Phase 5 drafts", Q9 and Q11)
- 2026-09-27 revised after audit N round 1 (`docs/audit-log.md`): Locked until `Core.create` returns; states to the app's state map; a new network callback per unlock whose first report is a baseline; `localeConfig` from API 33; transitive names in the allowlist
- 2026-09-27 revised after audit N round 2 (`docs/audit-log.md`): generations on the listener's calls and the lock state from `LockController`; `connectionStates()` after unlock; `onLost` clears the last network; the packaged library's symbol check
- 2026-09-27 revised after audit N round 3 (`docs/audit-log.md`): no generation filter in the reader, `Core`'s alone; a `locked` the host started moves `LockController` to locked
- 2026-09-27 revised after audit N round 4 (`docs/audit-log.md`): the event queue drained and discarded at the end of the app's own lock before the map is cleared; the fault count kept outside the view models
- 2026-09-27 revised after audit O round 1 (`docs/audit-log.md`): the F-Droid request unmerged until the public release, Play for the public release (specs 063-beta, 064-public-release)
- 2026-09-27 amended after audit O round 2 (`docs/audit-log.md`): the `versionCode` and ABI index derived from the tag (spec 060-reproducible-builds R2)
- 2026-09-28 revised after audit P (`docs/audit-log.md`): store screenshots and feature graphic from the screenshot tests; the export-compliance answer of 052-R10; review notes, the answer on user-generated content and the IARC rating (R11)
- 2026-09-28 revised after audit P round 2 (`docs/audit-log.md`): the "Data safety" answer rests on the reasons `docs/release-legal.md` records
