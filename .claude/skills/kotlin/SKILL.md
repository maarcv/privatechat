---
name: kotlin
description: Kotlin and Jetpack Compose standard for the Android client in `clients/android/`. Use it whenever you create or edit a `.kt` or `.kts` file, a Compose screen, a ViewModel, a Gradle build script, an Android manifest or resource, or when reviewing Android code — including "quick" UI tweaks. It assumes you have read the `architecture` skill, whose §7 "Client shape" holds everything the three clients share; this skill adds only the Android mechanics.
---

# Kotlin / Android standard

The shape of the app — layers, state and intents, how the core is driven, how
secrets are held, lifecycle, testing and tooling — is `architecture` §7. This
file is the Android delta. If you are writing protocol, parsing, counters, TTL
maths or anything about messages beyond displaying them, stop: it belongs in
`core`.

## Language and platform

- Kotlin 2.x, K2 compiler, `explicitApi()` off (it is an app),
  `allWarningsAsErrors = true`.
- Jetpack Compose with Material 3; `minSdk 26`. No Views, no Fragments, no
  XML layouts; a single `Activity`.
- Gradle Kotlin DSL with a version catalog (`gradle/libs.versions.toml`).
- Coroutines and `Flow` for everything asynchronous. No RxJava, no callbacks,
  no `LiveData`.

## Layout

```
ui/          Composables
viewmodel/   one ViewModel per screen: StateFlow<XxxUiState>, onIntent(XxxIntent)
platform/    Keystore, socket, file paths, clipboard, biometrics
```

- State and intents are `sealed interface`s; state is exposed as
  `StateFlow<ChannelUiState>`. Composables receive the state and a lambda per
  intent; they never call a ViewModel method from deep in the tree.
- Everything runs in `viewModelScope` or a scope cancelled with its owner.
  `GlobalScope` and un-scoped `launch` are bugs. Socket I/O is one coroutine
  per connection with an explicit `cancel()` on lock.

## Kotlin idioms that carry a project rule

- Never `!!`: the client face of "never panic on external data". Use `?.`,
  `?:`, and `requireNotNull(x) { "why" }` only for programming errors.
- `value class` for ids (`@JvmInline value class PeerId(val raw: Long)`),
  `sealed interface` for closed sets, `data class` for values: illegal states
  unrepresentable.
- `val` by default; `var` only in a ViewModel or a `platform/` class, never in
  a Composable.
- Map uniffi exceptions to the screen's `Error(kind)` at the ViewModel, once.
- Composables ≤ ~60 lines including the preview; `@Preview` for every
  screen-level Composable with representative states, including `Locked` and
  `Error`.
- `remember` only for purely visual, transient things. `LazyColumn` with
  `key = { it.serverId }`.
- Strings in `res/values/strings.xml`; content descriptions on every icon;
  minimum 48 dp touch targets; TalkBack once per screen.

## Platform layer

- Keystore: exactly the parameters in `docs/spec.md` §8, in one class
  `StorageKey` with `unwrap(): ByteArray` and nothing else. The unwrapped key
  goes once to the core and is zero-filled in a `finally`. `BiometricPrompt`
  with `DEVICE_CREDENTIAL` is the app lock; there is no app PIN.
- Password fields are `ByteArray`-backed; the `.chatcfg` password field uses
  `textPassword`, `IME_FLAG_NO_PERSONALIZED_LEARNING` and `flagNoExtractUi`
  (§8 "Keyboard").
- Screens that show a QR or the password words set `FLAG_SECURE`; the whole
  app does (§8 "Screenshot blocking").
- Lifecycle: `onStop` and screen-off → `Session.close()`, zero the key, drop
  the store handle. Reconnect in `onStart` with the core's cursor. No
  foreground service, no WorkManager, no push.
- Manifest: `allowBackup="false"`, `dataExtractionRules` excluding everything,
  no `exported` components, no `usesCleartextTraffic`, no custom URL scheme.
- Networking: OkHttp WebSocket. `now` is `System.currentTimeMillis()`.
- Clipboard: `ClipDescription.EXTRA_IS_SENSITIVE`, cleared after 60 s (§8).

## Testing

- JUnit 5 + `kotlinx-coroutines-test` + Turbine for `Flow`. Fake the core
  behind a small interface only where the uniffi object cannot be constructed
  in a test.
- Compose UI tests for the two flows of `architecture` §7.
- Test names: `s051_t02_r03_lock_closes_session_and_zeroes_key()`.

## Tooling

- `ktlint` (official style) and `detekt` with the project config; no
  `@Suppress` without a comment.
- Reproducible builds: fixed Gradle wrapper, locked dependency versions, no
  build-time network access beyond dependency resolution. F-Droid requires
  this.
- Debug builds sign with the debug key only; release signing happens in CI.
