---
name: kotlin
description: Kotlin and Jetpack Compose standard for the Android client in `clients/android/`. Use it whenever you create or edit a `.kt` or `.kts` file, a Compose screen, a ViewModel, a Gradle build script, an Android manifest or resource, or when reviewing Android code — including "quick" UI tweaks. It assumes you have read the `architecture` skill: the Android app is a thin shell over the Rust core (uniffi) and holds no protocol logic, no crypto and no persistent state of its own.
---

# Kotlin / Android standard

The Android app does four things: open a socket, drive `Session`, render what it
says, and ask the Keystore for a key. Everything else is in Rust. If you find
yourself writing protocol, parsing, counters, TTL maths or anything about
messages beyond displaying them, stop: it belongs in `core` (architecture §1).

## Language and platform

- Kotlin 2.x, K2 compiler, `explicitApi()` off (it is an app), `allWarningsAsErrors = true`.
- Jetpack Compose with Material 3; `minSdk 26`. No Views, no Fragments, no
  XML layouts; a single `Activity`.
- Gradle Kotlin DSL with a version catalog (`gradle/libs.versions.toml`). Every
  dependency has a one-line justification in the PR. No analytics, crash or
  ads SDKs of any kind (`docs/spec.md` §8 "Telemetry").
- Coroutines and `Flow` for everything asynchronous. No RxJava, no callbacks,
  no `LiveData`.

## Architecture inside the app

Unidirectional data flow, three layers, dependencies pointing inwards:

```
ui/          Composables. Render state, emit intents. No logic.
viewmodel/   One ViewModel per screen. Owns a StateFlow<UiState>, handles intents.
platform/    Keystore, socket, file paths, clipboard, biometrics. The only
             code that touches Android APIs beyond Compose.
core (Rust)  via uniffi: Config, Channel, Session, Settings — opaque handles.
```

- **UI state is one `sealed interface`** per screen (`Loading`, `Ready(data)`,
  `Locked`, `Error(kind)`), exposed as `StateFlow<ChannelUiState>`. Composables
  receive the state and a lambda per intent; they never touch a ViewModel
  method directly from deep in the tree.
- **Intents are a `sealed interface`** too (`SendText(text)`, `LabelPeer(id,
  name)`, `Lock`). One `onIntent(intent)` entry point per ViewModel. This makes
  every user action greppable and testable.
- **No business decisions in Composables.** A Composable may format a date
  and choose a colour; it may not decide whether a peer is trusted — the core
  already told it.
- **Constructor injection, by hand.** ViewModels take their dependencies as
  constructor parameters and a small `AppGraph` object wires them at startup.
  No Hilt, Dagger or Koin: the app has a dozen classes, and a DI framework
  would be the largest dependency in it.
- **Structured concurrency.** Everything runs in `viewModelScope` or a scope
  that is cancelled with its owner. `GlobalScope` and un-scoped `launch` are
  bugs. Socket I/O is one coroutine per connection with an explicit
  `cancel()` on lock.

## Talking to the Rust core

- `Config`, `Channel`, `Session` and `Settings` are uniffi **objects** — opaque
  handles. Never copy their contents into Kotlin data classes "for
  convenience"; call methods on them. Only `Received`, `Peer`, `Fingerprint`,
  `Gap`, `Event` are records (architecture §1).
- The wrapped storage key is unwrapped by the Keystore into a `ByteArray`,
  passed once to `openStore(path, keyBytes)`, and **filled with zeros
  immediately after**, in a `finally`. Same for the `.chatcfg` passphrase. A
  `String` cannot be zeroed; passphrase fields use `ByteArray`-backed input.
- The socket loop is a pure host for `Session`: read a frame → `onFrame(frame,
  now)` → for each `Event`, update state; write whatever `outgoing()` returns.
  No inspection of frame contents in Kotlin.
- `now` is always `System.currentTimeMillis()` passed **into** the core; the
  core never reads it.
- Do not retain anything the core returns beyond the current UI state: no
  caches, no `toString()`, no logging of `Received` (architecture: "promise
  not to retain").

## Types and style

- `val` by default; `var` only for state that is truly mutable, and then in a
  ViewModel or a `platform/` class, never in a Composable.
- Never `!!`. Use `?.`, `?:`, `requireNotNull(x) { "why" }` in the rare case a
  null is a programming error.
- `Result<T>` or a `sealed interface` for outcomes the caller must handle;
  exceptions only for programming errors. Map uniffi exceptions to the
  screen's `Error(kind)` state at the ViewModel boundary, once.
- `data class` for values, `value class` for ids (`@JvmInline value class
  PeerId(val raw: Long)`), `enum class` or `sealed interface` for closed sets.
- Names in full English words; Composables are nouns in PascalCase
  (`ChannelScreen`, `PeerRow`); state is `XxxUiState`; intents `XxxIntent`.
- One public class per file, file named after it. Composables that are only
  used by one screen live in that screen's file below the screen.
- Functions ≤ ~40 lines; Composables ≤ ~60 including the preview.

## Compose specifics

- Stateless Composables: state and lambdas in, nothing out. Hoist state to
  the ViewModel; `remember` only for purely visual, transient things (scroll
  position, animation).
- `@Preview` for every screen-level Composable with representative states,
  including `Locked` and `Error`. Previews are documentation.
- Strings in `res/values/strings.xml` (English is the source and default;
  translations for Spanish, French, Catalan and Italian, `docs/spec.md` §12), never
  hard-coded. Content descriptions on every icon; minimum 48 dp touch targets;
  test with TalkBack once per screen.
- Message lists use `LazyColumn` with stable `key = { it.serverId }`; never
  re-sort in the Composable — the core delivers order.
- Secrets never reach a Composable. The QR of a config is rendered from bytes
  the core returns and the screen sets `FLAG_SECURE`; the passphrase words are
  shown from a `ByteArray` and cleared on dispose.

## Platform layer

- Keystore: exactly the parameters in `docs/spec.md` §8, in one class
  `StorageKey` with `unwrap(): ByteArray` and nothing else. `BiometricPrompt`
  with `DEVICE_CREDENTIAL` is the app lock; there is no app PIN.
- Lifecycle: `onStop` and screen-off → `Session.close()`, zero the key, drop
  the store handle. Reconnect in `onStart` with the core's cursor. No
  foreground service, no WorkManager, no push (§8 "Background").
- Manifest: `allowBackup="false"`, `dataExtractionRules` excluding everything,
  no `exported` components, no `usesCleartextTraffic`, no custom URL scheme.
- Networking: OkHttp WebSocket with TLS 1.3 only, session resumption disabled,
  no `permessage-deflate`, `User-Agent: privatechat/1`, 70 000-byte frame
  limit, one connection per server host (§6 "Transport").

## Testing

- Unit tests: JUnit 5 + `kotlinx-coroutines-test` + Turbine for `Flow`. Test
  ViewModels by sending intents and asserting emitted `UiState`s; fake the
  core behind a small interface only where the uniffi object cannot be
  constructed in a test.
- Names mirror the Rust convention where a test covers a spec requirement:
  `s051_t02_r03_lock_closes_session_and_zeroes_key()`.
- Compose UI tests for the two flows that matter most: import a config and
  verify a peer. Not for every button.
- No test touches the network or the real Keystore; `platform/` classes have
  in-memory fakes.

## Tooling

- `ktlint` (official style) and `detekt` with the project config; both run in
  CI and must be clean. No `@Suppress` without a comment.
- Reproducible builds: fixed Gradle wrapper, locked dependency versions, no
  build-time network access beyond dependency resolution. F-Droid requires
  this (§8 "Code integrity").
- Debug builds only sign with the debug key; release signing happens in CI
  with the offline key.
