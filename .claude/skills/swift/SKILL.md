---
name: swift
description: Swift and SwiftUI standard for the iOS client in `clients/ios/`. Use it whenever you create or edit a `.swift` file, a SwiftUI view, a view model, an Xcode project or SwiftPM manifest, an `Info.plist` or entitlements, or when reviewing iOS code — including small view changes. It assumes you have read the `architecture` skill: the iOS app is a thin shell over the Rust core (uniffi), with no protocol logic, no crypto and no persistent state of its own.
---

# Swift / iOS standard

The iOS app opens a socket, drives `Session`, renders what it says, and asks
the Secure Enclave for a key. Everything about messages, peers, counters and
TTLs is in Rust. If you are writing logic that would also make sense on
Android, it belongs in `core` (architecture §1).

## Language and platform

- Swift 5.10 with **strict concurrency checking complete** (ready for Swift 6):
  `async`/`await`, `actor`s, `Sendable` everywhere; no GCD, no completion
  handlers, no Combine for new code.
- SwiftUI, iOS 16+. No UIKit except the thin wrappers the platform forces
  (camera for QR, `UIPasteboard`, screen-capture notifications).
- SwiftPM for the app and the uniffi package. No CocoaPods, no Carthage.
- No analytics, crash-reporting or ads SDKs (`docs/spec.md` §8 "Telemetry").
- Warnings are errors (`SWIFT_TREAT_WARNINGS_AS_ERRORS = YES`).

## Architecture inside the app

```
Views/       SwiftUI views. Render state, send intents. No logic.
ViewModels/  One @Observable class per screen. Owns the screen's state.
Platform/    Secure Enclave, Keychain, LAContext, socket, files, pasteboard.
core (Rust)  via uniffi: Config, Channel, Session, Settings — opaque handles.
```

- **State is a value type**, one `enum ChannelState { loading, locked,
  ready(ChannelData), failed(ErrorKind) }` per screen, held by an
  `@Observable` view model. Views read it and call one `send(_ intent:)`.
- **Intents are an `enum`** (`.sendText(String)`, `.labelPeer(PeerId, String)`,
  `.lock`). One entry point per view model; every user action is greppable.
- **Views decide presentation, never trust.** A view may pick a colour for a
  retired peer; it may not decide a peer is retired — the core said so.
- **Dependencies by initialiser.** View models take protocols
  (`StorageKeyProviding`, `SocketOpening`) in `init`; an `AppGraph` wires the
  real implementations at launch. No DI framework, no singletons except the
  graph.
- **Structured concurrency.** Every task belongs to a view model or to the
  socket actor and is cancelled with it. `Task.detached` and stored `Task`s
  without cancellation are bugs. The socket is an `actor` with one long-lived
  task and an explicit `close()`.

## Talking to the Rust core

- `Config`, `Channel`, `Session`, `Settings` are uniffi **objects**: opaque
  handles. Do not mirror their contents in Swift structs; call methods on
  them. Only `Received`, `Peer`, `Fingerprint`, `Gap`, `Event` are records.
- The storage key comes out of the Secure Enclave unwrap as `[UInt8]`, goes
  into `openStore(path:key:)` once, and is overwritten with zeros in a
  `defer` — same for the `.chatcfg` passphrase. `String` cannot be zeroed;
  passphrase entry produces `[UInt8]`.
- The socket actor is a pure host for `Session`: receive a frame →
  `onFrame(frame, now:)` → apply `Event`s → send `outgoing()`. It never looks
  inside a frame.
- `now` is `Date.now` converted to milliseconds and **passed in**; the core
  never reads a clock.
- Nothing from the core is retained beyond current state: no caches, no
  `description`, no `print`/`os_log` of `Received`.

## Types and style

- `struct` and `enum` by default; `class` only for view models
  (`@Observable`) and for platform wrappers that own a resource. `final` on
  every class.
- Never force-unwrap (`!`), force-try or force-cast. Use `guard let`, `if
  let`, `try?` only when the failure is genuinely irrelevant, and
  `preconditionFailure("why")` only for programming errors.
- Errors are `enum`s conforming to `Error`, one per module, one case per
  condition the caller can act on. Map uniffi errors to the screen's
  `.failed(kind)` once, at the view model.
- Closed sets are `enum`s; ids are wrapper structs (`struct PeerId:
  Hashable, Sendable { let raw: UInt64 }`), never bare integers.
- Full English words; views are nouns (`ChannelScreen`, `PeerRow`); view
  models `XxxViewModel`; intents `XxxIntent`. One type per file, file named
  after it; private helper views live at the bottom of the screen file.
- Functions ≤ ~40 lines; a view `body` ≤ ~40 lines — extract subviews rather
  than nest.

## SwiftUI specifics

- Views take state and closures in; `@State` only for transient visual state.
  Business state lives in the view model.
- `#Preview` for every screen with representative states including `.locked`
  and `.failed`. Previews are documentation and catch layout bugs.
- Strings in `Localizable.xcstrings` (English default); never inline.
  Accessibility labels on every icon; Dynamic Type supported; VoiceOver
  checked once per screen.
- Lists of messages use stable ids (`serverId`); never re-sort in a view.
- Secrets never reach a view as `String`. The config QR is drawn from bytes;
  the passphrase words are rendered from `[UInt8]` and cleared `onDisappear`.
  Screens that show a QR or passphrase blur on `willResignActive` and observe
  `capturedDidChange`.

## Platform layer

- `StorageKey`: one type that owns the P-256 Secure Enclave key with exactly
  the `SecAccessControl` flags in `docs/spec.md` §8 (`.privateKeyUsage,
  .userPresence`), the Keychain item as
  `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, and `unwrap() async throws
  -> [UInt8]`. The app lock **is** the `LAContext` prompt; there is no app PIN.
- Lifecycle: `sceneDidEnterBackground`, `protectedDataWillBecomeUnavailable`
  and screen lock → close the socket, zero the key, drop the store. Reconnect
  on foreground with the core's cursor. No background modes, no push.
- Files: `isExcludedFromBackup = true` on the data directory. Keychain items
  `ThisDeviceOnly`.
- Networking: `URLSessionWebSocketTask` with TLS 1.3 minimum, session
  resumption off, `User-Agent: privatechat/1`, 70 000-byte frame limit, one
  connection per server host (§6 "Transport").
- Pasteboard: `UIPasteboard.general.setItems(_, options: [.localOnly: true,
  .expirationDate: …])`. Configs are never copied to the pasteboard.

## Testing

- Swift Testing (`@Test`, `#expect`) for unit tests; XCTest only for UI
  tests. Test view models by sending intents and asserting the state
  sequence; fake platform protocols in memory.
- Names follow the spec convention where applicable:
  `@Test func s052_t02_r03_lockClosesSessionAndZeroesKey()`.
- UI tests for two flows: import a config, verify a peer.
- No test touches the network, the Keychain or the Secure Enclave.

## Tooling

- SwiftLint (project config) and SwiftFormat run in CI and must be clean; no
  `// swiftlint:disable` without a reason comment.
- Reproducible builds: pinned Xcode version in CI, SwiftPM `Package.resolved`
  committed, no build phases that fetch from the network.
- Release signing and notarisation happen in CI with the offline certificate;
  development uses automatic signing.
