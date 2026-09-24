---
name: swift
description: Swift and SwiftUI standard for the iOS client in `clients/ios/`. Use it whenever you create or edit a `.swift` file, a SwiftUI view, a view model, an Xcode project or SwiftPM manifest, an `Info.plist` or entitlements, or when reviewing iOS code — including small view changes. It assumes you have read the `architecture` skill, whose §7 "Client shape" holds everything the three clients share; this skill adds only the iOS mechanics.
---

# Swift / iOS standard

The shape of the app — layers, state and intents, how the core is driven, how
secrets are held, lifecycle, testing and tooling — is `architecture` §7. This
file is the iOS delta. Logic that would also make sense on Android belongs in
`core`.

## Language and platform

- Swift 5.10 with **strict concurrency checking complete** (ready for Swift 6):
  `async`/`await`, `actor`s, `Sendable` everywhere; no GCD, no completion
  handlers, no Combine for new code.
- SwiftUI, iOS 16+. No UIKit except the thin wrappers the platform forces
  (camera for QR, `UIPasteboard`, screen-capture notifications).
- SwiftPM for the app and the uniffi package. No CocoaPods, no Carthage.
- Warnings are errors (`SWIFT_TREAT_WARNINGS_AS_ERRORS = YES`).

## Layout

```
Views/       SwiftUI views
ViewModels/  one @Observable class per screen: state enum, send(_ intent:)
Platform/    Secure Enclave, Keychain, LAContext, socket, files, pasteboard
```

- State is a value type, one `enum ChannelState { loading, locked,
  ready(ChannelData), failed(ErrorKind) }` per screen; intents are an `enum`.
- View models take protocols (`StorageKeyProviding`, `SocketOpening`) in
  `init`; `AppGraph` wires the real ones at launch. No singletons except the
  graph.
- The socket is an `actor` with one long-lived task and an explicit `close()`.
  `Task.detached` and stored `Task`s without cancellation are bugs.

## Swift idioms that carry a project rule

- Never force-unwrap (`!`), force-try or force-cast: the client face of "never
  panic on external data". `preconditionFailure("why")` only for programming
  errors.
- `struct` and `enum` by default; `class` only for view models
  (`@Observable`) and platform wrappers that own a resource, always `final`.
- Ids are wrapper structs (`struct PeerId: Hashable, Sendable { let raw:
  UInt64 }`), never bare integers.
- Map uniffi errors to the screen's `.failed(kind)` at the view model, once.
- A view `body` ≤ ~40 lines: extract subviews rather than nest. `#Preview` for
  every screen with representative states including `.locked` and `.failed`.
- `@State` only for transient visual state. Lists keyed by `serverId`.
- Strings in `Localizable.xcstrings`; accessibility labels on every icon;
  Dynamic Type supported; VoiceOver once per screen.

## Platform layer

- `StorageKey`: one type that owns the P-256 Secure Enclave key with exactly
  the `SecAccessControl` flags in `docs/spec.md` §8 (`.privateKeyUsage,
  .userPresence`), the Keychain item as
  `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, and `unwrap() async throws
  -> [UInt8]`. The key is overwritten with zeros in a `defer` after the core
  call. The app lock **is** the `LAContext` prompt; there is no app PIN.
- Password entry produces `[UInt8]`; `secureTextEntry`; `autocorrectionType =
  .no` in the composer (§8 "Keyboard").
- Screens that show a QR or the password words blur on `willResignActive` and
  observe `capturedDidChange` (§8 "Screenshot blocking").
- Lifecycle: `sceneDidEnterBackground`, `protectedDataWillBecomeUnavailable`
  and screen lock → close the socket, zero the key, drop the store. Reconnect
  on foreground with the core's cursor. No background modes, no push.
- Files: `isExcludedFromBackup = true` on the data directory. Keychain items
  `ThisDeviceOnly`.
- Networking: `URLSessionWebSocketTask`. `now` is `Date.now` in milliseconds.
- Pasteboard: `UIPasteboard.general.setItems(_, options: [.localOnly: true,
  .expirationDate: …])`. Configs are never copied to the pasteboard.

## Testing

- Swift Testing (`@Test`, `#expect`) for unit tests; XCTest only for the two
  UI flows of `architecture` §7. Fake platform protocols in memory.
- Test names: `@Test func s052_t02_r03_lockClosesSessionAndZeroesKey()`.

## Tooling

- SwiftLint (project config) and SwiftFormat; no `// swiftlint:disable`
  without a reason comment.
- Reproducible builds: pinned Xcode version in CI, SwiftPM `Package.resolved`
  committed, no build phases that fetch from the network.
- Release signing and notarisation happen in CI with the offline certificate;
  development uses automatic signing.
