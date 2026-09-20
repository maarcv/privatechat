# Clients

Three thin UI layers over the same Rust core (`docs/spec.md` §9). None of them holds protocol
logic, cryptography or persistent state of its own: the core opens the channel, encrypts,
verifies, stores and decides; the client paints, captures input and moves bytes.

| Client | Directory | Stack | Spec | Phase |
| --- | --- | --- | --- | --- |
| Desktop (macOS, Windows, Linux) | `desktop/` | Tauri 2 + Svelte 5 + TypeScript; the core linked in as a Rust crate | 050-desktop-mvp | 5 |
| Android | `android/` | Kotlin + Jetpack Compose, minSdk 26; core via uniffi | 051-android-mvp | 5 |
| iOS | `ios/` | Swift 5.10 + SwiftUI, iOS 16+; core via uniffi | 052-ios-mvp | 5 |

There is no hosted web client in v1 (ADR 0017): served JavaScript would hold the channel key,
and whoever compromises the web origin reads the whole channel for every member.

No client work starts before phases 1 and 2 (core, session and storage) are closed
(`docs/spec.md` §10). Before writing code here, read `.claude/skills/architecture/SKILL.md` and
the skill of the language (`typescript-svelte`, `kotlin`, `swift`).
