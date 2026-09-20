# Desktop client (Tauri 2 + Svelte 5 + TypeScript)

Phase 5, spec 050-desktop-mvp; the bridge to the core is spec 041-desktop-bridge (phase 4).

- The Rust core is linked directly into the Tauri process as a crate: no wasm, no JavaScript
  ever sees a key. The web view only calls Tauri commands and renders `Record`s.
- Same encrypted `store` as the mobile clients; the storage key lives in the OS keychain.
- Device security measures of `docs/spec.md` §8 adapted to desktop (lock, clipboard,
  no screenshot blocking possible).
- UI strings: English source, plus Spanish, French, Catalan and Italian (`docs/spec.md` §12).

Standard: `.claude/skills/typescript-svelte/SKILL.md`.
