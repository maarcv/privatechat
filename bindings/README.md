# Bindings

Phase 4. How the Rust core reaches each client (`docs/spec.md` §9).

- `uniffi/` — Kotlin and Swift bindings for Android and iOS, generated from the core with
  uniffi proc macros (no UDL). Spec 040-uniffi.
- Desktop needs no bindings: the core is linked into the Tauri process and exposed as Tauri
  commands. Spec 041-desktop-bridge, code under `clients/desktop/`.

Exit criterion of the phase: Kotlin and Swift pass the same `specs/vectors/*.json` as Rust.
