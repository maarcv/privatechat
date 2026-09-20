# ADR 0012 — Nucli criptogràfic i de protocol en Rust, compartit per tots els clients

Data: 2026-09-19 · Estat: acceptada

## Context
Hi ha tres clients (escriptori, Android, iOS) i un servidor. Tota la criptografia i el protocol han de ser idèntics a tots.

## Decisió
Un crate Rust `core` conté crypto (libsodium via `libsodium-sys-stable`), sobre binari de missatge (ADR 0015), payload CBOR (`ciborium`), derivació de claus, signatures, gestió de peers i la sessió sans-I/O del protocol (ADR 0020). L'emmagatzematge és un crate Rust separat, `store`, també compartit (ADR 0020, 0021). S'exposa a Kotlin i Swift amb `uniffi` (macros proc) i al client d'escriptori Tauri com a crate Rust enllaçat directament (ADR 0017). La UI no toca mai una clau; el nucli no toca mai la xarxa ni el rellotge.

## Alternatives descartades
- Reimplementar el protocol a Kotlin, Swift i TypeScript: tres implementacions a auditar i a mantenir sincronitzades; divergències quasi segures.
- Compilar el nucli a wasm per a un client web: descartat amb el client web allotjat (ADR 0017); es reconsidera per a una extensió de navegador a la v2.

## Conseqüències
- Una sola implementació auditable; vectors de prova compartits a `specs/vectors/` validats pels bindings.
- Cost inicial de tooling (uniffi, Tauri, compilar libsodium per a Android i iOS).
- Servidor també en Rust (`axum`) per compartir tipus i tests d'integració.
