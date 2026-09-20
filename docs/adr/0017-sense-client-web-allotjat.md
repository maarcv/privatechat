# ADR 0017 — Sense client web allotjat a la v1; client d'escriptori natiu

Data: 2026-09-20 · Estat: acceptada

## Context
La primera versió incloïa un client web (Svelte + wasm) servit pel servidor, amb un avís permanent de «menys garanties». La revisió B (troballa B9) va mostrar que l'avís informa el membre web però no la resta: el JS servit té `K_ch`, `sk_u` i el text en clar, i amb ADR 0001 i 0004 qui comprometi l'origen web (operador, hosting, CDN, certificat fraudulent, versió antiga vulnerable amb hashes correctes) llegeix **tot el canal per a tots els membres**, també els natius. SRI i CSP no protegeixen contra el propi origen. El membre més feble fixa les garanties del canal.

## Decisió
La v1 no té client web allotjat. El tercer client és una app d'escriptori Tauri 2 (macOS, Windows, Linux) amb UI Svelte + TypeScript que enllaça el nucli Rust directament: codi fixat i signat, keychain de l'SO, el mateix `store` xifrat que els mòbils, un build reproduïble més. Res del nucli es compila a wasm a la v1.

## Alternatives descartades
- Web allotjat amb avís permanent: no mitigable per a la resta de membres.
- Web allotjat des d'un origen i operador diferents del servidor de missatges, amb `platform` visible als membres via `presence`: reduïx el risc però no l'elimina; queda com a opció de v2 (`docs/spec.md` §12).
- Extensió de navegador amb codi fixat: viable i compatible amb la UI Svelte; es reserva per a la v2 perquè requereix compilar libsodium a wasm i validar-ne l'aleatorietat.

## Conseqüències
- L'stack perd wasm, IndexedDB i Argon2id al navegador: menys risc (§12 «libsodium a wasm mal compilat» desapareix) i menys tooling.
- Specs 041 i 050 passen de web a escriptori (`041-desktop-bridge`, `050-desktop-mvp`).
- La UI Svelte és reutilitzable per a una futura extensió de navegador.
- El client d'escriptori té les mateixes mesures de §8 adaptades (keychain, bloqueig, sense captures bloquejables).
