# 000 — Estructura del repositori

Estat: en revisió
Fase: 0
ADR relacionades: 0012, 0020, 0021, 0022
Depèn de: —
Bloqueja: 001, 002, 003, 010
Revisor humà: Marc Vilardebó · Acceptada el: —

## Context

Abans de cap línia de producte cal un monorepo on la spec sigui la font de veritat, els lints facin complir `AGENTS.md` mecànicament i cap secret ni document privat pugui acabar-hi per error. `docs/spec.md` §11 dona l'arbre; §10 la Definició de fet; AGENTS 2, 4, 10, 12 i 25 les regles que aquest layout ha de fer complir. La carpeta `inici/` (material de partida i documents privats de l'empresa) viu al costat del repo i no s'ha de commitejar mai.

## Requisits

- R1 El workspace Cargo amb els crates `core`, `store` i `server` MUST compilar buit amb `cargo build --workspace --all-targets` sense warnings.
- R2 `cargo test --workspace` MUST passar, amb els tests d'aquesta spec inclosos.
- R3 Els lints del workspace MUST denegar a `core`, `store` i `server`: `unwrap_used`, `expect_used`, `panic`, `unreachable`, `indexing_slicing`, `arithmetic_side_effects`, `cast_possible_truncation`, `cast_sign_loss`, `todo`, `unimplemented`, `dbg_macro`, `print_stdout`, `print_stderr`, `undocumented_unsafe_blocks`; `unsafe_code` a `deny` al workspace i `#![forbid(unsafe_code)]` a cada crate fins que existeixi `core/src/crypto/ffi.rs`; `overflow-checks = true` al perfil `release`.
- R4 L'única URL de servidor al codi MUST ser la constant `privatechat_core::DEFAULT_SERVER_URL`, amb esquema `wss://` i, fins que hi hagi domini, el TLD reservat `.invalid`.
- R5 `.gitignore` MUST excloure `/inici/`, `.DS_Store`, `/target`, `node_modules/`, `dist/`, `.env` i el codi generat (`bindings/**/generated/`); `git ls-files inici` MUST retornar zero fitxers.
- R6 L'arrel MUST contenir: `AGENTS.md`, `CLAUDE.md`, `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `LICENSE` (MIT), `CODEOWNERS`, `Cargo.toml`, `rust-toolchain.toml`, `rustfmt.toml`, `deny.toml`, `.editorconfig`, `.gitignore`, `docs/spec.md`, `docs/threat-model.md`, `docs/adr/README.md`, `docs/adr/TEMPLATE.md`, `specs/TEMPLATE.md`, `specs/README.md`, `specs/vectors/README.md` i les cinc skills a `.claude/skills/`.
- R7 `rust-toolchain.toml` MUST fixar el canal a una versió estable concreta (`1.98.1`) amb `rustfmt` i `clippy`; `edition = "2024"` i `rust-version` al workspace.
- R8 `deny.toml` MUST prohibir a tot el workspace els crates de la llista d'AGENTS 2 i els de compressió (AGENTS 24), permetent `rand`/`rand_core` només com a dependència transitiva de `proptest`; llicències permeses: MIT, Apache-2.0, BSD-2/3, ISC, Unicode-3.0, Zlib, MPL-2.0; registre només crates.io.

## Límits

- Cap. Aquesta spec no processa entrada externa.

## Interfície

```
/
├─ Cargo.toml                (workspace: members core, store, server; [workspace.lints]; [profile.release])
├─ core/   (lib privatechat_core)   store/  (lib privatechat_store)   server/ (bin privatechat-server)
├─ rust-toolchain.toml · rustfmt.toml · deny.toml · .editorconfig · .gitignore
├─ AGENTS.md · CLAUDE.md · README.md · CONTRIBUTING.md · SECURITY.md · LICENSE · CODEOWNERS
├─ .claude/skills/{architecture,rust,kotlin,swift,typescript-svelte}/SKILL.md
├─ .github/{workflows/ci.yml, PULL_REQUEST_TEMPLATE.md, dependabot.yml}
├─ docs/{spec.md, threat-model.md, adr/}    specs/{TEMPLATE.md, README.md, NNN-*.md, vectors/}
└─ scripts/{doc_lint.sh, doc_lint.py, check_requirements.sh, check_requirements.py}
```

```rust
/// Servidor d'intercanvi per defecte de la instal·lació (ADR 0022).
pub const DEFAULT_SERVER_URL: &str = "wss://server.invalid";
```

## Seguretat

- `inici/` fora del repo per `.gitignore` i comprovat a la CI (T05): conté documents privats.
- `server.invalid` no resol mai (RFC 2606): un build sense configurar no pot connectar enlloc per error.
- Els lints són el mecanisme que fa complir AGENTS 4 i 12; no s'hi afegeix cap `allow` sense comentari.

## Canvis d'API pública

- Nova: `privatechat_core::DEFAULT_SERVER_URL`.

## Casos de prova

- T01 (cobreix R1): `cargo build --workspace --all-targets` → exit 0 (pas de CI `s000_t01_r01_workspace_builds`).
- T02 (cobreix R2): `cargo test --workspace` → exit 0 (pas de CI `s000_t02_r02_workspace_tests_pass`).
- T03 (cobreix R3): `s000_t03_r03_workspace_lints_deny_unwrap_and_arithmetic` llegeix `Cargo.toml` i comprova cada lint i `overflow-checks`.
- T04 (cobreix R4): `s000_t04_r04_default_server_url_is_wss_placeholder`.
- T05 (cobreix R5): pas de CI `s000_t05_r05_inici_is_ignored` (`git check-ignore inici` i `git ls-files inici` buit).
- T06 (cobreix R6): pas de CI `s000_t06_r06_root_files_exist`.
- T07 (cobreix R7): `s000_t07_r07_toolchain_is_pinned` comprova `rust-toolchain.toml`.
- T08 (cobreix R8): `cargo deny check` verd (pas `s001_t03_r03_cargo_deny`) i `s000_t08_r08_deny_bans_crypto_crates` comprova la llista a `deny.toml`.

## Vectors

- Cap: no hi ha format ni derivació.

## Criteri d'acceptació

`cargo build --workspace --all-targets && cargo test --workspace && cargo clippy --all-targets -- -D warnings && cargo deny check` en verd, i el job `doc-lint` de la CI verd.

## Fora d'abast

- Cap codi de producte: `core`, `store` i `server` són esquelets amb documentació de mòdul.
- El valor definitiu de `DEFAULT_SERVER_URL` (decisió oberta de §12).
- `core/fuzz/` (spec 016) i `bindings/`, `clients/`, `deploy/` (fases 3–5).

## Preguntes obertes

- [ ] 000-R4: quan hi hagi domini, la constant canvia amb un commit `chore:`; cal ADR? Proposta: no, és configuració, no protocol.

## Historial

- 2026-09-20 esborrany · 2026-09-20 en revisió
