# AGENTS.md — Regles per a qualsevol agent que treballi en aquest repositori

Llegeix aquest fitxer complet abans de tocar res.

## Fonts de veritat i precedència

1. La spec `specs/NNN-*.md` acceptada per a la feature que estàs implementant.
2. `docs/spec.md` (especificació completa; canònica a `main`).
3. Les ADR de `docs/adr/` (context històric de cada decisió).

La conversa amb l'usuari **no** és font de veritat. Si trobes una contradicció entre dues fonts, o entre una font i la conversa, atura't i obre una entrada a `## Preguntes obertes` de la spec afectada. No decideixis pel teu compte.

El document viu de Claude enllaçat al README és una còpia de lectura que pot anar endarrerida; no s'hi edita res.

## Regles

1. Llegeix `docs/spec.md` §3 (ADR), §4 (model criptogràfic) i la spec de la feature abans d'escriure codi. Si la spec no existeix, escriu-la primer amb `specs/TEMPLATE.md` i demana revisió humana abans de continuar.
2. **Cap primitiva criptogràfica pròpia.** Al crate `core` (i a tot allò que toqui `K_ch`, `sk_u`, claus de missatge o el format de cable): només libsodium a través de `core/src/crypto`. Prohibides com a dependència de `core`, directa o de dev: `rand`, `rand_core`, `getrandom`, `sha2`, `sha3`, `blake2`, `md-5`, `aes*`, `chacha20*`, `ring`, `openssl`, `ed25519-dalek`, `x25519-dalek`, `curve25519-dalek`, `argon2`, `hkdf`, `hmac`, `sodiumoxide`. Ho comprova `deny.toml`. La prohibició s'aplica a `[dependencies]` de `core`; les `[dev-dependencies]` poden dur `proptest` (i per tant `rand`), mai un crate criptogràfic. El `Store` viu al crate `store`, fora de `core` perquè fa I/O; xifra només amb `core::crypto` i no porta cap dependència criptogràfica pròpia. El servidor pot usar TLS (`rustls`) però verifica signatures Ed25519 **exclusivament** a través de `core::crypto`; cap altre crate implementa res del protocol.
3. Cap canvi al format de cable, a la config del canal, als tags de domini ni a les derivacions de claus sense una ADR nova numerada a `docs/adr/` i aprovada per un humà. El job `adr-guard` de la CI ho fa complir.
4. A `core`, `store` i `server`, clippy amb `unwrap_used`, `expect_used`, `panic`, `unreachable`, `indexing_slicing`, `arithmetic_side_effects`, `cast_possible_truncation`, `cast_sign_loss`, `todo`, `unimplemented`, `dbg_macro`, `print_stdout`, `print_stderr` a `deny` per a tot el crate (els tests poden relaxar-ho amb `#[cfg(test)]`); `[profile.release] overflow-checks = true`. Tot enter que ve de fora usa `checked_*` o `saturating_*`. Tot codi que rep dades externes retorna `Result<_, Error>`.
5. Tot material de clau viu en l'únic tipus `Secret<const N: usize>` de `core/src/crypto` (`Zeroize` + `ZeroizeOnDrop`, sense `Clone`, sense `Default`, `Debug` manual = `[REDACTED]`, `PartialEq` via `sodium_memcmp`); cap `[u8; 32]` de clau fora d'aquest mòdul. Mai en `String`, mai en logs, mai en missatges d'error. Tot tipus secret nou s'afegeix a `SECRET_TYPES` i el test `s010_t02_debug_is_redacted` el cobreix (checklist de PR). Els buffers de libsodium s'esborren amb `sodium_memzero` dins `core/src/crypto`.
6. Cada requisit R* de la spec té almenys un test T* amb el nom `sNNN_tTT_rRR_<descripció>` (spec, test i requisit amb dos dígits): `fn s013_t03_r02_rejects_bad_signature()`. `scripts/check_requirements.sh` ho comprova a la CI.
7. Commits petits, un per requisit quan sigui possible. El missatge comença per `NNN:` i cita el requisit: `013: R4 nonce aleatori de 24 B`. Altres prefixos permesos: `docs:`, `ci:`, `chore:`, `adr:`.
8. No afegeixis dependències sense justificar-ho a la PR i sense que `cargo deny check` passi. Les de dev també.
9. Abans de marcar una feature com feta, comprova la Definició de fet de `docs/spec.md` §10 i la plantilla de PR.
10. `core` no fa I/O ni llegeix el rellotge: cap `std::net`, `std::fs`, `tokio`, `reqwest`, `SystemTime::now`. El temps entra per paràmetre. Ho comprova `cargo deny` (bans) i clippy `disallowed_methods`.
11. Idioma: identificadors, noms de tests, missatges d'error de codi i comentaris de codi en anglès; specs, ADR, `docs/`, missatges de commit i PR en català.
12. `unsafe`: `#![forbid(unsafe_code)]` a tots els crates excepte `core/src/crypto/ffi.rs`, únic punt de contacte amb `libsodium-sys-stable`. Allà, `#![deny(unsafe_op_in_unsafe_fn)]`, cada bloc porta `// SAFETY:` i clippy `undocumented_unsafe_blocks` a `deny`.
13. Cap `TODO`, `FIXME` ni `XXX` al codi mergejat. El que quedi pendent va a `## Preguntes obertes` de la spec, amb l'id `NNN-Rk`.
14. Una PR: una spec, ≤ 400 línies de diff net (excloent `specs/vectors/*.json` i codi generat), títol que comença per `NNN:`.
15. Si un test T* no es pot escriure abans d'implementar (per exemple, necessita el vector generat), s'escriu igualment amb `#[ignore = "pending: NNN-Tk"]` i s'activa a la mateixa PR. Cap PR mergeja tests ignorats.
16. Codi generat (uniffi, Tauri bindings) no es commiteja; es genera a la CI.
17. `cargo fmt` i `cargo clippy --all-targets -- -D warnings` nets abans de cada commit.
18. Els vectors de `specs/vectors/*.json` només es regeneren amb un canvi de `proto_version` i ADR. La CI falla si el diff toca vectors sense tocar `docs/adr/`.
19. Cap log amb contingut, noms, claus, `channel_id` ni `pk` complets; com a màxim el prefix de 4 bytes hex. El test `s010_t01_no_secrets_in_logs` ho comprova.
20. La UI no toca mai una clau ni toca mai els fitxers d'emmagatzematge. `Config`, `Channel` i `Session` s'exposen com a handles opacs (uniffi `Object`); només `Received`, `Peer`, `Fingerprint`, `Gap` i `Event` són `Record`. Les contrasenyes creuen la frontera FFI com a bytes (`ByteArray`, `[UInt8]`, `Uint8Array`) i es zeroïtzen a la banda UI després de la crida. Fora del nucli no es promet esborrat: es promet no retenir (cap cache, cap log, cap `toString`).
21. Tot `parse`, `decrypt` i `open_*` de `core` té un target a `core/fuzz` i un test de propietat de round-trip (`proptest`); la CI comprova que el nombre de targets és ≥ el nombre de funcions públiques que reben `&[u8]`.
22. Cap `==` sobre `[u8; N]` a `core`: tota comparació de mides fixes passa per `crypto::ct_eq` (`sodium_memcmp`). Sense excepcions, així no cal decidir on cal temps constant.
23. Tota escriptura a l'estat passa per `Store::commit(WriteBatch)`, un sol commit per operació lògica. Cap camí de rebuig fa cap commit excepte el del cursor. Tota spec amb estat té un test amb `FailingStore` que falla al commit *n* i comprova l'estat en reobrir.
24. El payload no es comprimeix mai. Cap crate de compressió al workspace.
25. Abans d'escriure codi en un llenguatge, llegeix `.claude/skills/architecture/SKILL.md` i després `.claude/skills/<llenguatge>/SKILL.md` (`rust`, `kotlin`, `swift`, `typescript-svelte`). Són l'estàndard de codi del projecte: capes, mides, noms, errors, tests i eines. Si un agent no és Claude, són documents normals; llegeix-los igualment.

## Flux per feature

spec escrita → revisió humana → tests T* en vermell → implementació → CI verda → revisió humana (+ ADR si cal) → merge.

La revisió humana abans d'implementar i abans de fer merge és obligatòria a `core/`, `store/` i `server/`. Als clients (`clients/`) n'hi ha prou amb la revisió abans del merge.

## Estructura i ordre de treball

L'arbre del repositori és a `docs/spec.md` §11; les fases, les specs de cada fase i els criteris de sortida a §10. No dupliquem la llista aquí per no tenir dues fonts. Principi fix: no es comença UI fins que les fases 1 i 2 estan tancades.
