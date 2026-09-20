## Spec

`NNN-nom` · Estat de la spec: en revisió / acceptada / implementada
Requisits coberts: R1, R2, …

## Definició de fet (`docs/spec.md` §10)

- [ ] Cada R\* té un T\* (`scripts/check_requirements.sh` verd)
- [ ] `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, `cargo deny check` verds
- [ ] `scripts/doc_lint.sh` verd
- [ ] Cap secret als logs; `Debug` redactat a tot tipus secret nou (afegit a `SECRET_TYPES`)
- [ ] Tot camí de rebuig té un test `entrada → Error::X · commits = 0`; spec amb estat → test amb `FailingStore`
- [ ] Dependències noves justificades aquí, una frase cada una: …
- [ ] Canvi de format, config, derivació o tag? → ADR nova: `docs/adr/NNNN`
- [ ] Cap ADR acceptada modificada fora de la línia d'estat (s002_t04_r04_accepted_adr_only_state_changes)
- [ ] `docs/spec.md` al dia (capçalera `Actualitzat`) i fila a §13 si canvia una decisió
- [ ] ≤ 400 línies de diff net; una sola spec
- [ ] He llegit les skills d'`architecture` i del llenguatge
