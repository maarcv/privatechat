## Spec

`NNN-name` · Spec status: in review / accepted / implemented
Requirements covered: R1, R2, …

## Definition of done (`docs/spec.md` §10)

- [ ] Every R\* has a T\* (`scripts/check_requirements.sh` green)
- [ ] `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, `cargo deny check` green
- [ ] `scripts/doc_lint.sh` green
- [ ] No secret in logs; redacted `Debug` on every new secret type (added to `SECRET_TYPES`)
- [ ] Every rejection path has a test `input → Error::X · commits = 0`; stateful spec → test with `FailingStore`
- [ ] New dependencies justified here, one sentence each: …
- [ ] Format, config, derivation or tag change? → new ADR: `docs/adr/NNNN`
- [ ] No accepted ADR modified outside its status line (s002_t04_r04_accepted_adr_only_state_changes)
- [ ] `docs/spec.md` up to date (`Updated` header) and a row in §13 if a decision changes
- [ ] ≤ 400 lines of net diff; a single spec
- [ ] I have read the `architecture` skill and the language skill
- [ ] Everything in English (AGENTS 11)
