## Spec

`NNN-name` · Spec status: accepted (code PR) · in review (spec-only PR)
Requirements covered: R1, R2, …

## Definition of done (`docs/spec.md` §10)

- [ ] Every R\* has a T\* (`scripts/check_requirements.sh` green)
- [ ] The local CI commands of `.github/CONTRIBUTING.md` green (fmt, clippy, build, test, deny, doc lint, requirements)
- [ ] Workspace lints (`[workspace.lints]` in `Cargo.toml`) at `deny` in `core`, `store` and `server`; `overflow-checks = true` in release
- [ ] No secret in logs; redacted `Debug` on every new secret type (added to `SECRET_TYPES`)
- [ ] Every rejection path has a test `input → Error::X · commits = 0` (commits other than the cursor); stateful spec → test with `FailingStore`
- [ ] New dependencies justified in the PR, one sentence each
- [ ] Format, config, derivation or tag change → new ADR in `docs/adr/`
- [ ] No accepted ADR modified outside its status line, except a stale-reference correction logged in `docs/audit-log.md`
- [ ] `docs/spec.md` up to date (`Updated` header) and a row in `docs/audit-log.md` if a decision changes
- [ ] ≤ 400 lines of net diff; a single spec; PR title `NNN: …`
- [ ] The `architecture` skill and the language skill followed
- [ ] Everything in English (AGENTS 11)

<!-- Item 8 is spec 002 T04 (`s002_t04_r04_accepted_adr_only_state_changes`): human review, no mechanical check. -->
