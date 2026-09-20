# Contributing

Thanks for reading this before touching anything. The project has two rules that govern everything: **uncompromising and simple**. Every line of code has to earn its place.

## Before you start

1. Read [`AGENTS.md`](AGENTS.md) in full. It applies to people and to agents alike.
2. Read [`docs/spec.md`](docs/spec.md) §3 (decisions), §4 (cryptographic model) and the spec of the feature you want to touch in `specs/`.
3. Read [`.claude/skills/architecture/SKILL.md`](.claude/skills/architecture/SKILL.md) and the skill of your language. They are the coding standard.
4. Working with an AI assistant? Copy [`assistant.example.md`](assistant.example.md) to `assistant.md` (git-ignored) and write your personal preferences there, such as the language you want to talk in. It never changes what goes into the repository.

## Language

English, for absolutely everything: code, comments, docs, specs, ADRs, commit messages, pull requests and issues. This is an open project and English is its reference language.

## Flow

spec written → human review → tests red → implementation → CI green → human review (+ ADR if needed) → merge.

- If the spec does not exist, write it first with `specs/TEMPLATE.md` and open a PR with the spec only.
- Every requirement `R*` has a test `sNNN_tTT_rRR_*`. `scripts/check_requirements.sh` checks it.
- No change to the wire format, the config, the key derivations or the domain tags without a new ADR in `docs/adr/` (template in `docs/adr/TEMPLATE.md`).
- One PR = one spec, ≤ 400 lines of net diff, title `NNN: …`.

## Running the CI locally

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo deny check
scripts/doc_lint.sh
scripts/check_requirements.sh
```

All green before every commit. The commit message starts with `NNN:`, `docs:`, `ci:`, `chore:` or `adr:`.

## Security

Do not open public issues for vulnerabilities. See [`SECURITY.md`](SECURITY.md).
