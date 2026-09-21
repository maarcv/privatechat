# Contributing

## Before you start

1. Read [`docs/spec.md`](../docs/spec.md) §1, §9, §10 and §11 (what it promises, architecture, phases, tree).
2. Read [`AGENTS.md`](../AGENTS.md) in full; it applies to people and agents alike.
3. Read `docs/spec.md` §3, §4 and the feature spec in `specs/`.
4. Read the [`architecture`](../.claude/skills/architecture/SKILL.md) skill and your language skill.
5. Working with an AI assistant? Copy [`docs/assistant.example.md`](../docs/assistant.example.md) to `assistant.md` (git-ignored) and write your personal preferences there, such as the language you want to talk in. It never changes what goes into the repository.

## Language

English for everything that goes into the repository (AGENTS 11).

## Flow

Flow, review, PR size, commit prefixes and ADR rules: `AGENTS.md`. Nothing here overrides it.

## Running the CI locally

```sh
export RUSTFLAGS="-D warnings"
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo build --workspace --all-targets
cargo test --workspace
cargo deny --all-features check -D checksum-mismatch
scripts/doc_lint.sh
scripts/check_requirements.sh
```

All green before every commit.

## Security

Do not open public issues for vulnerabilities. See [`SECURITY.md`](SECURITY.md).
