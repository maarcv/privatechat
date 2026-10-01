#!/usr/bin/env bash
# Repository layout (spec 000). `ignored` checks R5, `files` checks R6; with no argument, both.
set -euo pipefail
cd "$(dirname "$0")/.."

s000_t05_r05_inici_is_ignored() {
  # One path at a time: with several, check-ignore succeeds when any one is ignored.
  for p in inici/x .DS_Store target/x node_modules/x dist/x .env bindings/a/generated/x .claude/worktrees/x; do
    git check-ignore -q --no-index "$p" || { echo "not ignored: $p"; exit 1; }
  done
  test "$(git ls-files inici | wc -l)" -eq 0 || { echo "inici/ is tracked"; exit 1; }
}

s000_t06_r06_root_files_exist() {
  for f in AGENTS.md CLAUDE.md README.md LICENSE .github/CONTRIBUTING.md .github/SECURITY.md .github/CODEOWNERS docs/assistant.example.md \
           Cargo.toml rust-toolchain.toml rustfmt.toml deny.toml .editorconfig .gitignore \
           docs/spec.md docs/threat-model.md docs/audit-log.md docs/adr/README.md docs/adr/TEMPLATE.md \
           specs/TEMPLATE.md specs/README.md specs/vectors/README.md \
           .claude/skills/architecture/SKILL.md .claude/skills/rust/SKILL.md \
           .claude/skills/kotlin/SKILL.md .claude/skills/swift/SKILL.md \
           .claude/skills/typescript-svelte/SKILL.md; do
    test -f "$f" || { echo "missing $f"; exit 1; }
  done
}

case "${1:-all}" in
  ignored) s000_t05_r05_inici_is_ignored ;;
  files) s000_t06_r06_root_files_exist ;;
  all) s000_t05_r05_inici_is_ignored; s000_t06_r06_root_files_exist ;;
  *) echo "usage: $0 [ignored|files]"; exit 2 ;;
esac
echo "check_layout: ok"
