#!/usr/bin/env sh
# Lint documental (spec 003). Amb DOC_LINT_BASE=<ref git> també comprova la capçalera de docs/spec.md.
set -eu
exec python3 "$(dirname "$0")/doc_lint.py" "$@"
