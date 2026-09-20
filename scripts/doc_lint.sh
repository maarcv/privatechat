#!/usr/bin/env sh
# Documentation lint (spec 003). With DOC_LINT_BASE=<git ref> it also checks the docs/spec.md header.
set -eu
exec python3 "$(dirname "$0")/doc_lint.py" "$@"
