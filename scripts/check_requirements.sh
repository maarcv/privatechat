#!/usr/bin/env sh
# Cada R* d'una spec acceptada té un T* (AGENTS 6, spec 001).
set -eu
exec python3 "$(dirname "$0")/check_requirements.py" "$@"
