#!/usr/bin/env sh
# Every R* of an accepted spec has a T* (AGENTS 6, spec 001).
set -eu
exec python3 "$(dirname "$0")/check_requirements.py" "$@"
