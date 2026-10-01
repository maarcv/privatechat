#!/usr/bin/env sh
# The fuzz targets of spec 016: the targets of R2 exist, each is one call, none is impure.
set -eu
exec python3 "$(dirname "$0")/check_fuzz_targets.py" "$@"
