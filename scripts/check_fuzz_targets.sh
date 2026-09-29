#!/usr/bin/env sh
# The fuzz targets of spec 016: the seven exist, each is one call, none is impure.
set -eu
exec python3 "$(dirname "$0")/check_fuzz_targets.py" "$@"
