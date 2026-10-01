#!/usr/bin/env bash
# Every system call of `store` lives in crates/store/src/fs.rs (spec 020-store-files R23).
# Fails when `std::fs`, `std::io::Write`, `OpenOptions`, `File` or `std::process`, as whole
# words on code lines with comments stripped, appear in another non-test source of `store`.
# With a directory argument it checks that tree instead; with none it first tests itself.
set -euo pipefail
cd "$(dirname "$0")/.."

WORDS='std::fs|std::io::Write|OpenOptions|File|std::process'
# A grouped import (`use std::{fs, io::Write}`) names them without the path.
GROUPED='std::[{]'

# The offending lines under `src`: every `.rs` but `fs.rs` and the test modules.
offenders() {
  local src="$1"
  find "$src" -name '*.rs' ! -name 'fs.rs' ! -name 'tests.rs' ! -path '*/tests/*' -print0 |
    sort -z |
    while IFS= read -r -d '' file; do
      sed -e 's#//.*$##' "$file" | grep -nE "(^|[^[:alnum:]_])($WORDS)($|[^[:alnum:]_])|$GROUPED" | sed "s#^#$file:#" || true
    done
}

# Spec 020, T23: the check fails on a call outside fs.rs and passes on the allowed places.
s020_t23_r23_io_in_one_module() {
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  mkdir -p "$tmp/src/tests"
  printf 'pub fn f() { let _ = std::fs::rename("a", "b"); }\n' > "$tmp/src/fs.rs"
  printf 'fn t() { std::fs::File::open("x"); }\n' > "$tmp/src/tests.rs"
  printf 'use std::fs::File;\n' > "$tmp/src/tests/crash.rs"
  printf '//! A `File` in a comment.\npub struct LockFile; // File\n' > "$tmp/src/lib.rs"
  if [ -n "$(offenders "$tmp/src")" ]; then
    echo "check_store_io: the self-test flags an allowed place"; return 1
  fi
  for line in 'pub fn g() { let _ = std::fs::rename("a", "b"); }' 'use std::io::Write;' \
              'let o = OpenOptions::new();' 'fn h(_: File) {}' 'fn e() { std::process::exit(1) }' \
              'use std::{fs, io::Write as W};'; do
    printf '%s\n' "$line" > "$tmp/src/other.rs"
    if [ -z "$(offenders "$tmp/src")" ]; then
      echo "check_store_io: the self-test accepts: $line"; return 1
    fi
  done
  # The whole script, not only its search, fails on such a tree.
  if "$0" "$tmp/src" > /dev/null; then
    echo "check_store_io: the script passes a tree with a call outside fs.rs"; return 1
  fi
}

if [ $# -eq 0 ]; then
  s020_t23_r23_io_in_one_module
  set -- crates/store/src
fi
found="$(offenders "$1")"
if [ -n "$found" ]; then
  echo "check_store_io: system calls outside fs.rs (R23):"
  printf '%s\n' "$found"
  exit 1
fi
echo "check_store_io: ok"
