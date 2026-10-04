#!/usr/bin/env bash
# Every system call of `store` lives in crates/store/src/fs.rs (spec 020-store-files R23).
# Outside fs.rs and the test modules, a non-test source of `store` may name only the modules
# of `std` that make no system call, listed below; any other `std::` path, or a grouped
# `std::{...}` import, on a code line with comments stripped, fails. With a directory
# argument it checks that tree instead; with none it first tests itself.
set -euo pipefail
self="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
cd "$(dirname "$0")/.."

ALLOWED=" collections path sync fmt mem cmp ops iter convert num borrow array slice str string vec boxed hash marker option result "

# The offending lines under `src`: every `.rs` but `fs.rs` and the test modules.
offenders() {
  local src="$1"
  find "$src" -name '*.rs' ! -name 'fs.rs' ! -name 'tests.rs' ! -path '*/tests/*' -print0 |
    sort -z |
    while IFS= read -r -d '' file; do
      sed -e 's#//.*$##' "$file" | { grep -noE 'std::([a-z_]+|[{])' || true; } |
        while IFS=: read -r line path; do
          case "$ALLOWED" in
            *" ${path#std::} "*) ;;
            *) echo "$file:$line: $path" ;;
          esac
        done
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
  printf '//! `std::fs` in a comment.\nuse std::sync::Arc;\nuse std::collections::HashSet; // std::fs\n' > "$tmp/src/lib.rs"
  if [ -n "$(offenders "$tmp/src")" ]; then
    echo "check_store_io: the self-test flags an allowed place"; return 1
  fi
  for line in 'pub fn g() { let _ = std::fs::rename("a", "b"); }' 'use std::io::Write;' 'use std::io;' \
              'fn e() { std::process::exit(1) }' 'let _ = std::env::var("x");' 'use std::os::unix::fs::symlink;' \
              'use std::{fs, io::Write as W};' 'use std::io::{stdout, Write};' 'use std::io::prelude::*;'; do
    printf '%s\n' "$line" > "$tmp/src/other.rs"
    if [ -z "$(offenders "$tmp/src")" ]; then
      echo "check_store_io: the self-test accepts: $line"; return 1
    fi
  done
  # The whole script, not only its search, fails on such a tree and on
  # one with no source, each with its own message.
  local out
  mkdir "$tmp/empty"
  for case in "$tmp/src:outside fs.rs" "$tmp/empty:no Rust source"; do
    if out="$("$self" "${case%%:*}")"; then
      echo "check_store_io: the script passes ${case%%:*}"; return 1
    fi
    case "$out" in
      *"${case#*:}"*) ;;
      *) echo "check_store_io: the script fails ${case%%:*} without '${case#*:}'"; return 1 ;;
    esac
  done
}

if [ $# -eq 0 ]; then
  s020_t23_r23_io_in_one_module
  set -- crates/store/src
fi
# A tree with no source is a wrong path, not a clean crate.
if [ -z "$(find "$1" -name '*.rs' -print)" ]; then
  echo "check_store_io: no Rust source under $1"
  exit 1
fi
found="$(offenders "$1")"
if [ -n "$found" ]; then
  echo "check_store_io: system calls outside fs.rs (R23):"
  printf '%s\n' "$found"
  exit 1
fi
echo "check_store_io: ok"
