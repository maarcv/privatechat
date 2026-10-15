#!/usr/bin/env bash
# The list `SOURCES` of crates/core/src/crypto/tests.rs names every tracked `.rs` file under
# crates/core/src, and nothing else (spec 010 T01: the test reads every source of `core`,
# and `core` cannot walk its own directory). With a directory argument it checks that tree
# (a git work tree holding `crypto/tests.rs`) instead; with none it first tests itself.
set -euo pipefail
self="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
cd "$(dirname "$0")/.."

# Each tuple of the list as `name path`: its name and the path of its `include_str!`,
# whether the tuple sits on one line or rustfmt breaks it.
pairs() {
  awk '/^const SOURCES/,/^];/' "$1/crypto/tests.rs" | tr '\n' ' ' |
    grep -oE '\( *"[^"]+", *include_str!\("[^"]+"\),? *\)' |
    sed -E 's/^\( *"([^"]+)", *include_str!\("([^"]+)"\).*$/\1 \2/'
}

# The names in the list.
listed() {
  pairs "$1" | cut -d' ' -f1 | sort
}

# The tuples whose `include_str!`, resolved from `crypto/`, reads another file than the
# name says: `../x.rs` reads `x.rs`, `x.rs` reads `crypto/x.rs`.
mismatched() {
  local name path
  pairs "$1" | while read -r name path; do
    case "$path" in
      ../*) [ "${path#../}" = "$name" ] || echo "mismatched: $name reads $path" ;;
      *) [ "crypto/$path" = "$name" ] || echo "mismatched: $name reads $path" ;;
    esac
  done
}

tracked() {
  git -C "$1" ls-files -- '*.rs' | sort
}

# One line per difference: `missing` names a tracked file the list lacks, `stale` a listed
# file that is not tracked, `mismatched` a tuple that reads another file than it names.
differences() {
  local src="$1" tmp
  tmp="$(mktemp -d)"
  listed "$src" > "$tmp/listed"
  tracked "$src" > "$tmp/tracked"
  comm -13 "$tmp/listed" "$tmp/tracked" | sed 's/^/missing: /'
  comm -23 "$tmp/listed" "$tmp/tracked" | sed 's/^/stale: /'
  mismatched "$src"
  rm -rf "$tmp"
}

# Spec 010, T01: the check passes on a complete list and fails on a missing or a stale entry,
# or on a name paired with another file, whether the tuple sits on one line or rustfmt
# breaks it.
s010_t01_r01_sources_list_complete() {
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  mkdir -p "$tmp/src/crypto" "$tmp/src/a"
  printf '//! A.\n' > "$tmp/src/lib.rs"
  printf '//! B.\n' > "$tmp/src/a/deep.rs"
  write_list() {
    { printf 'const SOURCES: [(&str, &str); 3] = [\n'
      printf '%s\n' "$@"
      printf '];\nconst OTHER: [&str; 1] = [\n    ("ghost.rs", ""),\n];\n'
    } > "$tmp/src/crypto/tests.rs"
  }
  local complete=('    ("crypto/tests.rs", include_str!("tests.rs")),' '    ("lib.rs", include_str!("../lib.rs")),'
                  '    (' '        "a/deep.rs",' '        include_str!("../a/deep.rs"),' '    ),')
  write_list "${complete[@]}"
  git -C "$tmp/src" init -q
  git -C "$tmp/src" add -A
  if [ -n "$(differences "$tmp/src")" ]; then
    echo "check_core_sources: the self-test flags a complete list"; return 1
  fi
  write_list "${complete[@]:0:2}"
  case "$(differences "$tmp/src")" in
    "missing: a/deep.rs") ;;
    *) echo "check_core_sources: the self-test misses a missing entry"; return 1 ;;
  esac
  write_list "${complete[@]}" '    ("gone.rs", include_str!("../gone.rs")),'
  case "$(differences "$tmp/src")" in
    "stale: gone.rs") ;;
    *) echo "check_core_sources: the self-test misses a stale entry"; return 1 ;;
  esac
  write_list '    ("crypto/tests.rs", include_str!("tests.rs")),' '    ("lib.rs", include_str!("../a/deep.rs")),' \
             '    (' '        "a/deep.rs",' '        include_str!("../a/deep.rs"),' '    ),'
  case "$(differences "$tmp/src")" in
    "mismatched: lib.rs reads ../a/deep.rs") ;;
    *) echo "check_core_sources: the self-test misses a mismatched pair"; return 1 ;;
  esac
  write_list '    ("crypto/tests.rs", include_str!("../tests.rs")),' "${complete[@]:1}"
  case "$(differences "$tmp/src")" in
    "mismatched: crypto/tests.rs reads ../tests.rs") ;;
    *) echo "check_core_sources: the self-test misses a mismatched pair in crypto/"; return 1 ;;
  esac
  # The whole script, not only its comparison, fails on such a tree.
  if "$self" "$tmp/src" > /dev/null; then
    echo "check_core_sources: the script passes a stale list"; return 1
  fi
}

if [ $# -eq 0 ]; then
  s010_t01_r01_sources_list_complete
  set -- crates/core/src
fi
found="$(differences "$1")"
if [ -n "$found" ]; then
  echo "check_core_sources: SOURCES of crypto/tests.rs differs from the tracked files (010 T01):"
  printf '%s\n' "$found"
  exit 1
fi
echo "check_core_sources: ok"
