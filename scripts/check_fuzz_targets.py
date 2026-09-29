#!/usr/bin/env python3
"""The fuzz targets of spec 016-fuzz-harness, read from the sources.

The seven targets of R2 exist and each calls the `fuzz_entry` function of its name (T02);
every `pub` parser of `core` that takes `&[u8]`, and every `pub` function of `fuzz_entry`, is
reached by a target or named with its reason in `fuzz_exclusions.txt` (T06, AGENTS 21); each
target is that one call on the fuzzer's bytes with the result ignored (T07); no target and no
`fuzz_entry` function names a clock, a random source or the file system (T10).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGETS_DIR = ROOT / "crates" / "core" / "fuzz" / "fuzz_targets"
CORE_SOURCES = ROOT / "crates" / "core" / "src"
FUZZ_ENTRY = CORE_SOURCES / "fuzz_entry.rs"
EXCLUSIONS = ROOT / "scripts" / "fuzz_exclusions.txt"
# R6: a `pub` parser, its signature matched across line breaks up to the body.
PARSER = re.compile(r"\bpub fn ((?:parse|decrypt|open)\w*)\(([^{;]*)", re.DOTALL)
ENTRY = re.compile(r"^pub fn (\w+)\(", re.MULTILINE)
# R2, in its order.
TARGETS = ("record_decode", "config_parse", "config_parse_qr", "payload_decode", "receive",
           "receive_signed", "verify_qr_parse")
# R10: what a target would name to read a clock, draw randomness or touch the file system.
IMPURE = re.compile(r"\b(SystemTime|Instant|std::time|std::fs|File|OpenOptions|random|rand|"
                    r"getrandom|std::env|std::net)\b")


def check_s016_t02_r02_the_seven_targets_exist(targets: dict[str, str]) -> list[str]:
    errors = [f"{name}: no fuzz_targets/{name}.rs" for name in TARGETS if name not in targets]
    errors += [f"{name}: not a target of R2" for name in targets if name not in TARGETS]
    errors += [f"{name}: does not call fuzz_entry::{name}" for name, source in targets.items()
               if f"fuzz_entry::{name}(data)" not in source]
    return errors


def parse_exclusions(text: str) -> tuple[set[str], list[str]]:
    """The names of the exclusion list, and an error for each line without a reason."""
    names, errors = set(), []
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        name, _, reason = line.partition("#")
        if not name.strip() or not reason.strip():
            errors.append(f"exclusion without a reason: {line.strip()}")
        names.add(name.strip())
    return names, errors


def unreached(sources: dict[str, str], entry: str, targets: dict[str, str],
              exclusions: str) -> list[str]:
    """R6: the parsers of `sources` and the entries of `entry` that no target reaches."""
    excluded, errors = parse_exclusions(exclusions)
    parsers = {name for source in sources.values() for name, signature in PARSER.findall(source)
               if "&[u8]" in signature}
    # A parser is reached through `fuzz_entry` or a target; an entry only by a target, since
    # its own definition names it.
    reach = {**{name: "\n".join([entry, *targets.values()]) for name in parsers},
             **{name: "\n".join(targets.values()) for name in ENTRY.findall(entry)}}
    return errors + [f"{name}: reached by no fuzz target and not excluded"
                     for name, text in sorted(reach.items())
                     if name not in excluded and not re.search(rf"\b{name}\(", text)]


def check_s016_t06_r06_every_parser_is_reached(sources: dict[str, str], entry: str,
                                               targets: dict[str, str],
                                               exclusions: str) -> list[str]:
    # The fixtures first: a new parser with no target, and a reason left out, must fail.
    fixture = {"new.rs": "/// A parser.\npub fn parse_new(\n    bytes: &[u8],\n) -> Result<(), Error> {"}
    named = "parse_new: reached by no fuzz target and not excluded"
    if named not in unreached({**sources, **fixture}, entry, targets, exclusions):
        return ["the check does not name a parser without a target"]
    no_reason = unreached(sources, entry, targets, exclusions + "\nparse_new\n")
    if "exclusion without a reason: parse_new" not in no_reason:
        return ["the check accepts an exclusion without a reason"]
    return unreached(sources, entry, targets, exclusions)


def check_s016_t07_r07_targets_are_small(targets: dict[str, str]) -> list[str]:
    shape = re.compile(r"\bfuzz_target!\(\|data: &\[u8\]\| \{\n    fuzz_entry::(\w+)\(data\);\n\}\);")
    errors = []
    for name, source in targets.items():
        if re.search(r"unwrap|expect\(|panic!|assert", source):
            errors.append(f"{name}: an unwrap, a panic or an assertion")
        calls = shape.findall(source)
        if calls != [name] or source.count("fuzz_entry::") != 1:
            errors.append(f"{name}: not one call of fuzz_entry::{name} with the result ignored")
    return errors


def check_s016_t10_r10_targets_are_pure(targets: dict[str, str], entry: str) -> list[str]:
    code = {**targets, "fuzz_entry.rs": entry}
    return [f"{name}: names {match.group(0)}" for name, source in code.items()
            for line in source.splitlines() if not line.lstrip().startswith("//")
            for match in [IMPURE.search(line)] if match]


def main() -> int:
    targets = {path.stem: path.read_text(encoding="utf-8")
               for path in sorted(TARGETS_DIR.glob("*.rs"))}
    entry = FUZZ_ENTRY.read_text(encoding="utf-8")
    # The non-test sources: every `tests.rs`, every module under a `tests/` directory and
    # `fuzz_entry.rs`, which only the targets call, are left out.
    sources = {str(path.relative_to(CORE_SOURCES)): path.read_text(encoding="utf-8")
               for path in sorted(CORE_SOURCES.rglob("*.rs"))
               if path.name != "tests.rs" and "tests" not in path.parts and path != FUZZ_ENTRY}
    exclusions = EXCLUSIONS.read_text(encoding="utf-8")
    errors = (check_s016_t02_r02_the_seven_targets_exist(targets)
              + check_s016_t06_r06_every_parser_is_reached(sources, entry, targets, exclusions)
              + check_s016_t07_r07_targets_are_small(targets)
              + check_s016_t10_r10_targets_are_pure(targets, entry))
    if errors:
        print("check_fuzz_targets: FAIL")
        for error in errors:
            print(" -", error)
        return 1
    print("check_fuzz_targets: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
