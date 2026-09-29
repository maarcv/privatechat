#!/usr/bin/env python3
"""The fuzz targets of spec 016-fuzz-harness, read from the sources.

The seven targets of R2 exist and each calls the `fuzz_entry` function of its name (T02);
each is that one call on the fuzzer's bytes with the result ignored (T07); no target and no
`fuzz_entry` function names a clock, a random source or the file system (T10).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGETS_DIR = ROOT / "crates" / "core" / "fuzz" / "fuzz_targets"
FUZZ_ENTRY = ROOT / "crates" / "core" / "src" / "fuzz_entry.rs"
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
    errors = (check_s016_t02_r02_the_seven_targets_exist(targets)
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
