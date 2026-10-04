#!/usr/bin/env python3
"""The fuzz targets of spec 016-fuzz-harness, read from the sources.

T02: the targets of R2 exist, and no other. T06: every `pub` parser of `core` that
takes `&[u8]`, and every `pub` entry of `fuzz_entry`, is reached by a target or named with
its reason in `fuzz_exclusions.txt`, and every exclusion names a function that exists
(AGENTS 21). T07: each target is the one-call template, and each entry only calls its
`_verdict`. T09: no workflow but `fuzz.yml` names a nightly. T10: no target and no entry
names a clock, a random source or the file system.

Every check runs first on fixtures that break its rule, so that a check which stopped
failing fails the script.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORE_SOURCES = "crates/core/src"
FUZZ_ENTRY = "crates/core/src/fuzz_entry.rs"
TARGETS_DIR = ROOT / "crates" / "core" / "fuzz" / "fuzz_targets"
EXCLUSIONS = ROOT / "scripts" / "fuzz_exclusions.txt"
WORKFLOWS = ROOT / ".github" / "workflows"
# R2, in its order.
TARGETS = ("record_decode", "config_parse", "config_parse_qr", "payload_decode", "receive",
           "receive_signed", "verify_qr_parse", "state_decode", "log_record_decode",
           "settings_decode", "channel_decrypt")
# R7 and the Interface: every target is this file, with its name.
TEMPLATE = """#![no_main]

use libfuzzer_sys::fuzz_target;
use privatechat_core::fuzz_entry;

fuzz_target!(|data: &[u8]| {{
    fuzz_entry::{name}(data);
}});
"""
# R6: a `pub` parser, with or without a lifetime or generics, its parameters matched across
# line breaks up to the closing parenthesis of the signature.
PARSER = re.compile(r"^( *)pub fn ((?:parse|decrypt|open)\w*)\s*(?:<[^>]*>)?\(([^)]*)\)",
                    re.MULTILINE)
TAKES_BYTES = re.compile(r"&\s*(?:'\w+\s+)?\[u8\]")
IMPL = re.compile(r"^impl(?:<[^>]*>)?\s+(\w+)", re.MULTILINE)
ANY_FN = re.compile(r"^( *)(?:pub(?:\([^)]*\))? )?fn (\w+)", re.MULTILINE)
ENTRY = re.compile(r"^pub fn (\w+)\(", re.MULTILINE)
# R10: what a target or an entry would name to read a clock, draw randomness or touch the
# file system or the process: `std` paths, grouped imports and the randomness of `core`.
IMPURE = re.compile(r"\b(SystemTime|Instant|std::(?:time|fs|env|net|io|process|thread)\b|"
                    r"use std::\{[^}]*\b(?:time|fs|env|net|io|process|thread)\b|File|"
                    r"OpenOptions|rand\w*|random\w*|getrandom|sign_keypair\b)")


def owner(source: str, at: int, indent: str) -> str | None:
    """The type of the `impl` block a function at `at` belongs to, or `None` when free."""
    if not indent:
        return None
    impls = [match.group(1) for match in IMPL.finditer(source, 0, at)]
    return impls[-1] if impls else None


def functions(sources: dict[str, str]) -> set[str]:
    """Every function of the sources, `T::name` for a method and `name` when free."""
    found = set()
    for source in sources.values():
        for match in ANY_FN.finditer(source):
            kind = owner(source, match.start(), match.group(1))
            found.add(f"{kind}::{match.group(2)}" if kind else match.group(2))
    return found


def parse_exclusions(text: str, sources: dict[str, str]) -> tuple[set[str], list[str]]:
    """The names of the exclusion list, an error for each line without a reason, and one for
    each name that is no function of `core`."""
    names, errors, known = set(), [], functions(sources)
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        name, _, reason = line.partition("#")
        name = name.strip()
        if not name or not reason.strip():
            errors.append(f"exclusion without a reason: {line.strip()}")
        elif name not in known:
            errors.append(f"exclusion of no function of core: {name}")
        names.add(name)
    return names, errors


def check_s016_t02_r02_the_targets_exist(targets: dict[str, str]) -> list[str]:
    errors = [f"{name}: no fuzz_targets/{name}.rs" for name in TARGETS if name not in targets]
    errors += [f"{name}: not a target of R2" for name in targets if name not in TARGETS]
    errors += [f"{name}: does not call fuzz_entry::{name}" for name, source in targets.items()
               if f"fuzz_entry::{name}(data)" not in source]
    return errors


def check_s016_t06_r06_every_parser_is_reached(sources: dict[str, str], entry: str,
                                               targets: dict[str, str],
                                               exclusions: str) -> list[str]:
    excluded, errors = parse_exclusions(exclusions, sources)
    reach_parser = "\n".join([entry, *targets.values()])
    reach_entry = "\n".join(targets.values())
    # Name → (where it must be called, how): a method as `T::name(`, a free function as the
    # whole word `name(`, unqualified or after a module path, an entry as `fuzz_entry::name(`
    # from a target.
    wanted = {}
    for source in sources.values():
        for match in PARSER.finditer(source):
            if TAKES_BYTES.search(match.group(3)):
                kind = owner(source, match.start(), match.group(1))
                name = f"{kind}::{match.group(2)}" if kind else match.group(2)
                # A free function may be called after a module path, never after a type.
                path = "" if kind else r"(?:[a-z_]\w*::)*"
                wanted[name] = (reach_parser, rf"(?<![\w:]){path}{name}\(")
    for name in ENTRY.findall(entry):
        wanted[f"fuzz_entry::{name}"] = (reach_entry, rf"\bfuzz_entry::{name}\(")
    return errors + [f"{name}: reached by no fuzz target and not excluded"
                     for name, (text, pattern) in sorted(wanted.items())
                     if name not in excluded and not re.search(pattern, text)]


def check_s016_t07_r07_targets_are_small(targets: dict[str, str], entry: str) -> list[str]:
    errors = [f"{name}: not the one-call template" for name, source in targets.items()
              if source != TEMPLATE.format(name=name)]
    for name in ENTRY.findall(entry):
        body = rf"^pub fn {name}\(data: &\[u8\]\) \{{\n    let _ = {name}_verdict\(data\);\n\}}$"
        if not re.search(body, entry, re.MULTILINE):
            errors.append(f"fuzz_entry::{name}: does more than drop {name}_verdict")
    return errors


def check_s016_t09_r09_only_the_fuzz_workflow_names_a_nightly(workflows: dict[str, str]
                                                              ) -> list[str]:
    return [f"{name}: names a nightly" for name, text in workflows.items()
            if name != "fuzz.yml" and "nightly" in text]


def check_s016_t10_r10_targets_are_pure(targets: dict[str, str], entry: str) -> list[str]:
    code = {**targets, "fuzz_entry.rs": entry}
    return [f"{name}: names {match.group(0)}" for name, source in code.items()
            for line in source.splitlines() if not line.lstrip().startswith("//")
            for match in [IMPURE.search(line.split("//")[0])] if match]


def self_test(sources: dict[str, str], entry: str, targets: dict[str, str],
              exclusions: str) -> list[str]:
    """Each check on a fixture that breaks its rule: a check that passes one is broken."""
    parser = "impl Box {{\n    /// A parser.\n    pub fn {name}<'a>(\n        bytes: &'a [u8],\n    ) {{"
    extra_entry = entry + "\n/// New.\npub fn new_entry(data: &[u8]) {\n    let _ = new_entry_verdict(data);\n}\n"
    broken_target = TEMPLATE.format(name="receive").replace(
        "    fuzz_entry::receive(data);\n", "    fuzz_entry::receive(data);\n    assert!(true);\n")
    reach = lambda extra, ex=exclusions, e=entry: check_s016_t06_r06_every_parser_is_reached(
        {**sources, "fixture.rs": extra}, e, targets, ex)
    # Each case, and a word its report must contain.
    fixtures = [
        ("a missing target", "no fuzz_targets/receive.rs", check_s016_t02_r02_the_targets_exist(
            {k: v for k, v in targets.items() if k != "receive"})),
        ("an extra target", "extra: not a target", check_s016_t02_r02_the_targets_exist(
            {**targets, "extra": TEMPLATE.format(name="extra")})),
        ("a parse parser without a target", "Box::parse_new", reach(parser.format(name="parse_new"))),
        ("a decrypt parser without a target", "Box::decrypt_new",
         reach(parser.format(name="decrypt_new"))),
        ("an open parser without a target", "Box::open_new", reach(parser.format(name="open_new"))),
        ("a free parser reached only as a method", "parse: reached",
         reach("pub fn parse(\n    b: &[u8],\n) {")),
        ("an entry without a target", "fuzz_entry::new_entry",
         check_s016_t06_r06_every_parser_is_reached(sources, extra_entry, targets, exclusions)),
        ("an exclusion without a reason", "without a reason: Config::parse",
         reach("", exclusions + "\nConfig::parse #   \n")),
        ("an exclusion of nothing", "no function of core: nothing_here",
         reach("", exclusions + "\nnothing_here # gone\n")),
        ("a target that asserts", "receive: not the one-call", check_s016_t07_r07_targets_are_small(
            {**targets, "receive": broken_target}, entry)),
        ("an entry that does more", "fuzz_entry::receive: does more",
         check_s016_t07_r07_targets_are_small(targets, entry.replace(
             "let _ = receive_verdict(data);", "let _ = receive_verdict(data);\n    let _ = 0;"))),
        ("a nightly in ci.yml", "ci.yml", check_s016_t09_r09_only_the_fuzz_workflow_names_a_nightly(
            {"ci.yml": "toolchain: nightly"})),
        ("std::fs in a target", "std::fs", check_s016_t10_r10_targets_are_pure(
            {"receive": "use std::fs;"}, "")),
        ("a grouped std import in the entries", "use std::{", check_s016_t10_r10_targets_are_pure(
            {}, "use std::{env, fs};")),
        ("the randomness of core", "random_bytes", check_s016_t10_r10_targets_are_pure(
            {}, "let x = crypto::random_bytes::<32>();")),
        *[(f"{word} in the entries", word, check_s016_t10_r10_targets_are_pure({}, line))
          for word, line in [("File", "let f = File::create(path);"),
                             ("Instant", "let t = Instant::now();"),
                             ("SystemTime", "let t = SystemTime::now();"),
                             ("OpenOptions", "let o = OpenOptions::new();"),
                             ("sign_keypair", "let k = crypto::sign_keypair();"),
                             ("std::io", "let o = std::io::stdout();"),
                             ("std::net", "let s = std::net::TcpStream::connect(a);"),
                             ("std::process", "std::process::exit(0);"),
                             ("std::thread", "std::thread::yield_now();"),
                             ("std::time", "let d = std::time::Duration::ZERO;"),
                             ("std::env", "let v = std::env::args();")]],
    ]
    errors = [f"the check accepts {case}" for case, word, found in fixtures
              if not any(word in error for error in found)]
    if any("parse_text" in error for error in reach("impl Box {\n    pub fn parse_text(text: &str) {")):
        errors.append("the check names a parser that takes no &[u8]")
    called_by_path = check_s016_t06_r06_every_parser_is_reached(
        {**sources, "fixture.rs": "pub fn parse_x(\n    b: &[u8],\n) {"},
        entry + "\nfn reach() { let _ = fingerprint::parse_x(data); }", targets, exclusions)
    if any("parse_x" in error for error in called_by_path):
        errors.append("the check misses a free parser called after its module path")
    return errors


def tracked(prefix: str) -> dict[str, str]:
    """The tracked `.rs` files under `prefix` that are not tests, by path."""
    listed = subprocess.run(["git", "ls-files", prefix], cwd=ROOT, capture_output=True,
                            text=True, check=True).stdout.split()
    return {path: (ROOT / path).read_text(encoding="utf-8") for path in listed
            if path.endswith(".rs") and "tests" not in Path(path).parts
            and not path.endswith("/tests.rs") and path != FUZZ_ENTRY}


def main() -> int:
    targets = {path.stem: path.read_text(encoding="utf-8")
               for path in sorted(TARGETS_DIR.glob("*.rs"))}
    entry = (ROOT / FUZZ_ENTRY).read_text(encoding="utf-8")
    sources = tracked(CORE_SOURCES)
    exclusions = EXCLUSIONS.read_text(encoding="utf-8")
    workflows = {path.name: path.read_text(encoding="utf-8")
                 for path in sorted(WORKFLOWS.glob("*.yml"))}
    errors = (self_test(sources, entry, targets, exclusions)
              + check_s016_t02_r02_the_targets_exist(targets)
              + check_s016_t06_r06_every_parser_is_reached(sources, entry, targets, exclusions)
              + check_s016_t07_r07_targets_are_small(targets, entry)
              + check_s016_t09_r09_only_the_fuzz_workflow_names_a_nightly(workflows)
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
