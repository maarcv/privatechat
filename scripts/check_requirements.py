#!/usr/bin/env python3
"""Every requirement R* of an implemented spec has a test T* (spec 001, AGENTS 6).

An `accepted` spec is not gated: its tests are written after acceptance, so the
gate would fail for the whole of the spec-to-code step of the flow.

For each `specs/NNN-*.md` with `Status: implemented`, every line
`- R<k>` in `## Requirements` must be covered by an identifier `sNNN_tTT_rKK_` (two
digits each), optionally prefixed (`check_s003_…`), somewhere in the tracked
tree: a Rust test name, a doc_lint check function, a CI step name or comment,
a Kotlin/Swift/TS test name. `specs/`, `docs/`, `.claude/` and `AGENTS.md` are
skipped: they describe tests and quote example test names, and an example must
not satisfy the check.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def tracked_text(root: Path) -> str:
    files = subprocess.run(["git", "ls-files"], cwd=root, capture_output=True, text=True, check=True).stdout.split()
    chunks = []
    for rel in files:
        if rel.startswith(("specs/", "docs/", ".claude/")) or rel == "AGENTS.md":
            continue
        p = root / rel
        try:
            chunks.append(p.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, OSError):
            continue
    return "\n".join(chunks)


def missing_tests(root: Path) -> list[str]:
    """Each requirement of an implemented spec under `root` with no test named after it."""
    corpus = tracked_text(root)
    missing: list[str] = []
    for spec in sorted((root / "specs").glob("[0-9][0-9][0-9]-*.md")):
        text = spec.read_text(encoding="utf-8")
        state = re.search(r"^Status: (.+)$", text, re.MULTILINE)
        if not state or state.group(1).strip() != "implemented":
            continue
        nnn = spec.stem[:3]
        start = text.find("## Requirements")
        end = text.find("\n## ", start + 3)
        section = text[start:end] if start >= 0 else ""
        for m in re.finditer(r"^- R(\d+)\b", section, re.MULTILINE):
            rr = f"{int(m.group(1)):02d}"
            if not re.search(rf"(?<![A-Za-z0-9])s{nnn}_t\d\d_r{rr}_", corpus):
                missing.append(f"{spec.name}: R{int(m.group(1))} has no test named s{nnn}_tTT_r{rr}_*")
    return missing


def check_s001_t07_r07_the_gate_fires() -> list[str]:
    """The gate on fixtures, each of which breaks one of its rules: a gate that stopped
    firing fails the script (spec 001 R7)."""
    spec = ("# 999\n\nStatus: {state}\nPhase: 9\n\n## Requirements\n\n- R1 One.\n"
            "- R2 Two.\n\n### Notes\n\n- R10 Ten, under a subheading of the section.\n\n"
            "## Limits\n\n- R3 is not a requirement here.\n")
    every = "s999_t01_r01_a s999_t02_r02_b s999_t10_r10_c"
    cases = [
        # (what the case shows, the spec's state, the tracked test file, gate fails?)
        ("an implemented spec with every test", "implemented", every, False),
        ("a requirement with no test", "implemented", "s999_t01_r01_a s999_t10_r10_c", True),
        ("a requirement under a ### subheading with no test", "implemented", "s999_t01_r01_a s999_t02_r02_b", True),
        ("a test of another requirement", "implemented", "s999_t01_r01_a s999_t02_r03_b s999_t10_r10_c", True),
        ("a test of R100 for R10", "implemented", "s999_t01_r01_a s999_t02_r02_b s999_t10_r100_c", True),
        ("a test of another spec", "implemented", "s999_t01_r01_a s998_t02_r02_b s999_t10_r10_c", True),
        ("a name glued to a longer word", "implemented", "s999_t01_r01_a xs999_t02_r02_b s999_t10_r10_c", True),
        ("an accepted spec, not gated", "accepted", "", False),
    ]
    errors = []
    for name, state, tests, should_fail in cases:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "specs").mkdir()
            (root / "specs" / "999-fixture.md").write_text(spec.format(state=state), encoding="utf-8")
            (root / "tests.rs").write_text(tests + "\n", encoding="utf-8")
            # A test named only in specs/ or docs/ is a description, never a test.
            (root / "docs").mkdir()
            (root / "docs" / "notes.md").write_text("s999_t02_r02_described\n", encoding="utf-8")
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "add", "-A"], cwd=root, check=True)
            if bool(missing_tests(root)) != should_fail:
                errors.append(f"the gate gets {name} wrong")
    return errors


def main() -> int:
    broken = check_s001_t07_r07_the_gate_fires()
    missing = broken + missing_tests(ROOT)
    if missing:
        print("check_requirements: FAIL")
        for line in missing:
            print(" -", line)
        return 1
    print("check_requirements: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
