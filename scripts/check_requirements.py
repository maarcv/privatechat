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
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def tracked_text() -> str:
    files = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
    chunks = []
    for rel in files:
        if rel.startswith(("specs/", "docs/", ".claude/")) or rel == "AGENTS.md":
            continue
        p = ROOT / rel
        try:
            chunks.append(p.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, OSError):
            continue
    return "\n".join(chunks)


def main() -> int:
    corpus = tracked_text()
    missing: list[str] = []
    for spec in sorted((ROOT / "specs").glob("[0-9][0-9][0-9]-*.md")):
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
    if missing:
        print("check_requirements: FAIL")
        for line in missing:
            print(" -", line)
        return 1
    print("check_requirements: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
