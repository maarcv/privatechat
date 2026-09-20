#!/usr/bin/env python3
"""Documentation lint for privatechat (spec 003).

Checks that the documentation is internally consistent, so an agent reading
one file cannot be misled by another. Pure standard library; runs in CI and
locally via `scripts/doc_lint.sh`. Each check is a function named after the
spec requirement it covers (`check_s003_tTT_rRR_*`) so
`scripts/check_requirements.sh` can find it.

Exit code 0 when everything passes, 1 otherwise; every failure is printed.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "docs" / "spec.md"
THREAT_MODEL = ROOT / "docs" / "threat-model.md"
ADR_DIR = ROOT / "docs" / "adr"
ADR_INDEX = ADR_DIR / "README.md"
SPECS_DIR = ROOT / "specs"
SPECS_INDEX = SPECS_DIR / "README.md"
AGENTS = ROOT / "AGENTS.md"

ADR_STATES = {"proposed", "accepted", "deprecated"}  # plus "superseded by NNNN"
ADR_SECTIONS = ["## Context", "## Decision", "## Alternatives considered", "## Consequences"]
SPEC_STATES = {"draft", "in review", "accepted", "implemented"}

failures: list[str] = []


def fail(msg: str) -> None:
    failures.append(msg)


def table_after(text: str, heading: str) -> list[str]:
    """Return the first markdown table's rows following `heading`."""
    start = text.find(heading)
    if start < 0:
        fail(f"heading not found: {heading!r}")
        return []
    rows: list[str] = []
    for line in text[start:].splitlines()[1:]:
        if line.startswith("|"):
            rows.append(line)
        elif rows:
            break
    return rows


def cells(row: str) -> list[str]:
    return [c.strip() for c in row.strip().strip("|").split("|")]


def spec_body(text: str) -> str:
    """The spec without §13 (audit log), which legitimately cites old names."""
    cut = text.find("## 13. Audit log")
    return text if cut < 0 else text[:cut]


# --- checks -----------------------------------------------------------------


def check_s003_t01_r01_threat_table_matches_spec(spec: str, tm: str) -> None:
    a = table_after(spec, "## 2. Threat model")
    b = table_after(tm, "## Adversaries and mitigations")
    if a != b:
        fail("docs/threat-model.md table differs from docs/spec.md §2")
        for x, y in zip(a, b):
            if x != y:
                fail(f"  spec: {x[:100]}\n  tm  : {y[:100]}")
        if len(a) != len(b):
            fail(f"  row count: spec={len(a)} threat-model={len(b)}")


def adr_files() -> dict[str, tuple[str, str, Path]]:
    found: dict[str, tuple[str, str, Path]] = {}
    for f in sorted(ADR_DIR.glob("[0-9][0-9][0-9][0-9]-*.md")):
        lines = f.read_text(encoding="utf-8").splitlines()
        m = re.match(r"# ADR (\d{4}) — (.+)", lines[0] if lines else "")
        if not m:
            fail(f"{f.name}: first line must be '# ADR NNNN — Title'")
            continue
        state_m = re.search(r"Status: ([^·]+)", lines[2] if len(lines) > 2 else "")
        if not state_m:
            fail(f"{f.name}: line 3 must contain 'Status: …'")
            continue
        state = state_m.group(1).strip()
        headings = [l for l in lines if l.startswith("## ")]
        if headings != ADR_SECTIONS:
            fail(f"{f.name}: sections must be exactly {ADR_SECTIONS}, got {headings}")
        found[m.group(1)] = (m.group(2).strip(), state, f)
    return found


def check_s002_t01_r01_adr_files_follow_template() -> dict[str, tuple[str, str, Path]]:
    files = adr_files()
    numbers = sorted(int(n) for n in files)
    if numbers != list(range(1, len(numbers) + 1)):
        fail(f"ADR numbering has gaps or duplicates: {numbers}")
    return files


def check_s002_t03_r03_adr_states_are_in_vocabulary(files: dict[str, tuple[str, str, Path]]) -> None:
    for n, (_, state, f) in files.items():
        if state not in ADR_STATES and not re.fullmatch(r"superseded by \d{4}", state):
            fail(f"{f.name}: invalid state {state!r}")


def check_s002_t02_r02_adr_index_matches_files_and_spec(spec: str, files: dict[str, tuple[str, str, Path]]) -> None:
    index: dict[str, tuple[str, str]] = {}
    for row in table_after(ADR_INDEX.read_text(encoding="utf-8"), "## Index"):
        c = cells(row)
        if len(c) >= 4 and re.fullmatch(r"\d{4}", c[0]):
            index[c[0]] = (c[1], c[3])
    s3: dict[str, tuple[str, str]] = {}
    for row in table_after(spec, "## 3. Design decisions"):
        c = cells(row)
        if len(c) >= 3 and re.fullmatch(r"\d{4}", c[0]):
            s3[c[0]] = (c[1], c[2])
    for n in sorted(set(files) | set(index) | set(s3)):
        f = files.get(n)
        entry = (f[0], f[1]) if f else None
        if not (entry == index.get(n) == s3.get(n)):
            fail(f"ADR {n} differs: file={entry} index={index.get(n)} spec§3={s3.get(n)}")


def check_s003_t03_r03_spec_refs_exist_in_plan(spec: str) -> None:
    plan = " ".join(table_after(spec, "## 10. SDD execution plan"))
    listed = set(re.findall(r"\b(\d{3}-[a-z][a-z0-9-]*)", plan))
    sources = [spec_body(spec), AGENTS.read_text(encoding="utf-8")]
    for extra in ("README.md", ".github/CONTRIBUTING.md"):
        p = ROOT / extra
        if p.exists():
            sources.append(p.read_text(encoding="utf-8"))
    for f in SPECS_DIR.glob("[0-9][0-9][0-9]-*.md"):
        sources.append(f.read_text(encoding="utf-8"))
    referenced = set()
    for text in sources:
        referenced |= set(re.findall(r"\b(\d{3}-[a-z][a-z0-9-]*)", text))
    for ref in sorted(referenced - listed):
        fail(f"spec id {ref!r} is referenced but not listed in docs/spec.md §10")
    for f in SPECS_DIR.glob("[0-9][0-9][0-9]-*.md"):
        if f.stem not in listed:
            fail(f"specs/{f.name} is not listed in docs/spec.md §10")


def check_s003_t04_r04_agents_has_no_spec_ranges() -> None:
    text = AGENTS.read_text(encoding="utf-8")
    if re.search(r"\b0\d\d[–-]0\d\d\b", text):
        fail("AGENTS.md contains a spec range (NNN–NNN); reference docs/spec.md §10 instead")


def check_s003_t05_r05_no_examples_in_requirements() -> None:
    for f in SPECS_DIR.glob("[0-9][0-9][0-9]-*.md"):
        text = f.read_text(encoding="utf-8")
        start = text.find("## Requirements")
        end = text.find("## ", start + 3) if start >= 0 else -1
        section = text[start:end] if start >= 0 else ""
        for i, line in enumerate(section.splitlines()):
            if re.search(r"\bfor example\b|\be\.g\.|\bsuch as\b", line, re.IGNORECASE):
                fail(f"specs/{f.name} Requirements: 'for example' is not a fixed value ({line.strip()[:80]})")


def check_s003_t06_r06_spec_header_date_changes_with_content() -> None:
    base = os.environ.get("DOC_LINT_BASE")
    if not base:
        return
    try:
        changed = subprocess.run(
            ["git", "diff", "--name-only", base, "--", "docs/spec.md"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout.strip()
        if not changed:
            return
        old = subprocess.run(
            ["git", "show", f"{base}:docs/spec.md"], cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout
    except subprocess.CalledProcessError:
        return  # no base available (first commit): nothing to compare
    header = re.compile(r"^Version: .*Updated: (\d{4}-\d{2}-\d{2})", re.MULTILINE)
    old_m, new_m = header.search(old), header.search(SPEC.read_text(encoding="utf-8"))
    if not new_m:
        fail("docs/spec.md header 'Version: … · Updated: YYYY-MM-DD' missing")
    elif old_m and old_m.group(0) == new_m.group(0):
        fail("docs/spec.md changed but its 'Version · Updated' header did not")


def check_s003_t07_r07_specs_index_matches_files() -> None:
    if not SPECS_INDEX.exists():
        fail("specs/README.md (index) is missing")
        return
    index: dict[str, tuple[str, str]] = {}
    for row in table_after(SPECS_INDEX.read_text(encoding="utf-8"), "## Index"):
        c = cells(row)
        if len(c) >= 4 and re.fullmatch(r"\d{3}", c[0]):
            index[c[0]] = (c[1], c[3])
    files: dict[str, tuple[str, str]] = {}
    for f in SPECS_DIR.glob("[0-9][0-9][0-9]-*.md"):
        text = f.read_text(encoding="utf-8")
        state_m = re.search(r"^Status: (.+)$", text, re.MULTILINE)
        state = state_m.group(1).strip() if state_m else "?"
        if state not in SPEC_STATES:
            fail(f"specs/{f.name}: invalid state {state!r} (must be one of {sorted(SPEC_STATES)})")
        files[f.stem[:3]] = (f.stem, state)
    for n in sorted(set(index) | set(files)):
        if index.get(n) != files.get(n):
            fail(f"specs index vs file for {n}: index={index.get(n)} file={files.get(n)}")


def main() -> int:
    spec = SPEC.read_text(encoding="utf-8")
    tm = THREAT_MODEL.read_text(encoding="utf-8")
    check_s003_t01_r01_threat_table_matches_spec(spec, tm)
    # check_s003_t02_r02_adr_consistency: the three s002 checks below, in order.
    adrs = check_s002_t01_r01_adr_files_follow_template()
    check_s002_t03_r03_adr_states_are_in_vocabulary(adrs)
    check_s002_t02_r02_adr_index_matches_files_and_spec(spec, adrs)
    check_s003_t03_r03_spec_refs_exist_in_plan(spec)
    check_s003_t04_r04_agents_has_no_spec_ranges()
    check_s003_t05_r05_no_examples_in_requirements()
    check_s003_t06_r06_spec_header_date_changes_with_content()
    check_s003_t07_r07_specs_index_matches_files()
    if failures:
        print("doc_lint: FAIL")
        for f in failures:
            print(" -", f)
        return 1
    print("doc_lint: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
