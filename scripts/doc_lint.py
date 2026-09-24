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
from datetime import date
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
ADR_LINE3 = re.compile(r"Date: \d{4}-\d{2}-\d{2} · Status: ([^·]+?)( · Supersedes: \d{4})?")
SPEC_STATES = {"draft", "in review", "accepted", "implemented"}
# A spec id in prose; a thousands-separated number ("70 000-byte") is not one.
SPEC_ID = re.compile(r"(?<!\d )\b(\d{3}-[a-z][a-z0-9-]*)")

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


def tracked_markdown() -> list[str]:
    """Every tracked `*.md`, as paths relative to the repository root."""
    out = subprocess.run(["git", "ls-files", "*.md"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    return out.split()


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
    for f in sorted(ADR_DIR.glob("[0-9][0-9][0-9][0-9]-[a-z0-9-]*.md")):
        lines = f.read_text(encoding="utf-8").splitlines()
        m = re.match(r"# ADR (\d{4}) — (.+)", lines[0] if lines else "")
        if not m:
            fail(f"{f.name}: first line must be '# ADR NNNN — Title'")
            continue
        line3 = ADR_LINE3.fullmatch(lines[2] if len(lines) > 2 else "")
        if not line3:
            fail(f"{f.name}: line 3 must be 'Date: YYYY-MM-DD · Status: <state>[ · Supersedes: NNNN]'")
            continue
        state = line3.group(1).strip()
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
    listed = set(SPEC_ID.findall(plan))
    # Every tracked Markdown file except the ADRs and the audit log, which cite old names as history.
    sources = [spec]
    for rel in tracked_markdown():
        if rel.startswith("docs/adr/") or rel in {"docs/audit-log.md", "docs/spec.md"}:
            continue
        sources.append((ROOT / rel).read_text(encoding="utf-8"))
    referenced = set()
    for text in sources:
        referenced |= set(SPEC_ID.findall(text))
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
    """R6: when docs/spec.md differs from the base, its `Updated` date is the date of its latest change.

    The date of the latest change is today when the file has uncommitted changes,
    otherwise the author date of the newest commit in base..HEAD that touches it.
    Comparing dates, not header strings, lets several changes land on one day.
    """
    base = os.environ.get("DOC_LINT_BASE")
    if not base:
        return

    def git(*args: str) -> str:
        return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()

    try:
        if not git("diff", "--name-only", base, "--", "docs/spec.md"):
            return
        if git("status", "--porcelain", "--", "docs/spec.md"):
            changed_on = date.today().isoformat()
        else:
            changed_on = git("log", "-1", "--format=%as", f"{base}..HEAD", "--", "docs/spec.md") or date.today().isoformat()
    except subprocess.CalledProcessError:
        return  # no base available (first commit): nothing to compare
    header = re.compile(r"^Version: .*Updated: (\d{4}-\d{2}-\d{2})", re.MULTILINE)
    m = header.search(SPEC.read_text(encoding="utf-8"))
    if not m:
        fail("docs/spec.md header 'Version: … · Updated: YYYY-MM-DD' missing")
    elif m.group(1) != changed_on:
        fail(f"docs/spec.md changed on {changed_on} but its header says 'Updated: {m.group(1)}'")


def check_s003_t07_r07_specs_index_matches_files() -> None:
    if not SPECS_INDEX.exists():
        fail("specs/README.md (index) is missing")
        return
    index: dict[str, tuple[str, str, str]] = {}
    for row in table_after(SPECS_INDEX.read_text(encoding="utf-8"), "## Index"):
        c = cells(row)
        if len(c) >= 4 and re.fullmatch(r"\d{3}", c[0]):
            index[c[0]] = (c[1], c[2], c[3])
    files: dict[str, tuple[str, str, str]] = {}
    for f in SPECS_DIR.glob("[0-9][0-9][0-9]-*.md"):
        text = f.read_text(encoding="utf-8")
        state_m = re.search(r"^Status: (.+)$", text, re.MULTILINE)
        state = state_m.group(1).strip() if state_m else "?"
        if state not in SPEC_STATES:
            fail(f"specs/{f.name}: invalid state {state!r} (must be one of {sorted(SPEC_STATES)})")
        phase_m = re.search(r"^Phase: (\d+)$", text, re.MULTILINE)
        if not phase_m:
            fail(f"specs/{f.name}: missing 'Phase: N' line")
        files[f.stem[:3]] = (f.stem, phase_m.group(1) if phase_m else "?", state)
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
