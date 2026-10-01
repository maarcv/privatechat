#!/usr/bin/env python3
"""Self-test of the documentation lint (spec 003 R8).

Copies the tracked Markdown and `doc_lint.py` into a temporary git repository,
checks that the lint passes there, then breaks one rule at a time and checks
that the lint fails each time with that rule's message: a rule that stopped
firing fails this script, even when another rule fails in its place.
Standard library only; runs in CI after the lint itself.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parent.parent


def git(cwd: Path, *args: str, when: str = "2026-01-01T12:00:00", committed: str | None = None) -> str:
    env = dict(os.environ, GIT_AUTHOR_DATE=when, GIT_COMMITTER_DATE=committed or when)
    return subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", *args], cwd=cwd,
                          capture_output=True, text=True, check=True, env=env).stdout.strip()


def copy_tree(to: Path) -> None:
    for rel in git(ROOT, "ls-files", "*.md").split():
        (to / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / rel, to / rel)
    (to / "scripts").mkdir(exist_ok=True)
    shutil.copy2(ROOT / "scripts" / "doc_lint.py", to / "scripts" / "doc_lint.py")
    git(to, "init", "-q")
    git(to, "add", "-A")
    git(to, "commit", "-qm", "base")


def lint(cwd: Path, base: str | None = None) -> tuple[int, str]:
    env = {k: v for k, v in os.environ.items() if k != "DOC_LINT_BASE"}
    if base:
        env["DOC_LINT_BASE"] = base
    run = subprocess.run([sys.executable, "scripts/doc_lint.py"], cwd=cwd, capture_output=True,
                         text=True, env=env)
    return run.returncode, run.stdout


def replace(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"doc_lint_selftest: {path.name} lacks {old[:40]!r}; update the fixture")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def first_adr(root: Path) -> Path:
    return sorted((root / "docs" / "adr").glob("0001-*.md"))[0]


def first_spec(root: Path) -> Path:
    return sorted((root / "specs").glob("0[1-9][0-9]-*.md"))[0]


def threat_cell(root: Path) -> None:
    path = root / "docs" / "threat-model.md"
    text = path.read_text(encoding="utf-8")
    start = text.find("|", text.find("## Adversaries and mitigations"))
    path.write_text(text[:start + 2] + "X" + text[start + 2:], encoding="utf-8")


def adr_section(root: Path) -> None:
    replace(first_adr(root), "## Consequences", "## Consequence")


def adr_line3(root: Path) -> None:
    replace(first_adr(root), "Date: ", "Dated: ")


def adr_state(root: Path) -> None:
    # In the file, the index and §3 alike, so that only the vocabulary rule breaks.
    replace(first_adr(root), "Status: accepted", "Status: withdrawn")
    for path in (root / "docs" / "adr" / "README.md", root / "docs" / "spec.md"):
        text = path.read_text(encoding="utf-8")
        row = next(line for line in text.splitlines() if line.startswith("| 0001 |"))
        replace(path, row, row.replace("| accepted |", "| withdrawn |", 1))


def adr_first_line(root: Path) -> None:
    replace(first_adr(root), "# ADR 0001 — ", "# ADR 0001 - ")


def adr_gap(root: Path) -> None:
    text = first_adr(root).read_text(encoding="utf-8").replace("# ADR 0001 ", "# ADR 0999 ", 1)
    (root / "docs" / "adr" / "0999-gap.md").write_text(text, encoding="utf-8")


def adr_duplicate(root: Path) -> None:
    shutil.copy2(first_adr(root), root / "docs" / "adr" / "0001-duplicate.md")


def adr_misnamed(root: Path) -> None:
    shutil.copy2(first_adr(root), root / "docs" / "adr" / "0099_misnamed.md")


def adr_heading_number(root: Path) -> None:
    replace(first_adr(root), "# ADR 0001 ", "# ADR 0002 ")


def adr_index_title(root: Path) -> None:
    replace(root / "docs" / "adr" / "README.md", "| 0001 | ", "| 0001 | X")


def unknown_spec_reference(root: Path) -> None:
    path = root / "README.md"
    path.write_text(path.read_text(encoding="utf-8") + "\nSee 999-no-such-spec.\n", encoding="utf-8")


def agents_range(root: Path) -> None:
    path = root / "AGENTS.md"
    path.write_text(path.read_text(encoding="utf-8") + "\nSpecs 010–017.\n", encoding="utf-8")


def example_in_requirements(root: Path, phrase: str = "for example") -> None:
    replace(first_spec(root), "## Requirements\n", f"## Requirements\n\n### Notes\n\n- R99 A key, {phrase} 32 bytes.\n")


def spec_index_state(root: Path) -> None:
    path = first_spec(root)
    number = path.name[:3]
    text = (root / "specs" / "README.md").read_text(encoding="utf-8")
    row = next(line for line in text.splitlines() if line.startswith(f"| {number} |"))
    replace(root / "specs" / "README.md", row, row.rsplit("|", 2)[0] + "| draft |")


def spec_phase(root: Path) -> None:
    replace(first_spec(root), "\nPhase: ", "\nStage: ")


def row_of(path: Path, number: str) -> str:
    return next(line for line in path.read_text(encoding="utf-8").splitlines() if line.startswith(f"| {number} |"))


def adr_superseded_bad(root: Path) -> None:
    replace(first_adr(root), "Status: accepted", "Status: superseded by 42")
    for path in (root / "docs" / "adr" / "README.md", root / "docs" / "spec.md"):
        row = row_of(path, "0001")
        replace(path, row, row.replace("| accepted |", "| superseded by 42 |", 1))


def adr_spec_title(root: Path) -> None:
    path = root / "docs" / "spec.md"
    row = row_of(path, "0001")
    replace(path, row, row.replace("| 0001 | ", "| 0001 | X", 1))


def adr_ghost_row(root: Path) -> None:
    path = root / "docs" / "adr" / "README.md"
    row = row_of(path, "0001")
    replace(path, row, row + "\n| 0999 | Ghost | 2026-01-01 | accepted |")


def spec_ghost_adr(root: Path) -> None:
    path = root / "docs" / "spec.md"
    row = row_of(path, "0001")
    replace(path, row, row + "\n| 0999 | Ghost | accepted | x |")


def spec_adr_state(root: Path) -> None:
    path = root / "docs" / "spec.md"
    row = row_of(path, "0001")
    replace(path, row, row.replace("| accepted |", "| deprecated |", 1))


def device_after_9(root: Path) -> None:
    spec_device_in_9(root)
    replace(root / "docs" / "spec.md", "## 10. SDD execution plan\n", "## 10. SDD execution plan\n\n`Device`.\n")


def agents_spec_id(root: Path) -> None:
    path = root / "AGENTS.md"
    rule = next(line for line in path.read_text(encoding="utf-8").splitlines() if line.startswith("20. "))
    replace(path, rule, rule.replace("027-core-api", "027"))


def adr_index_state(root: Path) -> None:
    path = root / "docs" / "adr" / "README.md"
    row = next(line for line in path.read_text(encoding="utf-8").splitlines() if line.startswith("| 0001 |"))
    replace(path, row, row.replace("| accepted |", "| deprecated |", 1))


def spec_missing_from_plan(root: Path) -> None:
    path = root / "docs" / "spec.md"
    row = next(line for line in path.read_text(encoding="utf-8").splitlines()
               if line.startswith("| 1. ") and first_spec(root).stem in line)
    replace(path, row, row.replace(f"{first_spec(root).stem}, ", "", 1))


def spec_missing_from_index(root: Path) -> None:
    path = root / "specs" / "README.md"
    row = next(line for line in path.read_text(encoding="utf-8").splitlines()
               if line.startswith(f"| {first_spec(root).name[:3]} |"))
    replace(path, row + "\n", "")


def spec_phase_number(root: Path) -> None:
    path = first_spec(root)
    phase = next(line for line in path.read_text(encoding="utf-8").splitlines() if line.startswith("Phase: "))
    replace(path, phase, "Phase: 9")


def spec_state_vocabulary(root: Path) -> None:
    replace(first_spec(root), "\nStatus: ", "\nStatus: shelved · was: ")


def spec_not_in_plan(root: Path) -> None:
    shutil.copy2(first_spec(root), root / "specs" / "998-ghost.md")


def agents_device(root: Path) -> None:
    replace(root / "AGENTS.md", "one opaque handle, `Device`", "one opaque handle")


def spec_imported(root: Path) -> None:
    replace(root / "docs" / "spec.md", "until the channel is imported", "before the channel is imported")


def spec_device_in_9(root: Path) -> None:
    path = next((root / "specs").glob("027-*.md"))
    text = path.read_text(encoding="utf-8")
    state = next(line for line in text.splitlines() if line.startswith("Status: "))
    replace(path, state, "Status: implemented")


# Each rule, the edit that breaks it, and a part of the message the rule prints.
BREAKS: dict[str, tuple[Callable[[Path], None], str]] = {
    "R1 threat table": (threat_cell, "threat-model.md table differs"),
    "002 R1 ADR sections": (adr_section, "sections must be exactly"),
    "002 R1 ADR first line": (adr_first_line, "first line must be"),
    "002 R1 ADR line 3": (adr_line3, "line 3 must be"),
    "002 R1 duplicate ADR number": (adr_duplicate, "used by more than one file"),
    "002 R1 misnamed ADR file": (adr_misnamed, "is named NNNN-kebab-case.md"),
    "002 R1 heading number": (adr_heading_number, "the heading's number is 0002"),
    "002 R1 contiguous numbering": (adr_gap, "numbering has gaps"),
    "002 R3 ADR state": (adr_state, "invalid state 'withdrawn'"),
    "002 R3 superseded by a bad number": (adr_superseded_bad, "invalid state 'superseded by 42'"),
    "002 R2 ADR index title": (adr_index_title, "ADR 0001 differs"),
    "002 R2 ADR index state": (adr_index_state, "ADR 0001 differs"),
    "002 R2 ADR title in §3": (adr_spec_title, "ADR 0001 differs"),
    "002 R2 index row with no file": (adr_ghost_row, "ADR 0999 differs"),
    "002 R2 §3 row with no file": (spec_ghost_adr, "ADR 0999 differs"),
    "002 R2 ADR state in §3": (spec_adr_state, "ADR 0001 differs"),
    "R3 unknown spec id": (unknown_spec_reference, "'999-no-such-spec' is referenced"),
    "R3 spec file not in the plan": (spec_not_in_plan, "specs/998-ghost.md is not listed"),
    "R3 spec dropped from the plan": (spec_missing_from_plan, "-primitives-wrapper.md is not listed"),
    "R4 range in AGENTS": (agents_range, "contains a spec range"),
    "R5 example in requirements": (example_in_requirements, "'for example' is not a fixed value"),
    "R5 e.g. in requirements": (lambda root: example_in_requirements(root, "e.g."), "R99 A key, e.g."),
    "R5 capitalised For example": (lambda root: example_in_requirements(root, "For example,"), "R99 A key, For example"),
    "R5 such as in requirements": (lambda root: example_in_requirements(root, "such as"), "R99 A key, such as"),
    "R7 spec index state": (spec_index_state, "specs index vs file for"),
    "R7 spec phase line": (spec_phase, "missing 'Phase: N' line"),
    "R7 spec phase number": (spec_phase_number, "specs index vs file for"),
    "R7 spec missing from the index": (spec_missing_from_index, "specs index vs file for"),
    "R7 spec state vocabulary": (spec_state_vocabulary, "invalid state 'shelved"),
    "027 R22 AGENTS 20": (agents_device, "AGENTS 20 must name"),
    "027 R22 AGENTS 20 spec id": (agents_spec_id, "AGENTS 20 must name"),
    "027 R22 §5": (spec_imported, "§5 must say"),
    "027 R22 §9": (spec_device_in_9, "§9 must name"),
    "027 R22 §9 ends at §10": (device_after_9, "§9 must name"),
}


def fires(case: Path, message: str, base: str | None = None) -> bool:
    code, out = lint(case, base)
    return code != 0 and message in out


def r6_case(base: Path, case: Path, header: str | None, message: str, *, commit: bool = True,
            committed: str | None = None) -> bool:
    """docs/spec.md changed with its header line replaced by `header` (None keeps it),
    committed on 2026-01-02 by its author (`committed` sets another committer date) or
    left uncommitted; whether the lint fails with `message`."""
    shutil.copytree(base, case, symlinks=True)
    start = git(case, "rev-parse", "HEAD")
    spec = case / "docs" / "spec.md"
    lines = spec.read_text(encoding="utf-8").splitlines()
    if header is not None:
        lines = [header if line.startswith("Version: ") else line for line in lines]
    spec.write_text("\n".join(lines) + "\nx\n", encoding="utf-8")
    if commit:
        git(case, "commit", "-qam", "stale", when="2026-01-02T12:00:00", committed=committed)
    return fires(case, message, start)


R6_STALE = "but its header says"
# Each case, and the header, commit and message it takes.
R6_CASES: dict[str, tuple[str | None, bool, str | None, str]] = {
    "a change committed under a stale date": (None, True, None, R6_STALE),
    "an uncommitted change under a stale date": ("Version: mvp · Updated: 2000-01-01", False, None, R6_STALE),
    "a header with the committer's date, not the author's": (
        "Version: mvp · Updated: 2026-01-03", True, "2026-01-03T12:00:00", R6_STALE),
    "no 'Updated' header": ("Version: mvp", True, None, "Updated: YYYY-MM-DD' missing"),
}


def check_s003_t08_r08_every_rule_fires() -> list[str]:
    errors = []
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp) / "base"
        copy_tree(base)
        code, out = lint(base)
        if code != 0:
            return ["the lint fails on an unbroken copy of the tree:\n" + out]
        for rule, (breaks, message) in BREAKS.items():
            case = Path(tmp) / rule.replace(" ", "_")
            shutil.copytree(base, case, symlinks=True)
            breaks(case)
            if not fires(case, message):
                errors.append(f"the lint accepts a broken {rule}, or fails without {message!r}")
        for i, (name, (header, commit, committed, message)) in enumerate(R6_CASES.items()):
            if not r6_case(base, Path(tmp) / f"R6_{i}", header, message, commit=commit, committed=committed):
                errors.append(f"the lint accepts docs/spec.md with {name}")
        # R6 takes two changes committed on the day the header says, whatever today is, but
        # not an uncommitted change on top of them; a tree that leaves docs/spec.md alone
        # passes under any header.
        case = Path(tmp) / "R6_pass"
        r6_case(base, case, "Version: mvp · Updated: 2026-01-02", R6_STALE)
        spec = case / "docs" / "spec.md"
        spec.write_text(spec.read_text(encoding="utf-8") + "y\n", encoding="utf-8")
        git(case, "commit", "-qam", "same day", when="2026-01-02T18:00:00")
        start = git(case, "rev-parse", "HEAD~2")
        if lint(case, start)[0] != 0:
            errors.append("the lint refuses docs/spec.md changed twice on the day its header says")
        spec.write_text(spec.read_text(encoding="utf-8") + "z\n", encoding="utf-8")
        if not fires(case, R6_STALE, start):
            errors.append("the lint accepts an uncommitted change under a committed day's date")
        # A merge that joins two changes to docs/spec.md, as GitHub's test merge does, is not
        # the latest change: the header keeps the date of the last commit that is not one.
        case = Path(tmp) / "R6_merge"
        shutil.copytree(base, case, symlinks=True)
        start = git(case, "rev-parse", "HEAD")
        trunk = git(case, "rev-parse", "--abbrev-ref", "HEAD")
        spec = case / "docs" / "spec.md"
        git(case, "checkout", "-qb", "side")
        spec.write_text(spec.read_text(encoding="utf-8") + "side\n", encoding="utf-8")
        git(case, "commit", "-qam", "side", when="2026-01-02T12:00:00")
        git(case, "checkout", "-q", trunk)
        lines = ["Version: mvp · Updated: 2026-01-02" if line.startswith("Version: ") else line
                 for line in spec.read_text(encoding="utf-8").splitlines()]
        spec.write_text("\n".join(lines) + "\n", encoding="utf-8")
        git(case, "commit", "-qam", "trunk", when="2026-01-02T13:00:00")
        git(case, "merge", "-q", "--no-edit", "side", when="2026-01-05T12:00:00")
        if lint(case, start)[0] != 0:
            errors.append("the lint dates docs/spec.md by a merge commit")
        case = Path(tmp) / "R6_untouched"
        shutil.copytree(base, case, symlinks=True)
        spec = case / "docs" / "spec.md"
        lines = ["Version: mvp · Updated: 2000-01-01" if line.startswith("Version: ") else line
                 for line in spec.read_text(encoding="utf-8").splitlines()]
        spec.write_text("\n".join(lines) + "\n", encoding="utf-8")
        git(case, "commit", "-qam", "old header")
        start = git(case, "rev-parse", "HEAD")
        (case / "README.md").write_text("x\n", encoding="utf-8")
        git(case, "commit", "-qam", "other file", when="2026-01-02T12:00:00")
        if lint(case, start)[0] != 0:
            errors.append("the lint refuses a change that leaves docs/spec.md alone")
    return errors


def main() -> int:
    errors = check_s003_t08_r08_every_rule_fires()
    for error in errors:
        print(f"doc_lint_selftest: {error}")
    if errors:
        return 1
    print(f"doc_lint_selftest: ok, {len(BREAKS) + len(R6_CASES)} rules fire")
    return 0


if __name__ == "__main__":
    sys.exit(main())
