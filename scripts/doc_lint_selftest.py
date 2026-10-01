#!/usr/bin/env python3
"""Self-test of the documentation lint (spec 003 R8).

Copies the tracked Markdown and `doc_lint.py` into a temporary git repository,
checks that the lint passes there, then breaks one rule at a time and checks
that the lint fails each time: a rule that stopped firing fails this script.
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


def git(cwd: Path, *args: str, when: str = "2026-01-01T12:00:00") -> str:
    env = dict(os.environ, GIT_AUTHOR_DATE=when, GIT_COMMITTER_DATE=when)
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


def lint(cwd: Path, base: str | None = None) -> int:
    env = {k: v for k, v in os.environ.items() if k != "DOC_LINT_BASE"}
    if base:
        env["DOC_LINT_BASE"] = base
    return subprocess.run([sys.executable, "scripts/doc_lint.py"], cwd=cwd, capture_output=True,
                          env=env).returncode


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
    path = first_adr(root)
    text = path.read_text(encoding="utf-8").splitlines()
    text[2] = text[2].replace("Status: ", "Status: rejected · was: ")
    path.write_text("\n".join(text) + "\n", encoding="utf-8")


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


def example_in_requirements(root: Path) -> None:
    replace(first_spec(root), "## Requirements\n", "## Requirements\n\n### Notes\n\n- R99 A key, for example 32 bytes.\n")


def spec_index_state(root: Path) -> None:
    path = first_spec(root)
    number = path.name[:3]
    text = (root / "specs" / "README.md").read_text(encoding="utf-8")
    row = next(line for line in text.splitlines() if line.startswith(f"| {number} |"))
    replace(root / "specs" / "README.md", row, row.rsplit("|", 2)[0] + "| draft |")


def spec_phase(root: Path) -> None:
    replace(first_spec(root), "\nPhase: ", "\nStage: ")


# Each rule, and the edit that breaks it.
BREAKS: dict[str, Callable[[Path], None]] = {
    "R1 threat table": threat_cell,
    "002 R1 ADR sections": adr_section,
    "002 R1 ADR line 3": adr_line3,
    "002 R3 ADR state": adr_state,
    "002 R1 duplicate ADR number": adr_duplicate,
    "002 R1 misnamed ADR file": adr_misnamed,
    "002 R1 heading number": adr_heading_number,
    "002 R2 ADR index title": adr_index_title,
    "R3 unknown spec id": unknown_spec_reference,
    "R4 range in AGENTS": agents_range,
    "R5 example in requirements": example_in_requirements,
    "R7 spec index state": spec_index_state,
    "R7 spec phase line": spec_phase,
}


def check_s003_t08_r08_every_rule_fires() -> list[str]:
    errors = []
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp) / "base"
        copy_tree(base)
        if lint(base) != 0:
            return ["the lint fails on an unbroken copy of the tree"]
        for rule, breaks in BREAKS.items():
            case = Path(tmp) / rule.replace(" ", "_")
            shutil.copytree(base, case, symlinks=True)
            breaks(case)
            if lint(case) == 0:
                errors.append(f"the lint accepts a broken {rule}")
        # R6: a committed change to docs/spec.md under a stale `Updated` date.
        case = Path(tmp) / "R6"
        shutil.copytree(base, case, symlinks=True)
        start = git(case, "rev-parse", "HEAD")
        spec = case / "docs" / "spec.md"
        spec.write_text(spec.read_text(encoding="utf-8") + "\nx\n", encoding="utf-8")
        git(case, "commit", "-qam", "stale", when="2026-01-02T12:00:00")
        if lint(case, start) == 0:
            errors.append("the lint accepts docs/spec.md changed under a stale date")
    return errors


def main() -> int:
    errors = check_s003_t08_r08_every_rule_fires()
    for error in errors:
        print(f"doc_lint_selftest: {error}")
    if errors:
        return 1
    print(f"doc_lint_selftest: ok, {len(BREAKS) + 1} rules fire")
    return 0


if __name__ == "__main__":
    sys.exit(main())
