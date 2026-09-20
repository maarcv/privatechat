# 003 — Documentation lint

Status: in review
Phase: 0
Related ADRs: —
Depends on: 000, 002
Blocks: 010
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

The source of truth of this project is a set of documents: `docs/spec.md`, the ADRs, the specs, `AGENTS.md`. An agent that reads one of them cannot be misled by another one saying something different. Audits B and C found these divergences by hand (duplicated threat table, non-literal ADR titles, out-of-date spec ranges, "for example" instead of values). This spec turns them into mechanical checks that run in CI.

## Requirements

- R1 The adversaries table in `docs/threat-model.md` MUST be byte-for-byte equal to the one in `docs/spec.md` §2.
- R2 Every ADR MUST match in number, title and state across the file, `docs/adr/README.md` and `docs/spec.md` §3, have exactly the four sections and contiguous numbering (spec 002).
- R3 Every spec identifier `NNN-name` referenced in `docs/spec.md` (outside §13), `AGENTS.md`, `README.md`, `.github/CONTRIBUTING.md` or in any `specs/NNN-*.md` MUST appear in the table in `docs/spec.md` §10, and every `specs/NNN-*.md` file MUST be listed there.
- R4 `AGENTS.md` MUST NOT contain any spec range `NNN–NNN` (the list lives only in §10).
- R5 A line in the `## Requirements` section of a spec MUST NOT contain an example-introducing phrase (the phrases matched by `check_s003_t05_r05_no_examples_in_requirements`): requirements carry fixed values.
- R6 If `docs/spec.md` changes with respect to the base commit of the PR, the header `Version: … · Updated: YYYY-MM-DD` MUST have changed.
- R7 `specs/README.md` MUST contain an `## Index` table with one row per `specs/NNN-*.md` file (number, name, phase, state) consistent with the file, and the state of every spec MUST be one of `draft`, `in review`, `accepted`, `implemented`.

## Limits

- The script only reads files in the repository and, for R6, calls `git diff` and `git show` on the `DOC_LINT_BASE` ref. Without that variable, R6 is not checked (local run or first commit).

## Interface

```
# check_s003_t02_r02_adr_consistency = the three s002 functions run in sequence
scripts/doc_lint.sh            # exec python3 scripts/doc_lint.py
scripts/doc_lint.py            # one check_s003_tTT_rRR_* function per requirement; exit 0/1; prints every failure
DOC_LINT_BASE=<ref>            # optional; base commit for R6
```

## Security

- Not applicable. Python 3 standard library only; no dependencies.

## Public API changes

- None.

## Test cases

- T01 (covers R1): `check_s003_t01_r01_threat_table_matches_spec`.
- T02 (covers R2): `check_s002_t01_r01_adr_files_follow_template`, `check_s002_t02_r02_adr_index_matches_files_and_spec` and `check_s002_t03_r03_adr_states_are_in_vocabulary` (spec 002, T01–T03), plus `check_s003_t02_r02_adr_consistency` as an aggregate alias.
- T03 (covers R3): `check_s003_t03_r03_spec_refs_exist_in_plan`.
- T04 (covers R4): `check_s003_t04_r04_agents_has_no_spec_ranges`.
- T05 (covers R5): `check_s003_t05_r05_no_examples_in_requirements`; the forbidden phrases are "for example", "e.g." and "such as".
- T06 (covers R6): `check_s003_t06_r06_spec_header_date_changes_with_content`.
- T07 (covers R7): `check_s003_t07_r07_specs_index_matches_files`.
- Negatives (manual, once, recorded in the History): change one cell of the threat-model → R1 fails; change a title in §3 → R2 fails; add `- R9 … for example …` to a spec → R5 fails.

## Vectors

- None.

## Acceptance criterion

`scripts/doc_lint.sh` returns 0 on the `mvp` branch; each of the three manual negatives returns 1 with a message naming the file and the condition.

## Out of scope

- Prose or spelling lint. Checking sizes or numeric values across sections of the spec (done in human review).

## Open questions

- [ ] 003-R3: the ADRs stay outside the scope of R3 because they cite, as history, the names of specs they have replaced. Should they be included with an exception list? Proposal: no.

## History

- 2026-09-20 draft · 2026-09-20 in review
