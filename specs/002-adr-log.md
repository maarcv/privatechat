# 002 — Architecture decision log

Status: implemented
Phase: 0
Related ADRs: all
Depends on: 000
Blocks: 003
Human reviewer: Marc Vilardebó · Accepted on: 2026-09-20

## Context

The 22 ADRs in `docs/adr/` are the historical context of every decision and the barrier against silent changes (AGENTS 3). For them to be useful, they must have a single format, an index that matches the table in `docs/spec.md` §3 and a closed state vocabulary, and a machine must check it. This spec fixes the format and the procedure; the check is implemented by spec 003.

## Requirements

- R1 Every ADR MUST live at `docs/adr/NNNN-<kebab>.md`, with `NNNN` sequential with no gaps and no reuse, and follow `docs/adr/TEMPLATE.md`: first line `# ADR NNNN — Title`, third line `Date: YYYY-MM-DD · Status: <state>[ · Supersedes: NNNN]`, and exactly the sections `## Context`, `## Decision`, `## Alternatives considered`, `## Consequences`, in that order.
- R2 `docs/adr/README.md` MUST contain an `## Index` table with one row per ADR (number, literal title, date, state) identical in number, title and state to the table in `docs/spec.md` §3 and to the files.
- R3 The state MUST be one of `proposed`, `accepted`, `deprecated`, `superseded by NNNN`.
- R4 An accepted ADR MUST NOT be edited except to change its state; changing a decision MUST be done with a new ADR carrying `Supersedes: NNNN`, and the old one becomes `superseded by MMMM`. Documented exception in the README: ADRs 0001–0022, written before the repository, carry review notes in their Context.
- R5 Every change to the wire format, the channel config, the domain tags or the key derivations MUST be accompanied by a new ADR (AGENTS 3); the CI enforces it (spec 001, R8).

## Limits

- Title ≤ 80 characters. No formulas inside an ADR: reference to `docs/spec.md` §4.

## Interface

- `docs/adr/TEMPLATE.md` — template.
- `docs/adr/README.md` — procedure and index.
- Mechanical check: `check_s002_t01_r01_*`, `check_s002_t02_r02_*`, `check_s002_t03_r03_*` in `scripts/doc_lint.py`.

## Security

- Not directly applicable; it is the log that prevents a security decision from changing without human review.

## Public API changes

- None.

## Test cases

- T01 (covers R1): `check_s002_t01_r01_adr_files_follow_template` validates the file name `NNNN-<kebab>.md`, line 1, line 3 (`Date · Status [· Supersedes]`), the four sections and the contiguous numbering.
- T02 (covers R2): `check_s002_t02_r02_adr_index_matches_files_and_spec` compares files ↔ index ↔ §3 (number, title, state).
- T03 (covers R3): `check_s002_t03_r03_adr_states_are_in_vocabulary`.
- T04 (covers R4): human review in the PR; item `s002_t04_r04_accepted_adr_only_state_changes` of the PR template. No mechanical check in v1.
- T05 (covers R5): CI step `s001_t08_r08_protected_paths_require_adr`, also recorded as `s002_t05_r05_format_changes_need_adr`.

## Vectors

- None.

## Acceptance criterion

`scripts/doc_lint.sh` green with the current 22 ADRs; a test ADR with one section missing makes the lint fail.

## Out of scope

- Generating the index automatically: it is maintained by hand and checked.

## Open questions

- [ ] 002-R4: is a script that detects diffs in accepted ADRs outside the state line worthwhile? Proposal: yes, in phase 1 if it proves necessary.

## History

- 2026-09-20 draft · 2026-09-20 in review · 2026-09-20 accepted (Marc Vilardebó) · 2026-09-20 implemented
