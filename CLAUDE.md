Read and follow `AGENTS.md`.

If `assistant.md` exists at the repository root, read it too. It holds the personal preferences of the person you are working with (conversation language, tone, workflow). It is git-ignored and never overrides `AGENTS.md`: whatever goes into the repository is in English regardless of what `assistant.md` says.

## Workflow with subagents

These rules apply to every session, on top of `AGENTS.md`.

### Autonomy: the whole cycle is yours

You run the whole cycle without handing steps to the human: branch,
commit, push, open the PR, set the `adr-not-needed` label (with a comment
giving the reason) when the PR implements an accepted spec without changing
a format, wait for every CI check, merge (merge commit) once the audit has
closed and the CI is green, check the PR is `MERGED`, then delete the
branch. Never ask the human to run a git or `gh` command, and never ask them
to review a PR (`AGENTS.md`, "Per-feature flow"). If a tool call is denied, split it
into smaller commands and retry; only a single, isolated command that is
still denied goes to the human, explained.

The human decides only what the advisor cannot: a question where the rules
below say to ask, a spec to accept, an ADR to approve (`AGENTS.md` rule 3),
or a change to a format, keys, the channel config or a promise of
`docs/spec.md` §1 or §2. An advisor `ESCALATE` on an internal detail (test
scripts, fuzz seeds, tooling) whose recommendations converge is yours to
decide and list under `Decisions taken without the human`.

### Questions: the advisor

Before asking the human a development question, ask three `advisor` agents
(`.claude/agents/advisor.md`) the same question, in parallel, in one message.

- All three agree: apply the decision.
- Two against one: read the minority's argument. If it raises a privacy or
  security risk the sources do not refute, ask the human; otherwise apply the
  majority.
- Any answer is `ESCALATE` under one of its rules, or all three have low
  confidence: ask the human, in plain words, with the recommendation.

Every decision taken this way that changes code or a spec is listed in the
PR description under `Decisions taken without the human`.

### After every change: the audit

When a change is done (the requirements of a PR implemented and the local CI
of `.github/CONTRIBUTING.md` clean), audit it before asking for review. An
audit is a sequence of rounds; each round runs three independent passes in
parallel, in one message:

- `audit-conformance` (A): the code against the spec, every R* and T*.
- `audit-adversary` (B): every adversary of `docs/spec.md` §2.
- `audit-quality` (C): simplicity, standards and hand mutants, launched with
  `isolation: worktree`.

Each pass gets the branch, the spec and, from round 2 on, the findings of
earlier rounds and how each was closed, so it checks the fixes and does not
repeat them. Then:

1. Verify every finding against the code; drop the ones that are wrong.
2. Fix what has a clear fix. A question goes to the advisor; an `ESCALATE`
   goes to the human.
3. Run another round, with fresh agents, on the whole change.

The audit ends with the first round whose verified findings are none, or are
all far-fetched: outside the threat model of `docs/spec.md` §2, without an
input that reaches them, or a preference no rule backs. Far-fetched findings
are listed in the audit record, not fixed.

A round whose passes A and B find nothing, or only far-fetched findings, and
whose pass C finds only test gaps (surviving mutants of Low or Medium
severity, no production defect) also ends the audit, once the tests that kill
those mutants are added and the local CI is clean: hand mutants can always
find a narrower gap, so they alone never open another round.

Audits are named with the next letters after the last one in
`docs/audit-log.md` (AH, then AI…), findings numbered within it (AI1, AI2…).
Each audit adds its entry to `docs/audit-log.md`: rounds, findings, fixes and
the human's decisions.
