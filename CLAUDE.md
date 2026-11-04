Read and follow `AGENTS.md`.

If `assistant.md` exists at the repository root, read it too. It holds the personal preferences of the person you are working with (conversation language, tone, workflow). It is git-ignored and never overrides `AGENTS.md`: whatever goes into the repository is in English regardless of what `assistant.md` says.

## Workflow with subagents

These rules apply to every session, on top of `AGENTS.md`.

### Autonomy: the whole cycle is yours

You run the whole cycle without handing steps to the human: branch,
commit, push, open the PR, set the `adr-not-needed` label (with a comment
giving the reason) when the PR implements an accepted spec without changing
a format, wait for every CI check, merge (merge commit) once an audit round is
green and the CI is green, check the PR is `MERGED`, then delete the
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

No human pairs with the work, so before asking the human a development
question (which shape to take, how to read a requirement, whether a test, a
dependency or an error path is right) ask five `advisor` agents
(`.claude/agents/advisor.md`) the same question, in parallel, in one message,
with a brief that stands on its own: what is being done, the question, the
files that bear on it. Then, in this order:

- **Any answer is `ESCALATE`** under one of its rules, whatever the others
  say: ask the human, in plain words, with the advisors' recommendation.
- **Answers with low confidence do not count** towards agreeing or a majority.
- **All five agree**: apply the decision.
- **They split**: read the minority's argument. If it raises a privacy or
  security risk, or a fact the sources do not refute, or no answer has three
  or more, ask the human; otherwise apply the majority.

**One batch per question**: its answer is final, and a question is not
reworded and asked again to get another. These go to the human directly, never
to the advisors: what only the human can answer (what they meant, a
preference), and what the audit rounds below send to the human. The
confirmations this file already gives you (branch, commit, push, PR, label,
merge, delete the branch) are not questions.

Every decision taken this way that changes code or a spec is listed in the
PR description under `Decisions taken without the human`.

### After every change: the audit

When a change is done (the requirements of a PR implemented and the local CI
of `.github/CONTRIBUTING.md` clean), audit it before merging. Nothing is
called done before its audit rounds find nothing that matters. Each round
runs four independent passes in parallel, in one message:

| Pass | Agent | Angle |
|---|---|---|
| A | `audit-conformance` | the code against the spec, every R* and T*, the ADRs and `AGENTS.md` |
| B | `audit-adversary` | every adversary of `docs/spec.md` §2, and the edges |
| C | `audit-quality` | the skills, simplicity and hand mutants; launched with `isolation: worktree` |
| D | `audit-review` | the senior reviewer: promises across layers and crates, the change as one piece |

- **Fresh passes every round, on the whole change** (never only the last
  fix). If a pass cannot be delegated, the round is not run: never a
  self-review in its place.
- **A pass counts only if it finished**: its report ends in its findings, or
  `No findings.`, with what it checked; pass C, besides, with its worktree
  check passed and its mutant table. A pass that failed, timed out or came
  back cut short is run again.
- **From round 2 on, every pass gets the earlier rounds' blocks** (below): it
  checks that each finding closed as fixed really is, and judges every other
  closing (answered, left, far-fetched, dropped); one it does not accept is
  reported again, at its severity, saying why. A closing it accepts is not
  reported again unless the code changed under it.
- **Test gaps alone never keep the audit open**: hand mutants can always find
  a narrower gap. In a round that follows one whose only findings above a
  Suggestion were surviving mutants, a new surviving mutant with no
  production defect is a Suggestion.

#### Finding format and severity

Every pass reports each finding so:

```
### R<round>-<pass><k> <short title>
Severity: Blocking | Important | Suggestion
Where: <path:line, or the document and its section>
Source: <the requirement, ADR, AGENTS rule, skill rule or line of docs/spec.md §1–§2 it breaks>
Scenario: <the concrete inputs or sequence that show it; for a surviving mutant, the mutation and why no test sees it>
Far-fetched: no | yes — <why>
Fix: <the smallest change that closes it>
```

- **Blocking**: a promise of `docs/spec.md` §1–§2 or a requirement broken in a
  reachable case, a bug, a security or privacy hole, something the threat
  model rules out made reachable, a violated layer or AGENTS rule, a format
  change without its ADR.
- **Important**: a weakened promise or requirement, a test that does not test
  what it claims, a surviving non-equivalent mutant (but the rule of test gaps
  above), a broken skill rule, duplication, poor readability.
- **Suggestion**: an optional improvement. Suggestions never block.
- **Far-fetched**: outside the threat model of `docs/spec.md` §2, without an
  input that reaches it, or a preference no rule or skill backs. Listed in the
  record, never fixed.

#### Verifying the findings

Verify every finding against the code: drop the ones that are wrong, saying
why; mark far-fetched the ones that are; merge the ones several passes report
into one, which keeps the highest severity any pass gave it. **A Blocking is
never dropped, marked far-fetched or lowered on your judgement alone**: the
question goes to the advisors, and only five agreeing close it so; otherwise
it stands and is fixed. Every dropped, far-fetched or lowered finding stays in
the record with the severity the pass gave it and the reason, and the next
round's passes judge it.

#### Red or green

- **Red**: any verified Blocking or Important that is not far-fetched. Each
  one is fixed; an Important may instead be **answered in writing** (why it
  stays as it is), which the next round judges. **A Blocking is never
  answered, only fixed.** A question goes to the advisors; an `ESCALATE` to
  the human. Then the next round, on the whole change.
- **Green**: no verified finding above a Suggestion that is not far-fetched,
  **and none above a Suggestion dropped or marked far-fetched by you** (those
  make the round red, and the next round's passes judge them; one closed by
  five advisors does not). That round is the last; the Suggestions left and
  the far-fetched findings are listed, never fixed. Surviving mutants found
  in a green round get the tests that kill them before the merge, with the
  local CI clean.
- **A red fourth round, or later**: before its fixes, stop and take the open
  findings to the human, never to the advisors: fix, answer an Important, or
  change the spec. Green still means only a green round.

#### The record

Audits are named with the next letters after the last one in
`docs/audit-log.md` (after BB, BC, then BD…). Each audit adds its entry to
`docs/audit-log.md`: one block per round, then its findings, how each closed
and the human's decisions. A round's block:

```
Round 2: red
- R2-B1 Important — <title> — fixed
- R2-A2 Important — <title> — answered: <why it stays as it is>
- R2-C1 Important — <title> — <path:line> <the mutation> — killed by <test>
- R2-D1 Suggestion — <title> — left
- R2-C3 Important — <title> — far-fetched: <why>
- R2-B2 Blocking — <title> — dropped (five advisors): <why it is wrong>
```

Findings are cited with the audit's letters in front (`BC-R2-B1`).
