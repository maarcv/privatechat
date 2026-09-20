# NNN — Feature name

Status: draft | in review | accepted | implemented
Phase: N
Related ADRs: 000X, 000Y
Depends on: NNN, NNN (specs that must be `implemented`)
Blocks: NNN
Human reviewer: (name) · Accepted on: YYYY-MM-DD

## Context

What this feature solves and why. Which ADR justifies it. Link to the section of `docs/spec.md` that describes it.

## Requirements

Numbered, verifiable, one sentence each. Every R* uses MUST / MUST NOT, cites concrete numeric values (no "for example") and is checkable with a T*.

- R1 …
- R2 …

## Limits

Every variable-length field has a numeric maximum here. Every external integer has its range here and what happens out of range.

## Interface

Exact signatures (Rust for `core`, messages for the server, screens for the clients). Formats in bytes with offsets. Possible `Error` codes.

```rust
pub fn example(input: &[u8]) -> Result<Output, Error>;
```

## Security

Which types carry secrets (→ `Zeroize`, `ZeroizeOnDrop`, redacted `Debug`). What must not reach the logs. External inputs and how they are validated. Constant-time comparisons where needed.

## Public API changes

New or changed signatures at the core boundary (`docs/spec.md` §9, spec 027). If there are any, 040 and 041 must be updated.

## Test cases

Every test cites the requirement it covers and is named `sNNN_tTT_rRR_<description>`.

- T01 (covers R1): input → expected output
- T02 (covers R2): invalid input → `Error::X` · commits to the Store = 0
- For every spec with state: a test with `FailingStore` that fails at commit *n* and checks that reopening yields the state prior to *n*.
- For every format: the mutation table (in "Vectors") is a test.

## Vectors

Mandatory for `core` specs with a format or a derivation: file `specs/vectors/NNN.json` with the schema of `specs/vectors/README.md` (`{ "name", "inputs": {…hex}, "expected": {…hex} }`), and at least one negative vector for every rejection requirement. For formats, a **mutation table**: for every offset region, the exact `Error` expected when mutating one byte, and the assert that the Store receives no commit. For signatures: negative vectors with non-canonical S (S + L), identity `pk`, small-order `pk` and `R`, non-canonical `pk`.

## Acceptance criterion

Exact command that must pass (`cargo test -p privatechat-core sNNN_`), plus the non-automatable criterion if there is one.

## Out of scope

What this feature does NOT do, so that the agent does not add it.

## Open questions

- [ ] …

## History

- YYYY-MM-DD draft · YYYY-MM-DD accepted (reviewer)
