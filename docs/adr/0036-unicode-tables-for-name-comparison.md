# ADR 0036 — Compare names with the unicode-rs normalisation and confusable tables

Date: 2026-09-25 · Status: accepted

## Context
`docs/spec.md` §7 compares labels and `display_name`s after `NFKC → casefold → no spaces or format characters → confusables skeleton (UTS #39)`, so that "Аlice" with a Cyrillic А collides with "Alice". It is the main defence against someone who writes with a new key and claims to be a known member. The rule needs the Unicode normalisation data and the UTS #39 confusables table, which `core` does not carry: its only dependencies are `libsodium-sys-stable` and `zeroize` (§9, ADR 0023). Writing spec 022-peers-tofu forced the choice.

## Decision
`core` depends on `unicode-normalization` for NFKC and on `unicode-security` for the UTS #39 skeleton, both pure Rust from the unicode-rs project; the name key is NFKC, the removal of invisible characters, the skeleton, the Unicode lowercase mapping of the standard library, the skeleton again, a fold of `i` into `l`, the removal of combining marks after canonical decomposition and a fold of `ȷ` into `j` (spec 022-peers-tofu), the invisible table also listing blank-rendering characters such as U+2800; other look-alikes remain a documented residual, covered by the unknown mark, the short identifier and verification; the invisible characters (General_Category Cf and `Default_Ignorable_Code_Point`, about forty ranges), which neither crate exposes, are one small table written by hand and pinned by a test.

## Alternatives considered
- Generating all the tables with a script and embedding them: no dependency, but thousands of entries on the one path an impersonator targets, and a generator to maintain. Only the invisible-character table, a few dozen ranges no crate offers, is kept by hand.
- A narrower rule (ASCII case and whitespace only): most confusable attacks would pass, and the short identifier and the warning of §7 alone would carry the defence.
- Full case folding through a third crate: it differs from the lowercase mapping in a handful of characters (ß, final sigma), and the skeleton step already maps the ones that matter visually.
- Without the final fold: lowercasing first lets "AIice" pass, since UTS #39 maps a capital I to a small l (audit J, J-B3); skeleton first lets "ALICE" pass, since its capital I becomes an l and its small i does not (J6-C1); and two keys, one of each, still let "ALlCE" and "0LIVIA" pass (J7-B2). Folding `i` into `l` at the end catches all of them, at the price of a few harmless extra collisions.

## Consequences
- `core` gains two direct dependencies and their dependency `unicode-script` (and `tinyvec`, used by `unicode-normalization`); each is named in the PR that adds it (AGENTS 8), and `cargo deny` checks their licences.
- Both parse hostile input (names from the network): the comparison function has its own fuzz target (spec 022-peers-tofu, AGENTS 21).
- The result depends on the Unicode version of the tables, so two clients on different versions may disagree on a rare collision; the comparison is local and only decides a warning or a refusal, never a byte on the wire.
- Affected specs: 022-peers-tofu, 026-peer-limits.
