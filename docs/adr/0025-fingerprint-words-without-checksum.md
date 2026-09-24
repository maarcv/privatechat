# ADR 0025 — Fingerprint words from 132 bits of the fingerprint, with no BIP-39 checksum

Date: 2026-09-24 · Status: accepted

## Context
`docs/spec.md` §4 encoded `fp[0..16]` as a standard BIP-39 mnemonic. Its 4-bit checksum is SHA-256 of the entropy, and SHA-256 is not among the primitives of §4 (spec 010-primitives-wrapper put SHA-2 out of scope). Adding it would reopen an implemented spec for one use. Audit E (findings A12, B13, C recommendation 1) also noted two further points. The checksum exists to catch typing errors when words are entered into a wallet, but here nobody types the words: two people compare them by eye or by voice. And words that form a valid seed phrase train users to read "their 12 words" aloud, which is the shape of a known phishing pattern.

## Decision
The 12 words are `words[i] = list[bits(fp, 11·i, 11)]` for `i` in 0..12, reading `fp` most significant bit first: the first 132 bits of the 256-bit fingerprint as indices into the English BIP-39 list of 2 048 words. They are not a BIP-39 mnemonic. The short identifier stays the first 4 words (44 bits).

## Alternatives considered
- Standard BIP-39 with `crypto_hash_sha256` from libsodium: no new crate, but it amends an implemented spec and a primitive table for a checksum nobody types.
- A checksum computed with BLAKE2b: words that look standard and fail in every BIP-39 tool, which is worse than being plainly not a mnemonic.
- Another word list: the English BIP-39 list is widely reviewed, has no two words sharing their first four letters, and the 7-word file password already uses it.

## Consequences
- No new primitive: spec 010-primitives-wrapper is untouched, and the only hash is the BLAKE2b that already produces `fp`.
- The words carry 132 bits of the fingerprint instead of 128.
- External BIP-39 tools do not accept the words, by design. The acceptance criterion of spec 014-fingerprint no longer asks a human to paste them into one.
- The word list is pinned by its BLAKE2b-256 digest (spec 011-config-format, which uses it first for the password).
- The closed decision of §12 on the word list is updated: English BIP-39 list, chosen for its review and prefix property, not for checksum compatibility.
- Affected specs: 011-config-format, 014-fingerprint, 055-verify-ui.
