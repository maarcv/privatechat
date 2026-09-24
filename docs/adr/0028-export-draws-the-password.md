# ADR 0028 — The export draws the file password; the invitation crosses the boundary as bytes

Date: 2026-09-24 · Status: accepted · Supersedes: 0026

## Context
ADR 0026 had `core` generate and canonicalise the 7-word file password, fixed the invitation expiry and made the config QR base64url text. Audit F (`docs/audit-log.md`, F5–F7) found three gaps:

- **The export accepted any password.** `export_encrypted(password)` took any canonical password, even `"a"`, so the 77-bit guarantee against the perfect offline oracle of the `secretbox` tag depended on every UI (F-B8).
- **The key sat in a `String`.** `export_qr` returned the base64url of the config, which contains `K_ch`, as a `String`. AGENTS 5 forbids key material in a `String` (F-A3).
- **Only four whitespace characters were collapsed.** A U+00A0 or U+3000 from a mobile keyboard turned the right password into a wrong one (F-A20).

## Decision
`export_encrypted(now)` draws the password itself and returns the file together with the password's canonical bytes. No caller chooses a password.

The canonical form stays as ADR 0026 fixed it: 7 lowercase ASCII words of the English BIP-39 list, joined by one U+0020, each word drawn as 11 bits from `randombytes_buf`. Opening a file canonicalises the typed password first: ASCII letters are lowercased, every run of Unicode `White_Space` characters becomes one U+0020, and leading and trailing whitespace is removed.

The invitation expiry stays fixed, with no parameter: `now + 600 000` ms for the QR and `now + 86 400 000` ms for the file. It is dropped once the config is imported.

The config QR is the base64url of the config record, without padding, with no prefix and no URL scheme. It crosses the core boundary as ASCII bytes, never as a `String`. The UI renders the QR from those bytes and zeroizes them after the call, the same way it treats the password (§8).

## Alternatives considered
- Refusing any password that is not 7 list words: it keeps a parameter whose only valid value the core could have drawn itself.
- A `String` return with an AGENTS exception: the rule would stop being literal, and a `String` cannot be wiped on any platform.
- Collapsing only ASCII whitespace: it turns a keyboard's quirk into a wrong password.

## Consequences
- The 77 bits are guaranteed by `core`: there is no path that seals a file under a weaker password.
- `Config::generate_password` disappears from the boundary. The UI shows the password that the export returns.
- A file exported on one platform opens on every other, whatever keyboard typed the words.
- Affected specs: 011-config-format, 021-channel-session, 027-core-api, 054-qr-invite.
