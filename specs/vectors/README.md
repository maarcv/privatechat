# Test vectors

JSON files validated by Rust, Kotlin and Swift: they guarantee that the three platforms produce exactly the same bytes (`docs/spec.md` §9, ADR 0012, 0023). One file per spec: `NNN.json`.

The reference script `scripts/reference/vectors.py` of spec 015-test-vectors produces every file from 011 on (R5); the Rust tests, and later Kotlin and Swift, reproduce them. They freeze when phase 1 closes, once `cargo test` reproduces every vector the script wrote. From then on they are rewritten **only** with a `proto_version` change accompanied by an ADR (AGENTS 18); the CI (`adr-guard`) refuses a diff that touches this directory without a new ADR, unless a human sets `adr-not-needed`.

## Schema

```json
{
  "spec": "013",
  "proto_version": 1,
  "vectors": [
    {
      "name": "text_message_k1",
      "kind": "positive",
      "source":   "published",
      "origin":   "RFC 9999 section 7.1 TEST 1",
      "inputs":   { "k_ch": "<hex>", "pk_u": "<hex>", "counter": "0000000000000000", "nonce": "<hex>", "payload": "<hex>" },
      "expected": { "blob": "<hex>", "mk": "<hex>" }
    },
    {
      "name": "mutate_signature",
      "kind": "negative",
      "source":   "derived",
      "origin":   "spec 013 mutation table, one flipped byte of the masked signature",
      "inputs":   { "blob": "<hex>" },
      "expected": { "error": "BadSignature" }
    }
  ]
}
```

- All bytes in lowercase hexadecimal. Integers up to 32 bits are JSON numbers; every 64-bit integer (counters, times) is its big-endian 8 bytes as 16 lowercase hex characters, so that Kotlin, Swift and any JSON parser read it without losing precision.
- A boolean is JSON `true` or `false`; an absent optional value is a missing field, never `null`; a list is a JSON array whose items follow the same rules.
- Text appears only in the fields `spec`, `name`, `kind`, `source`, `origin`, `error`, `content` (the outcome of a positive receive vector: `message`, `unreadable` or `stale`), `event` (the outcome of a frame vector of spec 028-session-sans-io: `accepted`, `reconnect` or `unsupported_server`), `policy`, `schema` and `words` (an array of words); every other string is hexadecimal.
- Every vector declares its provenance in `source`, and `origin` names it precisely:
  - `published` — transcribed from a standards document or from the primitive's
    upstream test suite. It proves the implementation matches the standard, so
    it is the only kind that can fail because *we* are wrong about the algorithm.
  - `derived` — written by the reference script of spec 015 from a rule the
    specification states in full (a formula of `docs/spec.md` §4, a padding
    scheme, a length formula). No external source is needed to check it by hand.
  - `pinned` — no published vector exists at the parameters the protocol fixes,
    so the value is the bytes libsodium produced once, transcribed into the
    script as a literal and frozen. It does not prove conformance; it detects a
    change of libsodium version, of build flags or of our wrapper before that
    change reaches a user. `origin` records the library version that produced it.
- A `pinned` vector is a last resort: it is used only when no published vector
  covers the exact parameters, and the spec's "Vectors" section says why.
- Every requirement that rejects external input (bytes from the network, a scanned or typed text, a file) has a `negative` vector with the exact `Error`, except a rejection the primitive wrapper (spec 010) already proves, which is not repeated one layer up; a rejection of a crate-internal function no platform reaches is a unit test of its spec, not a vector. Phase 1 vectors test pure functions and carry no `commits` (the `"commits": 0` of some `010.json` vectors predates this rule and is read as nothing); a vector of a stateful spec (phase 2) adds `commits`, the number of commits other than the cursor, which is 0 on every rejection path except the own-key and step-5 exceptions of spec 021-channel-session R3, which are unit tests. A rejection that needs state built by a sequence of calls (`Replay`, `RetiredKey`, `PeerLimit`, a label already in use) is a unit test of its spec, not a vector.
- For formats, the spec's mutation table (offset region → `Error`) is materialised as `negative` vectors with `name` = `mutate_<region>`.
- The strict Ed25519 negatives — `signature_s_plus_l`, `pk_identity`, `pk_small_order`, `r_small_order`, `pk_non_canonical` (`docs/spec.md` §4 "Primitives") — live once, in `010.json`; no format spec repeats them.
