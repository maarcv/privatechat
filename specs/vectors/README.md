# Test vectors

JSON files validated by Rust, Kotlin and Swift: they guarantee that the three platforms produce exactly the same bytes (`docs/spec.md` §9, ADR 0012, 0023). One file per spec: `NNN.json`.

They freeze when phase 1 closes, after `scripts/reference/` has recomputed every `derived` value independently (spec 015-test-vectors). From then on they are regenerated **only** with a `proto_version` change accompanied by an ADR (AGENTS 18); the CI (`adr-guard`) refuses a diff that touches this directory without a new ADR, unless a human sets `adr-not-needed`.

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
      "name": "signature_s_plus_l",
      "kind": "negative",
      "source":   "published",
      "origin":   "libsodium test/default/sign.c, add_l()",
      "inputs":   { "blob": "<hex>" },
      "expected": { "error": "BadSignature" }
    }
  ]
}
```

- All bytes in lowercase hexadecimal. Integers up to 32 bits are JSON numbers; every 64-bit integer (counters, times) is its big-endian 8 bytes as 16 lowercase hex characters, so that Kotlin, Swift and any JSON parser read it without losing precision.
- Every vector declares its provenance in `source`, and `origin` names it precisely:
  - `published` — transcribed from a standards document or from the primitive's
    upstream test suite. It proves the implementation matches the standard, so
    it is the only kind that can fail because *we* are wrong about the algorithm.
  - `derived` — computed from a rule the specification states in full (a padding
    scheme, a length formula). No external source is needed to check it by hand.
  - `pinned` — no published vector exists at the parameters the protocol fixes,
    so the value is the one our own build produced once and froze. It does not
    prove conformance; it detects a change of libsodium version, of build flags
    or of our wrapper before that change reaches a user. `origin` records the
    library version that produced it.
- A `pinned` vector is a last resort: it is used only when no published vector
  covers the exact parameters, and the spec's "Vectors" section says why.
- Every rejection requirement of the spec has at least one `negative` vector with the exact `Error`. Phase 1 vectors test pure functions and carry no `commits`; a vector of a stateful spec (phase 2) adds `commits`, the number of commits other than the cursor, which is 0 on every rejection path.
- For formats, the spec's mutation table (offset region → `Error`) is materialised as `negative` vectors with `name` = `mutate_<region>`.
- For Ed25519 signatures: `signature_s_plus_l`, `pk_identity`, `pk_small_order`, `r_small_order`, `pk_non_canonical` are mandatory (`docs/spec.md` §4 "Primitives").
