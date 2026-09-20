# Vectors de prova

Fitxers JSON generats pel nucli (`core`) i validats per Rust, Kotlin i Swift: garanteixen que les tres plataformes fan exactament els mateixos bytes (`docs/spec.md` §9, ADR 0012, 0015). Un fitxer per spec: `NNN.json`.

Es regeneren **només** amb un canvi de `proto_version` acompanyat d'una ADR (AGENTS 18); la CI (`adr-guard`) refusa un diff que toqui aquest directori sense una ADR nova.

## Esquema

```json
{
  "spec": "013",
  "proto_version": 1,
  "vectors": [
    {
      "name": "text_message_k1",
      "kind": "positive",
      "inputs":   { "k_ch": "<hex>", "pk_u": "<hex>", "counter": 0, "nonce": "<hex>", "payload": "<hex>" },
      "expected": { "blob": "<hex>", "mk": "<hex>" }
    },
    {
      "name": "signature_s_plus_l",
      "kind": "negative",
      "inputs":   { "blob": "<hex>" },
      "expected": { "error": "BadSignature", "commits": 0 }
    }
  ]
}
```

- Tots els bytes en hexadecimal minúscula; els enters com a nombres JSON.
- Cada requisit de rebuig de la spec té almenys un vector `negative` amb l'`Error` exacte i `commits: 0`.
- Per a formats, la taula de mutació de la spec (regió d'offsets → `Error`) es materialitza com a vectors `negative` amb `name` = `mutate_<regió>`.
- Per a signatures Ed25519: `signature_s_plus_l`, `pk_identity`, `pk_small_order`, `r_small_order`, `pk_non_canonical` són obligatoris (`docs/spec.md` §4 «Primitives»).
