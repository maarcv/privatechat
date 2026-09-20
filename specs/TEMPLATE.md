# NNN — Nom de la feature

Estat: esborrany | en revisió | acceptada | implementada
Fase: N
ADR relacionades: 000X, 000Y
Depèn de: NNN, NNN (specs que han d'estar `implementada`)
Bloqueja: NNN
Revisor humà: (nom) · Acceptada el: AAAA-MM-DD

## Context

Què resol aquesta feature i per què. Quina ADR ho justifica. Enllaç a la secció de `docs/spec.md` que ho descriu.

## Requisits

Numerats, verificables, una frase cada un. Cada R* usa MUST / NO POT, cita valors numèrics concrets (no «per exemple») i és comprovable amb un T*.

- R1 …
- R2 …

## Límits

Tot camp de longitud variable té aquí un màxim numèric. Tot enter extern té aquí el seu rang i què passa fora de rang.

## Interfície

Signatures exactes (Rust per a `core`, missatges per al servidor, pantalles per als clients). Formats en bytes amb offsets. Codis d'`Error` possibles.

```rust
pub fn exemple(input: &[u8]) -> Result<Output, Error>;
```

## Seguretat

Quins tipus porten secrets (→ `Zeroize`, `ZeroizeOnDrop`, `Debug` redactat). Què no pot sortir als logs. Entrades externes i com es validen. Comparacions en temps constant on calgui.

## Canvis d'API pública

Signatures noves o canviades a la frontera del nucli (`docs/spec.md` §9, spec 027). Si n'hi ha, cal actualitzar 040 i 041.

## Casos de prova

Cada test cita el requisit que cobreix i es diu `sNNN_tTT_rRR_<descripció>`.

- T01 (cobreix R1): entrada → sortida esperada
- T02 (cobreix R2): entrada invàlida → `Error::X` · commits al Store = 0
- Per a tota spec amb estat: un test amb `FailingStore` que falla al commit *n* i comprova que reobrir dona l'estat anterior a *n*.
- Per a tot format: la taula de mutació (a «Vectors») és un test.

## Vectors

Obligatoris per a specs de `core` amb format o derivació: fitxer `specs/vectors/NNN.json` amb l'esquema de `specs/vectors/README.md` (`{ "name", "inputs": {…hex}, "expected": {…hex} }`), i almenys un vector negatiu per cada requisit de rebuig. Per a formats, una **taula de mutació**: per a cada regió d'offsets, l'`Error` exacte esperat en mutar un byte, i l'assert que el Store no rep cap commit. Per a signatures: vectors negatius amb S no canònica (S + L), `pk` identitat, `pk` i `R` de petit ordre, `pk` no canònica.

## Criteri d'acceptació

Comanda exacta que ha de passar (`cargo test -p core sNNN_`), més el criteri no automatitzable si n'hi ha.

## Fora d'abast

Què NO fa aquesta feature, per evitar que l'agent ho afegeixi.

## Preguntes obertes

- [ ] …

## Historial

- AAAA-MM-DD esborrany · AAAA-MM-DD acceptada (revisor)
