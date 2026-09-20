# ADR 0009 — TTL definit a la config, aplicat al servidor i al client

Data: 2026-09-19 · Estat: acceptada

## Context
Els missatges han de desaparèixer passat un temps definit per canal.

## Decisió
`ttl_seconds` viu a la config (60 s – 30 dies). El servidor esborra els blobs passat el TTL. El client esborra els missatges pel seu compte, segons la seva còpia de la config, sense dependre del servidor.

## Alternatives descartades
- Només al servidor: el servidor no és de confiança; podria retenir còpies i el client no ho pot verificar.

## Conseqüències
- La garantia real d'esborrat és la del client. La del servidor és higiene i es documenta com a tal (sense còpies de seguretat de missatges, `secure_delete`, `docs/spec.md` §6).
- Com el servidor coneix i aplica el TTL sense que ningú el pugui canviar: ADR 0014. La regla inicial «si arriben TTL diferents guanya el menor» es va retirar a la revisió B (troballa B5).
