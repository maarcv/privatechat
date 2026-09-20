# ADR 0001 — Clau de canal precompartida fora de banda

Data: 2026-09-19 · Estat: acceptada

## Context
Cal que un grup de persones comparteixi un canal xifrat sense que el servidor conegui res dels membres.

## Decisió
L'accés a un canal es dona amb una clau arrel `K_ch` (32 B aleatoris) que viatja dins d'una config compartida fora de banda: QR en persona, fitxer xifrat amb contrasenya o enllaç amb fragment.

## Alternatives descartades
- X3DH amb prekeys al servidor (Signal): requereix que el servidor guardi claus públiques per usuari i coneixi la topologia del grup.
- MLS (RFC 9420): resol l'acord de claus i la gestió de membres en línia, que aquest model no necessita.

## Conseqüències
- El servidor no pot saber qui és membre de què.
- La config és l'únic secret: si es filtra, tot el canal queda llegible fins a crear-ne un de nou (vegeu ADR 0004 i 0008).
- La UX de compartir la config és crítica per a la seguretat.
