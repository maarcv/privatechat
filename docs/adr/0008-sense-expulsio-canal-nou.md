# ADR 0008 — Sense expulsió de membres: es crea un canal nou

Data: 2026-09-19 · Estat: acceptada

## Context
Treure un membre d'un grup xifrat requereix que la resta acordi una clau nova que l'expulsat no conegui.

## Decisió
No hi ha operació d'expulsió. Per treure algú, els membres restants creen un canal nou i en comparteixen la config fora de banda.

## Alternatives descartades
- Rekey selectiu (arbre de claus tipus MLS): eficient per a grups grans, però incompatible amb ADR 0001 (cap gestió de membres al servidor) i molt més complex.

## Conseqüències
- Coherent amb ADR 0001 i 0004.
- La UX de «crear canal nou a partir d'aquest» (mateix nom, nova `K_ch`, llista de peers verificats per reinvitar) ha de ser ràpida.
- Si la filtració ve del dispositiu d'un membre, el canal nou tornarà a filtrar-se pel mateix camí: la UX pregunta «saps d'on ha sortit?» i recomana excloure'n el membre sospitós.
