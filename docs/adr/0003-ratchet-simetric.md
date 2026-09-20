# ADR 0003 — Ratchet simètric de hash sobre la clau de canal

Data: 2026-09-19 · Estat: substituïda per 0013

## Context
Xifrar directament amb `K_ch` fa que qui obtingui el dispositiu avui pugui desxifrar tots els missatges antics que hagi capturat.

## Decisió
Cada emissor manté una cadena de claus derivada de `K_ch` i de la seva clau pública, avançada per hash a cada missatge; les claus consumides s'esborren.

## Alternatives descartades
- Clau estàtica: sense forward secrecy.
- Double Ratchet (DH + simètric): requereix acord de claus en línia entre parells; incompatible amb ADR 0001.

## Conseqüències
- **Revisió B (2026-09-20, troballa B1): la decisió no aconseguia el que pretenia.** L'arrel de cada cadena es deriva de `K_ch` i de `pk_u` (en clar al cable); qui obté el dispositiu té `K_ch` i recomputa qualsevol clau de la cadena. Esborrar les claus consumides no protegeix res. El ratchet només afegia estat, finestra de claus saltades, límit de salt i exportació del comptador, sense cap guany de seguretat. Vegeu ADR 0013.
