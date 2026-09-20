# ADR 0005 — Signatures Ed25519 per missatge, amb clau per usuari i per canal

Data: 2026-09-19 · Estat: acceptada

## Context
Amb només la clau de canal, qualsevol que la tingui pot enviar missatges fent-se passar per qualsevol nom. Cal autenticitat, no només confidencialitat.

## Decisió
Cada usuari genera un parell Ed25519 per a cada canal en importar la config. Cada missatge va signat amb aquesta clau sobre tots els camps del sobre. La clau pública viatja al sobre i serveix d'identitat local (ADR 0006).

## Alternatives descartades
- Clau d'identitat global per usuari: permetria enllaçar la mateixa persona entre canals, tant per als membres com per al servidor.
- MAC amb clau compartida per parells (deniabilitat, com fa Signal): dona missatges no demostrables a tercers, però requereix una clau per cada parell de membres i complica el model TOFU.

## Conseqüències
- Autenticitat verificable: dos missatges amb la mateixa `pk` venen del mateix dispositiu.
- Cap enllaç d'identitat entre canals.
- Els missatges són no repudiables: una signatura demostra que el titular de la clau el va escriure. Es documenta com a limitació coneguda.
