# ADR 0004 — Sense post-compromise security a la v1

Data: 2026-09-19 · Estat: acceptada

## Context
Amb ADR 0001 i 0013, qui obtingui `K_ch` pot llegir el canal sencer, passat i futur, indefinidament. La v1 no té ni forward secrecy ni post-compromise security criptogràfiques (revisió B, 2026-09-20).

## Decisió
La v1 no intenta recuperar la seguretat després d'una filtració de config ni protegir els missatges anteriors a una filtració. La resposta és l'alarma de compromís (ADR 0011), la retirada de clau (ADR 0016) i crear un canal nou (ADR 0008). Això es diu explícitament a la documentació pública (`docs/spec.md` §1).

## Alternatives descartades
- «Salt d'època» ara: cada membre publica una clau X25519 efímera signada; cada N missatges o dies, la nova `K_ch` es deriva de l'antiga més els DH entre membres actius. Dona FS i PCS a la vegada, però complica el format i el tractament de membres inactius. Es reserva per a la v2 (`docs/spec.md` §12).
- Ratchet simètric sense DH: no dona ni FS ni PCS en aquest model (ADR 0003, 0013).

## Conseqüències
- Simplicitat màxima a la v1.
- La v2 serà `proto_version = 2` amb capçal propi; no es reserven camps a la v1 i els receptors rebutgen versions desconegudes.
- A revisar per a la v2.
