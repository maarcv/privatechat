# ADR 0013 — Clau de missatge derivada directament del comptador

Data: 2026-09-20 · Estat: acceptada · Substitueix: 0003

## Context
L'ADR 0003 proposava un ratchet simètric de hash per emissor per obtenir forward secrecy. La revisió B (troballa B1, `docs/spec.md` §13) va mostrar que no la dona: l'arrel de cada cadena es deriva de `K_ch` i `pk_u`, tots dos disponibles per a qui obtingui el dispositiu, i per tant qualsevol clau de la cadena és recomputable. El ratchet només afegia estat de cadena, finestra de claus saltades, límit de salt endavant (que desincronitzava un emissor per sempre després d'un període fora de línia) i complexitat a l'exportació d'identitat.

## Decisió
La clau de cada missatge es deriva en O(1) de l'emissor i el comptador amb una sola PRF amb clau: `K_msg = KDF(K_ch, "msgkey__")` un cop per canal i `mk = BLAKE2b(key = K_msg, in = pk_u ‖ BE64(counter))` per missatge (`docs/spec.md` §4). No hi ha estat de cadena ni cap valor intermedi per emissor. L'anti-replay és un comptador estrictament creixent per emissor (ADR 0019).

Revisió C (2026-09-20): la versió inicial d'aquesta ADR tenia dues derivacions (`K_send(u)` per emissor i `mk_i` per comptador). La indirecció «per emissor» era un romanent del ratchet i no compartimentava res, perquè tothom té `K_ch`; s'ha fusionat en una.

## Alternatives descartades
- Mantenir el ratchet: cost sense benefici, i el límit de salt era un forat de disponibilitat.
- Llavor aleatòria per emissor distribuïda xifrada sota `K_ch` i re-emesa periòdicament: cau igualment davant «gravar tràfic + robar `K_ch` després» i complica la incorporació de membres.
- Salt d'època amb DH (FS + PCS reals): v2, vegeu ADR 0004 i §12.

## Conseqüències
- La v1 no té forward secrecy criptogràfica i ho diu (`docs/spec.md` §1). L'esborrat per TTL protegeix contra un adversari que obté el dispositiu **després** que els missatges hagin caducat i no hagi gravat el tràfic; res més.
- Implementació més petita: menys estat local, menys superfície de fuzzing, exportació d'identitat més senzilla.
- Clau per missatge i nonce aleatori són dos salvavides independents: si el generador aleatori falla, salva el comptador; si el comptador es repetís, salva el nonce. No es col·lapsa a una sola clau per canal.
- Specs afectades: 012-message-keys (substitueix 012-ratchet), 020-store-files, 025-identity-regen.
