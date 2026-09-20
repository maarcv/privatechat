# ADR 0019 — Una clau, un dispositiu: comptador estrictament creixent

Data: 2026-09-20 · Estat: acceptada

## Context
La revisió B va introduir una finestra lliscant anti-replay de 4 096 posicions amb bitmap per emissor, i mantenia l'exportació d'identitat entre dispositius (mateixa `sk_u` a dos llocs, amb un salt de +1 024 al comptador en importar). La revisió C va mostrar (troballa C2) que la finestra només protegeix qui va veure l'original: un intrús amb la config pot reinjectar un blob antic d'Alice a un membre incorporat després, a un que va estar fora de línia més d'un TTL, o a un desconegut evictat, i el missatge reapareix autenticat per Alice amb hora actual. En un sistema on cada `sk_u` viu en un sol dispositiu i el servidor lliura cada canal en ordre total, un comptador inferior al màxim vist no té cap causa legítima. L'exportació d'identitat era l'única raó de la finestra, i era alhora l'origen d'una classe de fallades (mateixa clau a dos dispositius, reutilització de comptador, «el destí confirma» sense cap protocol, esborrat a l'origen no forçable).

## Decisió
Una clau `sk_u` viu en un sol dispositiu i no s'exporta. Canviar de dispositiu = reimportar la config i regenerar la identitat (ADR 0007, 0016). L'anti-replay és un comptador estrictament creixent per emissor: `counter ≤ max_counter → Replay`; `counter > max_counter → acceptar`. Sense finestra ni bitmap. El servidor assigna `received_at` estrictament creixent per procés, de manera que l'ordre de lliurament és total. L'emissor reserva i persisteix el comptador abans d'emetre el blob, i drena la seva `outbox` en ordre.

## Alternatives descartades
- Mantenir la finestra i afegir `first_counter` per peer (rebutjar tot comptador anterior al primer acceptat): funciona, però manté 512 B d'estat per peer, dos codis d'error i l'exportació d'identitat amb els seus modes de fallada.
- Mantenir l'exportació d'identitat: comoditat (conservar «Verificat» en canviar de mòbil) que la pròpia spec desaconsellava com a camí recomanat.

## Conseqüències
- El replay queda tancat també per a receptors sense estat previ d'un emissor (excepte el primer missatge que vegin d'ell, que fixa `max_counter`).
- Desapareixen: el bitmap, `Error::TooOld`, el format `PKEY`, la regla «+1 024», `export_identity`/`import_identity` de l'API, la segona contrasenya i la doble instal·lació com a mode de fallada.
- Si el client rep un missatge vàlid de la seva pròpia `pk` amb comptador ≥ el seu, la clau és en un altre lloc: avança el comptador i alerta l'usuari (`docs/spec.md` §4).
- Specs afectades: 012-message-keys, 021-channel-session, 025-identity-regen, 032-storage-ttl.
