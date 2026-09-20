# ADR 0014 — TTL lligat al `channel_id` i caducitat per missatge

Data: 2026-09-20 · Estat: acceptada

## Context
El servidor ha de saber quan esborrar cada blob sense guardar cap secret ni cap taula de canals. La regla inicial («si arriben TTL diferents pel mateix `pk_ch`, guanya el menor») permetia a qualsevol persona amb la config —membre o intrús— fixar `ttl = 60 s` i destruir la retenció de tot el canal per a tothom, de forma gratuïta, indistingible i irreversible (troballa B5). A més, la taula `channels` creada implícitament no s'esborrava mai.

## Decisió
`channel_id = BLAKE2b("privatechat/chid/v1" ‖ pk_ch ‖ BE32(ttl_seconds))[0..16]`. El TTL forma part de la identitat del canal: un TTL diferent és un canal diferent on ningú escolta. El servidor recalcula `channel_id` a partir de `(pk_ch, ttl_seconds)` rebuts a la subscripció signada, comprova el rang, i per a cada `publish` guarda `expires_at = received_at + ttl_seconds`. No hi ha taula de canals; un canal existeix mentre té missatges no caducats o subscriptors.

## Alternatives descartades
- TTL per canal amb «guanya el menor»: DoS trivial.
- TTL per canal amb «guanya el primer»: un servidor maliciós pot fingir un primer TTL; els clients no ho poden verificar.
- TTL per missatge segons la subscripció de qui publica, sense lligar-lo al `channel_id`: evita el DoS, però permet que un membre amb un client modificat retingui els seus missatges al servidor més temps del que el canal ha acordat.

## Conseqüències
- Cap membre pot canviar el TTL d'un canal existent; canviar-lo és crear un canal nou (coherent amb ADR 0008).
- El servidor només té una taula, `messages`, amb índex per `expires_at`.
- El client segueix aplicant la seva pròpia caducitat (`min(received_at, now_local) + ttl_seconds`), ADR 0009.
- Specs afectades: 011-config-format, 031-auth-channel-signature, 032-storage-ttl.
