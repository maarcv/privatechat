# ADR 0010 — Autenticació al servidor amb un parell Ed25519 de canal

Data: 2026-09-19 · Estat: acceptada

## Context
Per subscriure's a un canal per WebSocket cal demostrar alguna cosa al servidor sense crear comptes ni revelar identitats d'usuari. Revisió A1 (2026-09-19): la proposta prèvia a aquesta ADR, `HMAC(K_auth, nonce)` amb un token compartit, es va descartar abans de crear el repositori perquè obligava el servidor a conèixer i guardar `K_auth`; no té ADR pròpia.

## Decisió
El client deriva un parell Ed25519 **del canal** a partir de `K_ch` (`docs/spec.md` §4). En connectar, el servidor envia un `server_nonce`; el client envia `pk_ch`, `ttl_seconds` i una signatura amb `sk_ch` sobre un missatge amb tag de domini que inclou el nonce, el `channel_id`, el TTL i el nom d'amfitrió del servidor (§6). El servidor recalcula `channel_id` a partir de `(pk_ch, ttl_seconds)` i verifica la signatura.

## Alternatives descartades
- HMAC amb token compartit: el servidor ha de guardar un secret per canal i cal un pas de registre.
- Autenticar amb la clau Ed25519 de l'usuari: donaria al servidor el mapa complet de quina clau és a quins canals.
- Comptes clàssics: incompatible amb l'objectiu de zero coneixement d'identitats.

## Conseqüències
El que la signatura protegeix, exactament:
- (a) Qui no té la config no pot subscriure's (veure blobs, classes de mida, horaris) ni publicar.
- (b) El servidor no guarda cap secret ni cap taula de canals: `channel_id` autocertificant, estat zero, cap registre previ; un canal «existeix» mentre té missatges no caducats o subscriptors.
- (c) La credencial **no és reutilitzable** per qui la vegi: servidor, proxy TLS, logs o un bolcat de la BD del servidor no permeten subscriure's. Un token portador derivat de `K_ch` seria més simple però perdria això, i faria dependre la seguretat de la disciplina de logs del proxy.
- (d) `host` dins la signatura impedeix que un servidor rellevi una subscripció cap a un altre desplegament amb la mateixa config.

Altres:
- Tots els membres comparteixen `sk_ch`: la signatura demostra tenir la config, no qui és; per això `publish` es lliga a la subscripció de la connexió i hi ha quotes (§6).
- El client no envia `channel_id` a `subscribe`: el servidor el recalcula i el retorna a `ok`.
- Revisió C (2026-09-20): es va avaluar substituir-ho per un token portador i es va mantenir per (c) i (d).
