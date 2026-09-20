# ADR 0018 — Capçalera de missatge xifrada amb clau de canal

Data: 2026-09-20 · Estat: acceptada

## Context
Amb `sender_pk` i `counter` en clar al sobre, i `publish` lligat a la subscripció autenticada de la connexió (§6), el servidor obtenia per a cada missatge `(channel_id, sender_pk, counter, mida, hora, IP)`: un pseudònim perfecte i permanent per membre, lligat a una IP. Podia comptar escriptors, veure l'activitat i l'horari de cadascun, detectar regeneracions de clau (pk antiga calla, pk nova neix amb `counter = 0` des de la mateixa IP) i censurar un membre concret. Un disc requisat contenia fins a 30 dies d'aquest registre. La frase «el servidor no la pot lligar a res» era falsa (revisió C, troballa C1).

## Decisió
Els 40 bytes `sender_pk ‖ counter` del sobre es xifren amb `crypto_stream_xchacha20_xor` sota `K_hdr = KDF(K_ch, "chhdr___")`, compartida per tots els membres, usant el mateix `nonce` aleatori del sobre. La mida del blob no canvia; els offsets no canvien; l'AAD segueix sent `blob[0..81]` tal com viatja. El receptor desxifra la capçalera en un pas i segueix el mateix flux de verificació (§4). La capçalera no té autenticació pròpia: la signatura cobreix el blob complet, i una capçalera desxifrada amb una `K_hdr` incorrecta dona una `pk` aleatòria amb la qual la signatura falla.

## Alternatives descartades
- Deixar `sender_pk` en clar i documentar-ho: cost zero, però el servidor conserva el registre pseudònim↔IP.
- Identificador d'emissor rotatiu derivat de `K_send` i `counter`: el receptor necessita una taula `tag → (peer, counter)` o cerca lineal, i un format alternatiu per al primer missatge d'una `pk` desconeguda. Dos formats, més estat, més fuzzing.
- Prova de desxifrat per peer (trial decryption): innecessària, perquè tots els membres tenen `K_ch` i una sola clau compartida desxifra la capçalera.

## Conseqüències
- El servidor veu `channel_id`, la classe de mida, l'hora i la IP de la connexió. No sap qui escriu, quants escriuen, ni quant. Un disc requisat tampoc.
- Zero canvis al servidor (no parsejava `sender_pk`). No pot verificar la signatura del sobre, i no cal: `publish` ja va lligat a la subscripció.
- Un context KDF més (`chhdr___`) i un `crypto_stream_xchacha20_xor` de 40 B per missatge.
- Col·lisió de `nonce` sota `K_hdr` entre dos missatges del canal (2^-192) filtraria el XOR de dues capçaleres; negligible.
- Amb IP domèstica fixa la IP segueix sent un pseudònim sorollós; amb CGNAT o Tor el servidor deixa de tenir res per membre.
- Specs afectades: 012-message-keys, 013-wire-message, 015-test-vectors.
