# ADR 0022 — Servidor d'intercanvi per canal, fixat en crear-lo

Data: 2026-09-20 · Estat: acceptada

## Context
El projecte és de codi obert i qualsevol podrà desplegar el servidor. La config del canal ja portava `server_url` (§5), però §6 assumia «una sola connexió per dispositiu» i `Session` prenia un sol `host`, i no es deia com es tria el servidor en crear un canal ni si es pot canviar després.

## Decisió
Cada canal viu en un sol servidor, el que tria qui el crea. El formulari de creació prefixa el `default_server_url` de la configuració de l'app —a la instal·lació, la constant de compilació `DEFAULT_SERVER_URL`, el servidor del projecte— i l'usuari pot canviar tant el valor per defecte de l'app com el del canal en aquell moment. Un canal creat no canvia de servidor ni de cap altra dada bàsica (`K_ch`, TTL): canviar-ne una és crear un canal nou (ADR 0008). El client manté una connexió i una `Session` per servidor; un dispositiu amb canals a N servidors té N connexions.

## Alternatives descartades
- Un sol servidor per dispositiu: obligaria tot el grup a acceptar l'operador d'un membre; incompatible amb canals rebuts per invitació.
- Canvi de servidor en calent (editar `server_url` localment): membres amb `server_url` diferent deixarien de veure's sense cap error; importar una config amb el mateix `channel_id` i servidor diferent ja dona `ConfigMismatch` (§5).
- `host` dins del `channel_id`: un canvi de DNS o de port mataria el canal; el `host` ja va dins la signatura d'autenticació (ADR 0010), que és on protegeix.
- Cap servidor per defecte: fricció a cada creació; el projecte pot operar-ne un i qui no el vulgui el canvia.

## Conseqüències
- La UI agrupa canals per `host` i obre un socket per grup; `Session::new(host, channels)`.
- `settings.bin` al `data_dir` (`default_server_url`, `lock_timeout`, proxy), mateix format que `state.bin` (ADR 0021).
- Cap URL de servidor al codi fora de `DEFAULT_SERVER_URL`; cada *fork* hi posa la seva.
- El servidor del projecte concentra les metadades de qui no canvia el defecte; es diu a §1 «El que no promet». Cada servidor només veu els canals que hi viuen.
- `deploy/README.md` documenta com desplegar un servidor propi (spec 034/035).
- Specs afectades: 000-repo-layout, 020-store-files, 028-session-sans-io, 034-docker, 035-server-ops, 050–052 (formulari de creació).
