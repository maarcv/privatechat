# privatechat — xat de grup privat i simple

Un xat de grup xifrat punt a punt on el servidor és només una bústia: no té comptes, no coneix identitats i no pot llegir res. L'accés a un canal es dona compartint una config fora de banda (QR en persona o fitxer xifrat amb contrasenya). Clients d'escriptori, Android i iOS sobre un mateix nucli criptogràfic en Rust. Codi obert: qualsevol pot desplegar el servidor, i cada canal viu al servidor que va triar qui el va crear.

**Estat:** fase 0 (fundació), branca `mvp`. Encara no hi ha res que es pugui fer servir.

## El que promet

- Ni el servidor ni ningú a la xarxa pot desxifrar els missatges.
- Els missatges caducats s'esborren al servidor i al client segons el TTL del canal.
- Cada missatge està autenticat: el receptor sap que ve de la mateixa clau que ja havia etiquetat.
- Cap identitat global: la clau d'un usuari és diferent a cada canal.
- El servidor no sap qui escriu: veu blobs opacs per canal, no per membre.

## El que no promet

- No protegeix contra un dispositiu compromès ni contra un membre que reenviï.
- La confidencialitat de tot el canal depèn de la clau del canal: qui la tingui pot llegir-ho tot, passat i futur, fins que es creï un canal nou. La v1 no té *forward secrecy* ni *post-compromise security*.
- Els missatges són autenticats però no negables.
- El servidor pot esborrar o retardar missatges; el client ho detecta parcialment però no ho pot impedir.
- Qui operi, allotgi o requisi el servidor sap des de quina IP i a quina hora escolta cadascú. Sense Tor, una IP és una persona.
- Per defecte els canals nous van al servidor configurat a l'app; qui no vulgui que aquest operador vegi les seves metadades el canvia.

La llista completa, el model d'amenaces i totes les decisions són a [`docs/spec.md`](docs/spec.md), [`docs/threat-model.md`](docs/threat-model.md) i [`docs/adr/`](docs/adr/README.md).

## Com està fet

- `core/` — criptografia (libsodium), format de cable, sessió. Sense I/O ni rellotge.
- `store/` — emmagatzematge local: fitxers xifrats amb commit atòmic. Sense base de dades.
- `server/` — bústia amb TTL sobre WebSocket. Un binari, SQLite, cap secret.
- `clients/` — escriptori (Tauri), Android (Kotlin), iOS (Swift): capes fines sobre el nucli.

El desenvolupament segueix specs (`specs/`) escrites abans del codi, amb tests que citen cada requisit. Vegeu [`CONTRIBUTING.md`](CONTRIBUTING.md) i [`AGENTS.md`](AGENTS.md).

## Llicència

[MIT](LICENSE).
