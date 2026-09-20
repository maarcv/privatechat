# Model d'amenaces

Extracte de `docs/spec.md` §1, §2 i §6. La taula és una còpia literal de la de §2; si hi ha discrepància mana `spec.md` i el lint documental (spec 003) ho detecta.

## Adversaris i mitigacions

| Adversari | Què pot veure o fer | Com ho mitiguem |
| --- | --- | --- |
| Servidor honest-però-curiós | Quins `channel_id` s'escolten, des de quina IP, quan (cada connexió = l'usuari mira l'app), classe de mida (múltiples de 1 KiB) i freqüència dels blobs, política de retenció del canal, plataforma per empremta TLS | AEAD, padding a cubells de 1 KiB, capçalera xifrada (no veu qui escriu ni quant, ADR 0018), autenticació per clau de canal (no d'usuari), sense comptes, cap registre d'IP, `since` arrodonit, sense reanudació TLS, suport de proxy SOCKS5 / Tor / servei .onion |
| Servidor maliciós | A més: retenir blobs més enllà del TTL, esborrar o retardar blobs selectivament, ocultar oients, omplir el canal | TTL també al client, buits de comptador visibles al client, codi obert + builds reproduïbles, cap client amb codi servit pel servidor (ADR 0017) |
| Operador requisat o coaccionat (ordre de conservació o intercepció) | Activar el registre IP↔canal↔hora a partir de l'ordre | No mitigable pel protocol: el servidor no guarda IP a disc per disseny però pot ser obligat a fer-ho. Tor o servei .onion; autoallotjament |
| Proveïdor de hosting o xarxa del servidor | Netflow: IP↔servidor↔hora de tots els clients; mida del grup connectat pel ventall de `push` | Tor o servei .onion. Res més a la v1 |
| Observador de xarxa de l'usuari (ISP, wifi) | DNS/SNI del servidor, hora de cada connexió, mida i direcció de cada missatge (classe d'1 KiB; escriure vs llegir). No veu quin canal ni quin membre | TLS 1.3, una sola connexió (no revela el nombre de canals), Tor opcional. A la v1 no es rota `channel_id` ni s'afegeix tràfic de cobertura |
| Membre que opera el servidor autoallotjat | Tot el del servidor + tot el del membre: etiqueta↔IP↔hora de cada company | Es documenta: en autoallotjar, l'operador veu les IP dels membres. Tor si això importa |
| Atacant sense config | Crear canals i omplir el servidor de blobs | `publish` lligat a una subscripció autenticada a la mateixa connexió; quotes per connexió, per canal i globals; límits per IP només abans d'autenticar |
| Intrús amb la config filtrada (també un ex-membre, per sempre) | Llegir tot el canal (passat i futur); escriure com a clau nova; crear claus infinites; omplir el canal fins al TTL; reinjectar blobs antics a membres que no els van veure | Es detecta si escriu (apareix com a desconegut); límit de peers desconeguts amb evicció; la quota per canal protegeix el servidor, no el canal: l'única resposta és canal nou (ADR 0008). La lectura passiva no es pot evitar |
| Intrús amb la clau privada d'un membre | Suplantar-lo dins d'aquell canal; silenciar-lo | Retirada de clau (ADR 0016); alerta a la víctima quan es rep un missatge vàlid de la seva pròpia clau; regeneració de clau; canal nou |
| Replay d'un missatge capturat | Reinjectar un missatge antic | Comptador estrictament creixent per emissor (ADR 0019): tot comptador ja vist es rebutja; `channel_id` dins l'AAD i la signatura |
| Observador físic (càmera, espectador, Google Lens) | Capturar el QR d'invitació | QR efímer en pantalla amb captures bloquejades i «escaneja només amb aquesta app»; alternativa fitxer + contrasenya dita en veu; el QR de verificació no és secret |
| Furt del dispositiu bloquejat | Fitxers locals xifrats | `K_db` embolcallada al Keystore / Secure Enclave amb credencial del dispositiu; fitxers tancats i clau zeroïtzada en bloquejar |
| Coacció física | Requisa del dispositiu desbloquejat | Només limitació de danys: bloqueig immediat en apagar pantalla, PIN de dispositiu recomanat sobre biometria. Sense codi de coacció a la v1 |
| Anàlisi forense del dispositiu després d'esborrar | Recuperar versions antigues dels fitxers (snapshots del sistema de fitxers, còpies, flash) | La garantia criptogràfica cobreix tots els fitxers (`K_db` al Keystore/SE); l'esborrat d'un missatge dins del log és físic (compactació) i no resisteix còpies antigues. Es documenta |
| Membre deshonest | Reenviar, fer captures, demostrar autoria via signatures; conèixer hàbits horaris i estil dels altres | No mitigable. Es documenta |

## Fora del model

Malware al dispositiu, dispositiu rootejat o amb jailbreak, serveis d'accessibilitat maliciosos, atacs a la cadena de subministrament de les botigues d'apps, criptoanàlisi de les primitives, disponibilitat garantida del servidor.

## Limitacions assumides i documentades públicament

- No protegeix contra un dispositiu compromès ni contra un membre que reenviï.
- La confidencialitat de tot el canal depèn de `K_ch`: qui la tingui pot desxifrar qualsevol missatge del canal que hagi capturat, passat o futur, fins que es creï un canal nou. La v1 no té *forward secrecy* ni *post-compromise security* criptogràfiques (ADR 0013, 0004).
- Els missatges són autenticats però no negables.
- El servidor pot esborrar o retardar missatges; el client ho detecta parcialment (buits de comptador) però no ho pot impedir.
- Qui operi, allotgi o requisi el servidor sap des de quina IP i a quina hora escolta cadascú, i quan obres l'app. Sense Tor, una IP és una persona.
- Per defecte els canals nous van al servidor configurat a l'app, que a la instal·lació és el del projecte; qui no vulgui que aquest operador vegi les seves metadades el canvia a la configuració o en crear el canal.
- La botiga d'apps i el sistema operatiu saben que tens l'app instal·lada i quan la fas servir; altres apps poden detectar-la.
- A escriptori, dins la sessió de l'usuari qualsevol procés seu pot llegir els fitxers de dades i el keychain.
- Sense notificacions push a la v1 per no crear el mapa dispositiu↔canals al servidor.
- Si la filtració ve del dispositiu d'un membre, el canal nou tornarà a filtrar-se pel mateix camí.
- La quota per canal protegeix el servidor, no el canal: un intrús amb la config el pot deixar ple fins al TTL; l'única resposta és canal nou.
