# Registre de decisions arquitectòniques

Una decisió per fitxer, plantilla a `TEMPLATE.md`. El lint documental (spec 003) comprova que aquesta taula, els fitxers i la taula de `docs/spec.md` §3 coincideixen en número, títol i estat.

## Procediment

- Una ADR acceptada no s'edita, excepte per canviar-ne l'estat. Per canviar una decisió es crea una ADR nova amb `Substitueix: NNNN` i l'antiga passa a `Estat: substituïda per MMMM`.
- Els números són seqüencials i no es reutilitzen.
- Estats: `proposada` · `acceptada` · `obsoleta` · `substituïda per NNNN`.
- Les ADR 0001–0022 es van escriure abans de crear el repositori i s'han revisat en tres auditories (`docs/spec.md` §13); per això algunes contenen notes de revisió al Context.

## Índex

| # | Títol | Data | Estat |
| --- | --- | --- | --- |
| 0001 | Clau de canal precompartida fora de banda | 2026-09-19 | acceptada |
| 0002 | Un sol AEAD (XChaCha20-Poly1305) via libsodium | 2026-09-19 | acceptada |
| 0003 | Ratchet simètric de hash sobre la clau de canal | 2026-09-19 | substituïda per 0013 |
| 0004 | Sense post-compromise security a la v1 | 2026-09-19 | acceptada |
| 0005 | Signatures Ed25519 per missatge, amb clau per usuari i per canal | 2026-09-19 | acceptada |
| 0006 | TOFU: cap llista de membres a la config | 2026-09-19 | acceptada |
| 0007 | Regeneració de clau lliure i sense enllaç amb l'antiga | 2026-09-19 | acceptada |
| 0008 | Sense expulsió de membres: es crea un canal nou | 2026-09-19 | acceptada |
| 0009 | TTL definit a la config, aplicat al servidor i al client | 2026-09-19 | acceptada |
| 0010 | Autenticació al servidor amb un parell Ed25519 de canal | 2026-09-19 | acceptada |
| 0011 | Alarma de compromís | 2026-09-19 | obsoleta |
| 0012 | Nucli criptogràfic i de protocol en Rust, compartit per tots els clients | 2026-09-19 | acceptada |
| 0013 | Clau de missatge derivada directament del comptador | 2026-09-20 | acceptada |
| 0014 | TTL lligat al `channel_id` i caducitat per missatge | 2026-09-20 | acceptada |
| 0015 | Sobre binari de mida fixa; CBOR només al payload xifrat | 2026-09-20 | acceptada |
| 0016 | Retirada de clau amb missatge `key_retired` | 2026-09-20 | acceptada |
| 0017 | Sense client web allotjat a la v1; client d'escriptori natiu | 2026-09-20 | acceptada |
| 0018 | Capçalera de missatge xifrada amb clau de canal | 2026-09-20 | acceptada |
| 0019 | Una clau, un dispositiu: comptador estrictament creixent | 2026-09-20 | acceptada |
| 0020 | Store i sessió sans-I/O al nucli Rust | 2026-09-20 | acceptada |
| 0021 | Client sense base de dades: fitxers xifrats amb commit atòmic | 2026-09-20 | acceptada |
| 0022 | Servidor d'intercanvi per canal, fixat en crear-lo | 2026-09-20 | acceptada |
