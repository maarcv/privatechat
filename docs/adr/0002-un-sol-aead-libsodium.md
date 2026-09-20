# ADR 0002 — Un sol AEAD (XChaCha20-Poly1305) via libsodium

Data: 2026-09-19 · Estat: acceptada

## Context
La proposta inicial preveia xifrar cada missatge en n capes amb algoritmes diferents definits a la config del canal.

## Decisió
Cada missatge es xifra una sola vegada amb `crypto_aead_xchacha20poly1305_ietf` de libsodium (clau 32 B, nonce 24 B aleatori, tag 16 B). Cap altra primitiva criptogràfica al protocol ni al nucli `core`.

## Alternatives descartades
- Cascada de xifrats: no afegeix seguretat demostrable si el primer algoritme és segur, i multiplica els punts d'error (nonces, padding, modes sense autenticació).
- AES-256-GCM: equivalent en seguretat; XChaCha permet nonce aleatori de 24 B sense risc de col·lisió i no depèn d'acceleració hardware.
- Nonce derivat del comptador (estalvia 24 B): descartat a la revisió B (2026-09-20). Aquest disseny té un mode de fallada real de reutilització de clau de missatge (clonació o restauració de dispositiu, identitat importada dos cops); amb nonce aleatori la reutilització no filtra res, amb nonce derivat dona reutilització de keystream i falsificació.

## Conseqüències
- Una sola primitiva a auditar i a versionar (`proto_version`).
- La config del canal no porta cap paràmetre d'algoritme.
- L'abast «cap altra biblioteca criptogràfica» és el crate `core` i tot allò que toqui `K_ch`, `sk_u` o el format de cable. El servidor pot usar TLS (`rustls`) i els clients el Keystore / Secure Enclave de la plataforma per embolcallar `K_db`; cap d'ells implementa res del protocol. L'emmagatzematge local xifra amb el mateix libsodium (ADR 0021). Llista de crates prohibides a `AGENTS.md` regla 2 i a `deny.toml`.
