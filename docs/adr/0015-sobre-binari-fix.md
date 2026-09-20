# ADR 0015 — Sobre binari de mida fixa; CBOR només al payload xifrat

Data: 2026-09-20 · Estat: acceptada

## Context
La primera versió definia el sobre de missatge com a «CBOR canònic» i la signatura «sobre tots els camps anteriors». `ciborium` no implementa el perfil determinista de la RFC 8949 §4.2, i «tots els camps anteriors» admet diverses serialitzacions: els bytes signats no estaven definits i els vectors de prova no serien reproduïbles per un tercer (troballa B2). Un sobre amb set camps, sis dels quals de mida fixa, no necessita CBOR.

## Decisió
El sobre és un format binari d'offsets fixos (`docs/spec.md` §4): `proto_version` (1) ‖ `channel_id` (16) ‖ `enc_hdr` (40: `sender_pk` ‖ `counter` u64 BE, xifrats segons ADR 0018) ‖ `nonce` (24) ‖ `ciphertext` (16 + 1 024·k) ‖ `signature` (64). L'AAD són els primers 81 bytes; la signatura, amb tag de domini, cobreix tot excepte ella mateixa (*encrypt-then-sign*). El CBOR queda només dins del payload xifrat i als missatges del protocol client-servidor, on la codificació exacta no és rellevant per a la seguretat.

## Alternatives descartades
- CBOR amb perfil determinista implementat a mà: més codi propi en el camí crític i cap avantatge per a un sobre de mida fixa.
- Protobuf o similar: dependència nova sense necessitat.
- *Sign-then-encrypt*: obligaria a desxifrar abans de rebutjar, i el receptor ha de poder descartar barat.

## Conseqüències
- Vectors de prova en hex complets a `specs/vectors/013.json`, verificables amb qualsevol implementació de libsodium.
- El servidor pot validar l'embolcall (longitud, versió, `channel_id`) sense parsejar res. No pot verificar la signatura (no veu `sender_pk`), i no cal.
- Mides: blob mínim 1 185 B, màxim 64 673 B; payload en clar màxim 64 511 B.
- La v2 és `proto_version = 2` amb capçal propi; no es reserven camps.
- Specs afectades: 013-wire-message, 015-test-vectors, 030-ws-protocol.
