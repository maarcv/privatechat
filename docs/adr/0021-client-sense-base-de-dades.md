# ADR 0021 — Client sense base de dades: fitxers xifrats amb commit atòmic

Data: 2026-09-20 · Estat: acceptada

## Context
L'ADR 0020 va concentrar l'emmagatzematge en un sol `Store` en Rust, però el format era SQLCipher: compilar C i OpenSSL per a Android i iOS, un crate separat només per aïllar OpenSSL de la regla «només libsodium», pragmes (`secure_delete`, `incremental_vacuum`, WAL, `busy_timeout`) i una frontera C que els fuzzers no travessen. L'estat d'un canal és petit (config, `sk_u`, comptador, cursor, ≤ 550 peers, `outbox`) més els missatges vius, que caduquen pel TTL; el client no fa cap consulta que necessiti SQL.

## Decisió
El client no porta cap base de dades. Per canal, un directori `<data_dir>/<channel_id hex>/` amb dos fitxers, tots dos xifrats amb `crypto_secretbox` sota `K_db` (32 B aleatoris, embolcallats al Keystore / Secure Enclave, `docs/spec.md` §8):

- `state.bin` = `"PSTA"` ‖ `version` u8 ‖ `nonce` 24 ‖ `secretbox(CBOR(state))`, on `state` = config, seed de `sk_u`, comptador d'enviament, cursor, peers, `outbox`, `log_committed_len` u64 i `log_generation` u32. Es reescriu **atòmicament** a cada commit: escriure `state.bin.tmp`, `fsync`, `rename` sobre `state.bin`, `fsync` del directori.
- `messages.log` = seqüència de registres `len` u32 BE ‖ `nonce` 24 ‖ `secretbox(CBOR(record))`, append-only; `record` = `received_at`, `expires_local`, `sender_pk`, `counter`, `server_id`, payload o marca `Unreadable`, propi o no.

Protocol de commit: (1) `append` dels registres nous al log + `fsync`; (2) escriptura atòmica de `state.bin` amb el nou `log_committed_len`. En obrir: llegir `state.bin`, truncar el log a `log_committed_len` (els bytes sobrants són d'un commit no acabat). Un registre corrupte **dins** de la longitud compromesa → `StoreError::Corrupt`; la recuperació és reimportar la config i regenerar la identitat. Purga per TTL = compactació: escriure `messages.log.new` sense els caducats, `state.bin` amb la nova longitud i `log_generation + 1`, `rename`. Es fa en obrir i en desbloquejar. Sortir del canal = esborrar el directori. Un fitxer `LOCK` (advisory) al `data_dir` impedeix dos processos. Límit del log: 64 MiB, igual que la quota per canal del servidor.

El servidor sí porta SQLite pla (sense xifrar: només blobs opacs, disc xifrat en repòs) via `rusqlite` amb `bundled`, sense `sqlx`.

## Alternatives descartades
- SQLCipher: madur, però C + OpenSSL al client, excepció permanent a AGENTS 2, i l'atomicitat depenia de la semàntica de `BEGIN` d'una biblioteca externa.
- Un sol fitxer per canal reescrit sencer a cada commit: trivialment atòmic, però reescriure fins a 64 MiB per missatge no és acceptable.
- Servidor sense SQLite (fitxers de log per canal o només memòria): viable, però canvia una dependència madura per codi propi sense cap guany de seguretat; memòria sola perd fins a 30 dies de missatges en reiniciar.

## Conseqüències
- Zero C fora de libsodium a tot el client. Desapareix el crate `store-sqlite`, l'excepció d'OpenSSL a `deny.toml`, i tota la configuració de SQLCipher.
- L'atomitat del `commit(WriteBatch)` surt del `rename` del sistema de fitxers: és el WAL mínim (~100 línies) i es prova amb `FailingStore` i amb un test que mata el procés entre els passos (1) i (2).
- El mateix `Secret<32>` i el mateix `secretbox` xifren estat i missatges; tot el camí és fuzzejable des de Rust.
- L'esborrat d'un registre és físic (compactació) igual que amb `secure_delete`; la garantia criptogràfica és la destrucció de `K_db`. Clau per canal per a esborrat criptogràfic de canal: v2 (`docs/spec.md` §12).
- El client carrega el canal en memòria (uns pocs MB); no hi ha consultes ni cerca a la v1.
- Specs afectades: 020-store-files, 023-ttl-purge, 025-identity-regen, 032-storage-ttl (servidor, `rusqlite`).
