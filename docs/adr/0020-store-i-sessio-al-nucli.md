# ADR 0020 — Store i sessió sans-I/O al nucli Rust

Data: 2026-09-20 · Estat: acceptada

## Context
La spec exigia persistir «missatge, estat anti-replay i cursor en una sola transacció», però l'emmagatzematge era un trait implementat a cada plataforma (Room a Android, GRDB a iOS, `rusqlite` a escriptori): tres codis diferents per a la mateixa transacció, cap test del nucli que la pogués demostrar, la clau de la BD convertida en `String` de JVM/Swift per al `PRAGMA key`, i tot l'estat (text en clar, peers, comptadors) creuant la frontera FFI a cada lectura. Alhora, l'API del nucli no exposava res per implementar el protocol de §6 (`ack`, cursor, paginació, `hello → subscribe → ok → push`): la màquina d'estats WebSocket s'hauria escrit tres vegades (revisió C, troballes C6 i C10). El veredicte del red team: «fallarà a l'estat, no a la criptografia».

## Decisió
1. **Un sol `Store`**, en Rust, al crate `store`, compartit per les tres plataformes. El trait té una única operació d'escriptura, `commit(WriteBatch)`, atòmica. Kotlin i Swift només desembolcallen la clau de 32 B, criden `open_store(path, key_bytes)` una vegada i zeroïtzen els seus bytes; no toquen mai l'emmagatzematge. `Channel` no té cap estat que no hagi passat per `commit`. Un directori, un procés. El format en disc el fixa l'ADR 0021 (la versió inicial d'aquesta ADR deia SQLCipher; substituït el mateix dia).
2. **Una `Session` sans-I/O** al nucli: `on_connect`, `on_frame(bytes) → Vec<Event>`, `outgoing() → Vec<bytes>`. Parseja `hello`/`ok`/`push`/`ack`/`error`, gestiona nonce, subscripcions, cursor i `outbox`, crida `decrypt` i notifica `acked`. La UI obre el socket TLS, passa frames en les dues direccions i reconnecta amb backoff quan rep `Event::Reconnect`.

## Alternatives descartades
- Store natiu per plataforma amb «integració idiomàtica» (Room, GRDB): tres transaccions, tres semàntiques de `BEGIN`, clau fora de Rust.
- SQLCipher via `rusqlite` en Rust: una sola implementació, però C + OpenSSL al client i una excepció permanent a la regla «només libsodium» (vegeu ADR 0021).
- Trait `KeyValue` genèric amb `put`/`get` separats: no pot expressar atomicitat entre missatge, comptador i cursor.
- Protocol WS implementat a cada client sobre una API plana del nucli: divergències quasi segures en reconnexió, paginació i dedupe.

## Conseqüències
- La transacció crítica existeix un cop i es prova un cop, incloent-hi un `FailingStore` que falla al commit *n* i comprova l'estat en reobrir.
- `store` és un crate separat de `core` perquè fa I/O (AGENTS 10); no porta cap dependència criptogràfica pròpia, usa `core::crypto`.
- La clau d'emmagatzematge `K_db` no surt mai de Rust un cop desembolcallada; s'exposa com a `Secret<32>`.
- Cap widget ni share extension a la v1 (un sol procés obre l'emmagatzematge).
- Specs afectades: 020-store-files (substitueix 020-store-trait), 021-channel-session, 027-core-api, 028-session-sans-io (nova).
