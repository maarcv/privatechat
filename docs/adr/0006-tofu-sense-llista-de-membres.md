# ADR 0006 — TOFU: cap llista de membres a la config

Data: 2026-09-19 · Estat: acceptada

## Context
Es podria incloure a la config la llista de claus públiques autoritzades i rebutjar tot el que no vingui d'elles.

## Decisió
La config no porta membres. Quan arriba una clau pública nova, el client la mostra com a «desconegut»; l'usuari l'etiqueta i, opcionalment, la verifica comparant el fingerprint per un altre canal (Trust On First Use). A partir d'aquí el client garanteix la continuïtat: la mateixa clau = la mateixa etiqueta. Les regles de presentació, de reutilització d'etiquetes i de límits són a `docs/spec.md` §7.

## Alternatives descartades
- Llista tancada a la config: un intrús amb la config quedaria rebutjat en silenci i ningú s'adonaria de la filtració; un canvi de dispositiu obligaria a redistribuir la config.

## Conseqüències
- Un intrús que escriu es fa visible.
- El moment zero és el punt feble: la UI ha de mostrar clarament l'estat «no verificat», no pot reutilitzar una etiqueta existent per a una clau no verificada, i ha de facilitar la pre-verificació per QR.
- Els desconeguts es poden col·lapsar i silenciar en bloc per defensar-se d'inundacions; hi ha un límit amb evicció (§7).
