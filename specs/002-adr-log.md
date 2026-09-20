# 002 — Registre de decisions arquitectòniques

Estat: en revisió
Fase: 0
ADR relacionades: totes
Depèn de: 000
Bloqueja: 003
Revisor humà: Marc Vilardebó · Acceptada el: —

## Context

Les 22 ADR de `docs/adr/` són el context històric de cada decisió i la barrera contra canvis silenciosos (AGENTS 3). Perquè serveixin, han de tenir un format únic, un índex que coincideixi amb la taula de `docs/spec.md` §3 i un vocabulari d'estat tancat, i cal que una màquina ho comprovi. Aquesta spec fixa el format i el procediment; la comprovació la implementa la spec 003.

## Requisits

- R1 Tota ADR MUST viure a `docs/adr/NNNN-<kebab>.md`, amb `NNNN` seqüencial sense forats ni reutilització, i seguir `docs/adr/TEMPLATE.md`: primera línia `# ADR NNNN — Títol`, tercera línia `Data: AAAA-MM-DD · Estat: <estat>[ · Substitueix: NNNN]`, i exactament les seccions `## Context`, `## Decisió`, `## Alternatives descartades`, `## Conseqüències`, en aquest ordre.
- R2 `docs/adr/README.md` MUST contenir una taula `## Índex` amb una fila per ADR (número, títol literal, data, estat) idèntica en número, títol i estat a la taula de `docs/spec.md` §3 i als fitxers.
- R3 L'estat MUST ser un de `proposada`, `acceptada`, `obsoleta`, `substituïda per NNNN`.
- R4 Una ADR acceptada NO POT editar-se excepte per canviar-ne l'estat; canviar una decisió MUST fer-se amb una ADR nova amb `Substitueix: NNNN` i l'antiga passa a `substituïda per MMMM`. Excepció documentada al README: les ADR 0001–0022, escrites abans del repositori, porten notes de revisió al Context.
- R5 Tot canvi al format de cable, a la config del canal, als tags de domini o a les derivacions de claus MUST anar acompanyat d'una ADR nova (AGENTS 3); la CI ho fa complir (spec 001, R8).

## Límits

- Títol ≤ 80 caràcters. Cap fórmula dins d'una ADR: referència a `docs/spec.md` §4.

## Interfície

- `docs/adr/TEMPLATE.md` — plantilla.
- `docs/adr/README.md` — procediment i índex.
- Comprovació mecànica: `check_s002_t01_r01_*`, `check_s002_t02_r02_*`, `check_s002_t03_r03_*` a `scripts/doc_lint.py`.

## Seguretat

- No aplica directament; és el registre que evita que una decisió de seguretat canviï sense revisió humana.

## Canvis d'API pública

- Cap.

## Casos de prova

- T01 (cobreix R1): `check_s002_t01_r01_adr_files_follow_template` valida primera línia, tercera línia, les quatre seccions i la numeració contínua.
- T02 (cobreix R2): `check_s002_t02_r02_adr_index_matches_files_and_spec` compara fitxers ↔ índex ↔ §3 (número, títol, estat).
- T03 (cobreix R3): `check_s002_t03_r03_adr_states_are_in_vocabulary`.
- T04 (cobreix R4): revisió humana a la PR; ítem `s002_t04_r04_accepted_adr_only_state_changes` de la plantilla de PR. Sense comprovació mecànica a la v1.
- T05 (cobreix R5): pas `s001_t08_r08_protected_paths_require_adr` de la CI, anotat també com `s002_t05_r05_format_changes_need_adr`.

## Vectors

- Cap.

## Criteri d'acceptació

`scripts/doc_lint.sh` verd amb les 22 ADR actuals; una ADR de prova amb una secció de menys fa fallar el lint.

## Fora d'abast

- Generar l'índex automàticament: es manté a mà i es comprova.

## Preguntes obertes

- [ ] 002-R4: convé un script que detecti diffs a ADR acceptades fora de la línia d'estat? Proposta: sí, a la fase 1 si es demostra necessari.

## Historial

- 2026-09-20 esborrany · 2026-09-20 en revisió
