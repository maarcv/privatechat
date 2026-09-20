# 003 — Lint documental

Estat: en revisió
Fase: 0
ADR relacionades: —
Depèn de: 000, 002
Bloqueja: 010
Revisor humà: Marc Vilardebó · Acceptada el: —

## Context

La font de veritat d'aquest projecte són documents: `docs/spec.md`, les ADR, les specs, `AGENTS.md`. Un agent que llegeix un d'ells no pot ser enganyat per un altre que digui una cosa diferent. Les auditories B i C van trobar aquestes divergències a mà (taula d'amenaces duplicada, títols d'ADR no literals, rangs de specs desfasats, «per exemple» en lloc de valors). Aquesta spec les converteix en comprovacions mecàniques que corren a la CI.

## Requisits

- R1 La taula d'adversaris de `docs/threat-model.md` MUST ser byte a byte igual a la de `docs/spec.md` §2.
- R2 Cada ADR MUST coincidir en número, títol i estat entre el fitxer, `docs/adr/README.md` i `docs/spec.md` §3, tenir exactament les quatre seccions i numeració contínua (spec 002).
- R3 Tot identificador `NNN-nom` de spec referenciat a `docs/spec.md` (fora de §13), `AGENTS.md`, `README.md`, `CONTRIBUTING.md` o a qualsevol `specs/NNN-*.md` MUST aparèixer a la taula de `docs/spec.md` §10, i tot fitxer `specs/NNN-*.md` MUST estar-hi llistat.
- R4 `AGENTS.md` NO POT contenir cap rang de specs `NNN–NNN` (la llista viu només a §10).
- R5 Cap línia de la secció `## Requisits` d'una spec NO POT contenir «per exemple» ni «p. ex.»: els requisits porten valors fixos.
- R6 Si `docs/spec.md` canvia respecte al commit base de la PR, la capçalera `Versió: … · Actualitzat: AAAA-MM-DD` MUST haver canviat.
- R7 `specs/README.md` MUST contenir una taula `## Índex` amb una fila per fitxer `specs/NNN-*.md` (número, nom, fase, estat) coherent amb el fitxer, i l'estat de cada spec MUST ser un de `esborrany`, `en revisió`, `acceptada`, `implementada`.

## Límits

- El script només llegeix fitxers del repositori i, per R6, crida `git diff` i `git show` sobre el ref `DOC_LINT_BASE`. Sense aquesta variable, R6 no es comprova (execució local o primer commit).

## Interfície

```
# check_s003_t02_r02_adr_consistency = les tres funcions s002 executades en seqüència
scripts/doc_lint.sh            # exec python3 scripts/doc_lint.py
scripts/doc_lint.py            # una funció check_s003_tTT_rRR_* per requisit; exit 0/1; imprimeix cada fallada
DOC_LINT_BASE=<ref>            # opcional; commit base per a R6
```

## Seguretat

- No aplica. Només biblioteca estàndard de Python 3; cap dependència.

## Canvis d'API pública

- Cap.

## Casos de prova

- T01 (cobreix R1): `check_s003_t01_r01_threat_table_matches_spec`.
- T02 (cobreix R2): `check_s002_t01_r01_adr_files_follow_template`, `check_s002_t02_r02_adr_index_matches_files_and_spec` i `check_s002_t03_r03_adr_states_are_in_vocabulary` (spec 002, T01–T03), més `check_s003_t02_r02_adr_consistency` com a àlies de conjunt.
- T03 (cobreix R3): `check_s003_t03_r03_spec_refs_exist_in_plan`.
- T04 (cobreix R4): `check_s003_t04_r04_agents_has_no_spec_ranges`.
- T05 (cobreix R5): `check_s003_t05_r05_no_examples_in_requirements`.
- T06 (cobreix R6): `check_s003_t06_r06_spec_header_date_changes_with_content`.
- T07 (cobreix R7): `check_s003_t07_r07_specs_index_matches_files`.
- Negatius (manuals, una vegada, anotats a l'Historial): canviar una cel·la del threat-model → falla R1; canviar un títol a §3 → falla R2; afegir `- R9 … per exemple …` a una spec → falla R5.

## Vectors

- Cap.

## Criteri d'acceptació

`scripts/doc_lint.sh` retorna 0 sobre la branca `mvp`; cadascun dels tres negatius manuals retorna 1 amb el missatge que anomena el fitxer i la condició.

## Fora d'abast

- Lint de prosa o d'ortografia. Comprovació de mides o valors numèrics entre seccions de la spec (es fa a la revisió humana).

## Preguntes obertes

- [ ] 003-R3: les ADR queden fora de l'abast de R3 perquè citen com a història els noms de specs que han substituït. Convé incloure-les amb una llista d'excepcions? Proposta: no.

## Historial

- 2026-09-20 esborrany · 2026-09-20 en revisió
