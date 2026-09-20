# Contribuir

Gràcies per llegir això abans de tocar res. El projecte té dues regles que ho governen tot: **infranquejable i simple**. Cada línia de codi hi ha de servir.

## Abans de començar

1. Llegeix [`AGENTS.md`](AGENTS.md) complet. Val per a persones i per a agents.
2. Llegeix [`docs/spec.md`](docs/spec.md) §3 (decisions), §4 (model criptogràfic) i la spec de la feature que vols tocar a `specs/`.
3. Llegeix [`.claude/skills/architecture/SKILL.md`](.claude/skills/architecture/SKILL.md) i la skill del teu llenguatge. Són l'estàndard de codi.

## Flux

spec escrita → revisió humana → tests en vermell → implementació → CI verda → revisió humana (+ ADR si cal) → merge.

- Si la spec no existeix, escriu-la primer amb `specs/TEMPLATE.md` i obre una PR només amb la spec.
- Cada requisit `R*` té un test `sNNN_tTT_rRR_*`. `scripts/check_requirements.sh` ho comprova.
- Cap canvi al format de cable, a la config, a les derivacions de claus ni als tags de domini sense una ADR nova a `docs/adr/` (plantilla a `docs/adr/TEMPLATE.md`).
- Una PR = una spec, ≤ 400 línies de diff net, títol `NNN: …`.

## Córrer la CI en local

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo deny check
scripts/doc_lint.sh
scripts/check_requirements.sh
```

Tot verd abans de cada commit. El missatge de commit comença per `NNN:`, `docs:`, `ci:`, `chore:` o `adr:` i està en català.

## Seguretat

No obris issues públiques per a vulnerabilitats. Vegeu [`SECURITY.md`](SECURITY.md).
