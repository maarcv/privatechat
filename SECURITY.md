# Política de seguretat

## Abast

Tot el que hi ha en aquest repositori: `core`, `store`, `server`, els clients i el desplegament de referència a `deploy/`. El model d'amenaces, amb el que el sistema promet i el que no, és a [`docs/threat-model.md`](docs/threat-model.md). Una troballa que estigui dins de «Fora del model» o de «Limitacions assumides» és benvinguda com a discussió, però no és una vulnerabilitat.

## Com informar

**No obris una issue pública.** Fes servir el formulari privat de GitHub: *Security → Report a vulnerability* en aquest repositori. Inclou versió o commit, passos per reproduir-ho i l'impacte que hi veus.

Compromís: resposta inicial en 72 hores; avaluació i pla en 14 dies; publicació coordinada quan hi hagi correcció. Si la troballa afecta el servidor públic del projecte, es corregeix i es redesplega abans de publicar-la.

## Reconeixement

Qui informi d'una vulnerabilitat confirmada surt, si ho vol, a la nota de la versió que la corregeix i al registre d'auditoria de `docs/spec.md` §13.

## Revisió externa

El nucli criptogràfic està pendent de revisió externa abans de la beta (`docs/spec.md` §13, spec 061). Fins llavors, tracta el projecte com a experimental.
