# ADR 0011 — Alarma de compromís

Data: 2026-09-19 · Estat: obsoleta

## Context
Si un membre veu un missatge signat amb la seva clau que no ha escrit, o sospita que la config s'ha filtrat, cal que la resta ho sàpiga de seguida.

## Decisió
Missatge de tipus `compromise_alert` amb motiu (`config_leaked`, `key_stolen`, `other`) i nota, signat com qualsevol altre. El client el mostra com un banner vermell fix amb l'emissor i el motiu, passa el canal a només lectura fins que l'usuari ho accepta i ofereix «Sortir del canal». Les regles d'agrupació, límits i el comportament de «Sortir del canal» són a `docs/spec.md` §7.

## Alternatives descartades
- Cap mecanisme: la reacció dependria de que algú ho digués per un altre canal.

## Conseqüències
- **Revisió C (2026-09-20): retirada de la v1.** Un tipus de missatge separat afegia una màquina d'estats d'UI (banner, només lectura, un cop per 24 h, agrupació, silenciar), una nota de text lliure dins d'un banner del sistema (vector de phishing) i la possibilitat que un lladre amb `sk_u` bloquegés el canal amb el nom d'una víctima verificada. L'únic acte amb semàntica de protocol és la retirada de clau (ADR 0016); «la config s'ha filtrat, canal nou» és text normal. La detecció de clau robada la fa el receptor de la pròpia clau (`docs/spec.md` §4 «Missatges de la pròpia clau»). Es pot reintroduir a la v1.x com a clau CBOR nova si l'ús ho demana.
- No dona deniabilitat (una signatura vàlida segueix demostrant que el titular de la clau va escriure el missatge); és una eina de reacció, no de negació.
- Una alarma prova que la té qui té la clau, no qui és la persona: un lladre de clau també pot emetre'n. L'acció correcta és sempre verificar fora de banda.
- Les alarmes de desconeguts no bloquegen i s'agrupen; les d'un mateix emissor només bloquegen un cop per 24 h (defensa contra spam i bloqueig social).
- Una alarma `key_stolen` enllaça amb la retirada de clau (ADR 0016) i amb el canal nou (ADR 0008).
