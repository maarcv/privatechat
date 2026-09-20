# ADR 0016 — Retirada de clau amb missatge `key_retired`

Data: 2026-09-20 · Estat: acceptada

## Context
L'escenari que motiva regenerar una clau (sospita de còpia, dispositiu perdut) és exactament aquell en què algú més té `sk_u`. Amb ADR 0007 tal com estava, en regenerar la clau els altres membres conservaven el peer antic com a etiquetat o verificat: el lladre podia seguir escrivint com a «Alice ✓» mentre l'Alice real apareixia com a desconeguda, i la seva alarma de compromís des de la clau nova era «de desconegut» i no bloquejava (troballa B7). No hi havia cap mecanisme de retirada.

## Decisió
Nou tipus de payload `key_retired`, amb cos buit, signat amb la clau que es retira. El receptor marca el peer com a **Retirada**: conserva l'etiqueta com a «Alice (clau retirada el DD/MM)» i rebutja qualsevol missatge d'aquesta `pk` rebut després de la retirada, sigui quin sigui el seu comptador. Els registres `(pk, retired_at)` no es purguen mai (revisió C: purgar-los passat el TTL permetia que la clau morta ressuscités com a desconeguda nova). «Regenerar la meva clau» envia `key_retired` amb l'antiga si encara la té i després l'esborra. Si s'ha perdut, la UI ho diu i cada peer té l'acció manual «Marcar aquesta clau com a retirada». No hi ha cap enllaç entre la clau retirada i la nova (coherent amb ADR 0007).

## Alternatives descartades
- Cap mecanisme: la clau robada queda vàlida fins que cada membre l'esborra a mà, sense que res els ho indiqui.
- Canvi de clau signat apuntant a la nova: descartat a ADR 0007 (rastre entre identitats; no serveix si s'ha perdut la clau).
- Retirar per alarma de compromís: una alarma la pot emetre també el lladre; la retirada explícita és una acció diferent i sense ambigüitat.

## Conseqüències
- Un lladre que tingui `sk_u` també pot emetre `key_retired` de la víctima: l'efecte és tancar la clau, que és el que la víctima voldria. No pot revertir-la. Si el client rep un `key_retired` de la seva pròpia clau, el canal queda en només lectura fins a regenerar.
- `regenerate_identity` escriu el `key_retired` a `outbox` al mateix commit que esborra la clau antiga; així no es perd si la UI és fora de línia.
- Estat nou al diagrama de peers i columna `retired_at` (`docs/spec.md` §7).
- El tipus s'afegeix a l'enum de la v1 abans de congelar el format (spec 013).
- Specs afectades: 022-peers-tofu, 024-key-retired, 025-identity-regen, 055-verify-ui.
