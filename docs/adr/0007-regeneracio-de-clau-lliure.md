# ADR 0007 — Regeneració de clau lliure i sense enllaç amb l'antiga

Data: 2026-09-19 · Estat: acceptada

## Context
Un usuari pot voler canviar la seva clau d'un canal (nou mòbil, sospita de còpia). Es va considerar anunciar el canvi signat amb la clau antiga per mantenir l'etiqueta.

## Decisió
L'usuari pot regenerar la clau d'un canal quan vulgui, sense cap missatge d'enllaç entre la clau antiga i la nova. Reapareix com a desconegut i els altres membres l'han de tornar a etiquetar i verificar. La clau antiga, si encara es té, es retira amb `key_retired` (ADR 0016), que tanca l'antiga sense apuntar a la nova.

## Alternatives descartades
- Canvi de clau signat amb l'antiga apuntant a la nova: manté la continuïtat automàticament, però requereix tenir la clau antiga (no serveix si s'ha perdut el dispositiu) i deixa un rastre entre claus.

## Conseqüències
- Simplicitat i cap enllaç entre identitats.
- Cost d'UX: re-verificació manual. Es mitiga amb una UI de «desconegut» molt visible, pre-verificació per QR i etiquetes no reutilitzables sense verificar (§7).
- Risc social: «he canviat de mòbil» com a vector de suplantació. Mitigat a §7.
- No hi ha exportació de la clau privada: una clau viu en un sol dispositiu (ADR 0019). Canviar de dispositiu = reimportar la config i regenerar.
