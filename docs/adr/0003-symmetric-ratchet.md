# ADR 0003 — Symmetric hash ratchet over the channel key

Date: 2026-09-19 · Status: superseded by 0013

## Context
Encrypting directly with `K_ch` means that whoever obtains the device today can decrypt every old message they have captured.

## Decision
Each sender maintains a key chain derived from `K_ch` and its public key, advanced by hash on every message; consumed keys are erased.

## Alternatives considered
- Static key: no forward secrecy.
- Double Ratchet (DH + symmetric): requires online key agreement between peers; incompatible with ADR 0001.

## Consequences
- **Review B (2026-09-20, finding B1): the decision did not achieve what it intended.** The root of each chain is derived from `K_ch` and `pk_u` (in the clear on the wire); whoever obtains the device has `K_ch` and recomputes any key in the chain. Erasing consumed keys protects nothing. The ratchet only added state, a skipped-keys window, a skip limit and counter export, with no security gain. See ADR 0013.
