# ADR 0034 — Publish no stale `outbox` entry, and re-seal a pending `key_retired`

Date: 2026-09-24 · Status: accepted

## Context
`sent_at` is fixed when a blob is sealed, and since ADR 0027 and 0030 a blob published after `sent_at + ttl_ms + 360 000` is stale for every receiver and discarded as `Expired`, while the server still answers `ack`. The client connects only while unlocked, so in a 60-second channel a message left in the `outbox` for about seven minutes is lost, and the sender sees it as delivered. Audit H (`docs/audit-log.md`, H44) found that the case that matters most is a `key_retired` written by "Regenerate my key" while offline, the natural reaction to the own-key alert: it goes stale everywhere, the old key is never retired, and the old `sk_u` is already erased. ADR 0016's "it is not lost if the UI is offline" no longer held.

## Decision
The core never hands out an `outbox` entry whose `sent_at + ttl_ms + 360 000 < now`, and treats an `ack` whose `received_at` is more than `ttl_ms + 360 000` from `sent_at`, on either side, as a message not delivered: an ordinary message is removed and reported to the UI as not delivered, and a pending `key_retired` is sealed again, with a fresh `sent_at`, nonce and `ClientRef`, only when it is handed out in a later minute than its current copy, the core keeping the current copy's `ClientRef` and `sent_at` alone, for which the old `sk_u` is kept, used for nothing else, until an `ack` arrives in time, and then erased.

## Alternatives considered
- Exempting `key_retired` from the stale rule: a server could replay a retirement forever, and the stale rule would gain an exception readable before the type check.
- Re-sealing ordinary messages with a fresh `sent_at`: the message would claim a send time it did not have, and a new counter would be needed for each retry; reporting it as not delivered lets the user resend.
- Leaving it as it was: silent loss, and a retirement that fails exactly when it is needed.

## Consequences
- No message leaves the device already stale, and the `ack` is checked against the server's `received_at` on both sides, so a server clock ahead of or behind the sender's by more than the margin, or a slow publish, does not hide a loss behind an `ack`.
- The old `sk_u` outlives regeneration until its `key_retired` is acknowledged. A thief already holds it, so this gives him nothing; it is never used to write anything else, and the channel shows the user that the retirement is still pending.
- The re-sealed retirement keeps the counter of ADR 0033 with a fresh nonce, so no (`mk`, nonce) pair repeats. Its signature is not kept for the own-key echo: the old key is a retired peer from the regeneration commit on, so its echoes are `RetiredKey` at step 5, and the signatures of blobs sealed under it are dropped in that commit. A late `ack` only marks the current copy not delivered and an `ack` of an older copy changes nothing, so re-sealing happens at most once per minute of `sent_at` whatever the server answers.
- A retirement is a message like any other on the server: it expires with the TTL, so a member who does not connect within it never receives it and keeps the old key as valid. The regeneration warning says so and asks the user to have those members mark the key retired by hand (§7).
- Refines ADR 0016 (regeneration) and ADR 0027 (sources of loss). Affected specs: 020-store-files, 021-channel-session, 025-identity-regen.
