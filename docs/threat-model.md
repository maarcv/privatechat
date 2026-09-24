# Threat model

The table is a literal copy of the one in `docs/spec.md` §2; if there is a discrepancy `spec.md` prevails and the doc lint (spec 003) detects it. What the system promises and does not promise is the list in `docs/spec.md` §1, not repeated here.

## Adversaries and mitigations

| Adversary | What it can see or do | How we mitigate it |
| --- | --- | --- |
| Honest-but-curious server | Which `channel_id`s are being listened to, from which IP, when (each connection = the user looks at the app), how many connections and which channels share a device (same connection, or same IP and time), size class (multiples of 1 KiB) and frequency of the blobs, the channel's retention policy, platform by TLS fingerprint | AEAD, padding to 1 KiB buckets, encrypted header (it does not see who writes nor how much, ADR 0018), authentication by channel key (not by user), no accounts, no IP logging, rounded `since`, no TLS resumption, SOCKS5 proxy / Tor / .onion service support |
| Malicious server | In addition: retain blobs beyond the TTL, selectively delete or delay blobs, hide listeners, fill the channel | TTL also on the client, counter gaps visible to the client, open source + reproducible builds, no client with code served by the server (ADR 0017) |
| Seized or coerced operator (preservation or interception order) | Turn on IP↔channel↔time logging from the order onwards | Not mitigable by the protocol: the server does not store IPs on disk by design but can be compelled to. Tor or .onion service; self-hosting |
| Server's hosting or network provider | Netflow: IP↔server↔time of all clients; size of the connected group from the `push` fan-out | Tor or .onion service. Nothing else in v1 |
| User's network observer (ISP, wifi) | Server DNS/SNI, time of each connection, size and direction of each message (1 KiB class; write vs read). Does not see which channel or which member | TLS 1.3, one connection per server (does not reveal the number of channels on it), optional Tor. In v1 `channel_id` is not rotated and no cover traffic is added |
| Member who operates the self-hosted server | Everything the server sees + everything a member sees: label↔IP↔time of each fellow member | Documented: when self-hosting, the operator sees the members' IPs. Tor if that matters |
| Attacker without the config | Create channels and fill the server with blobs | `publish` bound to an authenticated subscription on the same connection; per-connection, per-channel and global quotas; per-IP limits only before authenticating |
| Intruder with the leaked config (also a former member, forever) | Read the whole channel (past and future); write as a new key; create endless keys; fill the channel until the TTL; re-inject old blobs to members who did not see them | Detected if it writes (it appears as unknown); limit on unknown peers with eviction; the per-channel quota protects the server, not the channel: the only answer is a new channel (ADR 0008). Passive reading cannot be prevented |
| Intruder with a member's private key | Impersonate them within that channel; silence them | Key retirement (ADR 0016); alert to the victim when a valid message from their own key is received; key regeneration; new channel |
| Replay of a captured message | Re-inject an old message | Strictly increasing counter per sender (ADR 0019): any counter already seen is rejected; `channel_id` inside the AAD and the signature |
| Physical observer (camera, onlooker, Google Lens) | Capture the invitation QR | Ephemeral on-screen QR with screenshots blocked and "scan only with this app"; alternative file + password spoken aloud; the verification QR is not secret |
| Theft of the locked device | Encrypted local files | `K_db` wrapped in the Keystore / Secure Enclave with the device credential; files closed and key zeroized on lock |
| Physical coercion | Seizure of the unlocked device | Damage limitation only: immediate lock when the screen turns off, device PIN recommended over biometrics. No duress code in v1 |
| Forensic analysis of the device after deletion | Recover old versions of the files (file-system snapshots, copies, flash) | The cryptographic guarantee covers all files (`K_db` in the Keystore/SE); deleting a message inside the log is physical (compaction) and does not resist old copies. Documented |
| Dishonest member | Forward, take screenshots, prove authorship via signatures; know the others' time habits and style | Not mitigable. Documented |

## Outside the model

Malware on the device, rooted or jailbroken device, malicious accessibility services, supply-chain attacks on the app stores, cryptanalysis of the primitives, guaranteed server availability.

## Accepted limitations

`docs/spec.md` §1 "What it does not promise" is the single list; every item there is public documentation, and the root `README.md` restates it in plain words.
