# privatechat — private, simple group chat

An end-to-end encrypted group chat where the server is just a mailbox: it has no accounts, knows no identities and can read nothing. Access to a channel is granted by sharing a config out of band (a QR code in person or a password-encrypted file). Desktop, Android and iOS clients on top of one cryptographic core in Rust. Open source: anyone can deploy the server, and each channel lives on the server chosen by whoever created it.

**Status:** phase 0 (foundation), branch `mvp`. Nothing usable yet.

## What it promises

- Neither the server nor anyone on the network can decrypt the messages.
- Expired messages are deleted on the server and on the client according to the channel TTL.
- Every message is authenticated: the receiver knows it comes from the same key it had already labelled.
- No global identity: a user's key is different in every channel.
- The server does not know who writes: it sees opaque blobs per channel, not per member.

## What it does not promise

In plain words; the normative list is `docs/spec.md` §1.

- It does not protect against a compromised device or against a member who forwards.
- The confidentiality of the whole channel depends on the channel key: whoever has it can read everything, past and future, until a new channel is created. v1 has neither *forward secrecy* nor *post-compromise security*.
- Messages are authenticated but not deniable.
- The server can delete or delay messages; the client detects this partially but cannot prevent it.
- Whoever operates, hosts or seizes the server knows from which IP and at what time each person listens. Without Tor, an IP is a person.
- By default new channels go to the server configured in the app; anyone who does not want that operator to see their metadata can change it.
- The app store and the operating system know you have the app installed and when you use it; other apps can detect it.
- On desktop, within the user's session any of their processes can read the data files and the keychain.
- Reinstalling the app, restoring a backup or a hardware failure erases all local data; recovery is re-importing the config.

The threat model and every decision are in [`docs/spec.md`](docs/spec.md), [`docs/threat-model.md`](docs/threat-model.md) and [`docs/adr/`](docs/adr/README.md).

## How it is built

- `crates/core/` — cryptography (libsodium), wire format, session. No I/O, no clock.
- `crates/store/` — local storage: encrypted files with atomic commit. No database.
- `crates/server/` — mailbox with TTL over WebSocket. One binary, SQLite, no secrets.
- `clients/` — desktop (Tauri), Android (Kotlin), iOS (Swift): thin layers over the core.

Development follows specs (`specs/`) written before the code, with tests that cite every requirement. See [`.github/CONTRIBUTING.md`](.github/CONTRIBUTING.md) and [`AGENTS.md`](AGENTS.md).

## Licence

[MIT](LICENSE).
