# privatechat — private, simple group chat

An end-to-end encrypted group chat where the server is just a mailbox: it has no accounts, knows no identities and can read nothing. Access to a channel is granted by sharing a config out of band (a QR code in person or a password-encrypted file). Desktop, Android and iOS clients on top of one cryptographic core in Rust. Open source: anyone can deploy the server, and each channel lives on the server chosen by whoever created it.

**Status:** phases 0 to 2 closed (foundation, cryptographic core, session and local storage), branch `mvp`. Nothing usable yet: the server, the bindings and the apps come next.

## What it promises

- Neither the server nor anyone on the network can decrypt the messages.
- Expired messages are deleted on the server and on the client according to the channel TTL.
- Every message is authenticated: the receiver knows it comes from the same key it had already labelled.
- No global identity: a user's key is different in every channel.
- The server cannot tell by key which member writes: it sees opaque blobs per channel. It does see which connection sends each one, and without Tor its address: with or without Tor, messages sent over one connection come from one device and messages sent over two connections open at the same time on one channel come from two devices, so members online together are told apart.

## What it does not promise

In plain words; the normative list is `docs/spec.md` §1.

- It does not protect against a compromised device or against a member who forwards.
- The confidentiality of the whole channel depends on the channel key: whoever has it can read everything, past and future, until a new channel is created. v1 has neither *forward secrecy* nor *post-compromise security*.
- Messages are authenticated but not deniable.
- The server can delete or delay messages; the client detects this partially but cannot prevent it.
- The app judges when a message has expired by the device's clock. If that clock is more than a few minutes behind, a server can hand back messages that have already expired.
- Whoever operates, hosts or seizes the server knows from which IP and at what time each person listens, and when they open the app. Without Tor, an IP is a person.
- By default new channels go to the server configured in the app, which at installation is the project's; anyone who does not want that operator to see their metadata can change it.
- The app store and the operating system know you have the app installed and when you use it; other apps can detect it.
- On desktop, within the user's session any of their processes can read the data files and the keychain.
- Reinstalling the app, restoring a backup or a hardware failure erases all local data; recovery is re-importing the config. After losing every device, that needs a fresh invitation from a member who still has the channel. What comes back is the messages the server still holds; the names you gave others, your verifications and your own key do not.
- Two devices of one person are two members: each sees the other as an unknown key with the same name, to be labelled and verified like anyone else's.
- No push notifications in v1, so that no server or push provider stores a map of which channels each device follows.
- If the leak came from a member's device, a new channel will leak again by the same path.
- The per-channel quota protects the server, not the channel: someone with the config can keep the channel full until its messages expire; the only answer is a new channel.

The threat model and every decision are in [`docs/spec.md`](docs/spec.md), [`docs/threat-model.md`](docs/threat-model.md) and [`docs/adr/`](docs/adr/README.md).

## How it is built

- `crates/core/` — cryptography (libsodium), wire format, session. No I/O, no clock.
- `crates/store/` — local storage: encrypted files with atomic commit. No database.
- `crates/server/` — mailbox with TTL over WebSocket. One binary, SQLite, no secrets.
- `clients/` — desktop (Tauri), Android (Kotlin), iOS (Swift): thin layers over the core.

Development follows specs (`specs/`) written before the code, with tests that cite every requirement. See [`.github/CONTRIBUTING.md`](.github/CONTRIBUTING.md) and [`AGENTS.md`](AGENTS.md).

## Licence

[MIT](LICENSE).
