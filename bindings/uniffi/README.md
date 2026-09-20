# uniffi bindings (Kotlin, Swift)

Spec 040-uniffi, phase 4.

- Only `Config`, `Channel` and `Session` cross the boundary, as opaque `Object`s; only
  `Received`, `Peer`, `Fingerprint`, `Gap` and `Event` are `Record`s (AGENTS 20). No key
  material ever crosses by value.
- Passwords are passed as bytes (`ByteArray`, `[UInt8]`) and zeroized on the UI side.
- The generated Kotlin and Swift sources go to `generated/` and are git-ignored; CI generates
  them and runs the vector tests on both languages.
