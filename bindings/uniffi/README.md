# uniffi bindings (Kotlin, Swift)

Spec 040-uniffi, phase 4.

- Opaque `Object`s and plain `Record`s cross the boundary (the boundary types are listed in
  `docs/spec.md` §9); no key material ever crosses by value (AGENTS 20).
- Passwords are passed as bytes (`ByteArray`, `[UInt8]`) and zeroized on the UI side.
- The generated Kotlin and Swift sources go to `generated/` and are git-ignored; CI generates
  them and runs the vector tests on both languages.
