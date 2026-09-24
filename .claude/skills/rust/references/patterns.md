# Rust patterns used in this repository

These are the shapes the spec assumes. Reuse them; do not invent parallel ones.
These shapes are written to pass the workspace lints; when the implementing
spec lands, the real code supersedes the snippet and is re-checked against it.

Contents:
1. `Secret<N>` — key material
2. Fixed-offset parsing — the wire envelope (§4)
3. `Store` trait and `WriteBatch` — one commit per operation
4. Sans-I/O `Session`
5. Encrypt: reserve before you emit
6. Test vector loader

## 1. `Secret<N>` — the only home for key material

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Fixed-size secret. Never `Clone`, `Default`, `Copy` or `PartialEq` by
/// derive; never printed. `docs/spec.md` §8 "Logging", AGENTS 5.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Secret<const N: usize>([u8; N]);

impl<const N: usize> Secret<N> {
    pub(crate) fn from_bytes(bytes: [u8; N]) -> Self { Self(bytes) }
    pub(crate) fn expose(&self) -> &[u8; N] { &self.0 }
}

impl<const N: usize> core::fmt::Debug for Secret<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<const N: usize> PartialEq for Secret<N> {
    fn eq(&self, other: &Self) -> bool { crate::crypto::ct_eq(&self.0, &other.0) }
}
```

Every secret type is listed in `crypto::SECRET_TYPES` and covered by
the redacted-`Debug` test of spec 010, which formats each with `{:?}` and asserts
the exact string.

## 2. Fixed-offset parsing (`docs/spec.md` §4 envelope)

Conventions this pattern fixes, so you do not have to decide them again:

- **Every offset and length is a named constant** with a doc comment pointing
  at §4. Derived constants (`MIN_BLOB = BLOB_OVERHEAD + PAD_BLOCK`) are
  preferred over literals, and one test pins them to the spec's literals
  (1 185, 64 673) so a wrong derivation cannot hide.
- **Step 1 of "Verification on receive" is three conditions with three
  variants**, checked in order: 1a length class → `BadLength`, 1b version →
  `UnsupportedVersion`, 1c channel → `WrongChannel`. The spec writes them as
  one numbered step; the skills label them 1a/1b/1c so tests can name them.
- **1c lives inside the parser**, which therefore takes the expected
  `ChannelId`. The signature is `Envelope::parse(blob, &channel_id)`, not
  `TryFrom<&[u8]>` (which cannot carry the channel).
- **No bare `-`, `%` or indexing**, even where a previous check makes them
  safe: `checked_sub` and `is_multiple_of` cost nothing and keep the lint
  list honest. A `get` that "cannot fail" after validation still maps to
  `BadLength` rather than `unwrap` — that is the convention for
  impossible-after-validation failures.
- **Borrowing views with a lifetime are fine here** because `Envelope` is
  `pub(crate)`; the "no lifetimes on public `core` types" rule is about the
  FFI surface.
- The parser exposes `aad` (`blob[0..81]`) and `signed_bytes`
  (`blob[0..len-64]`) so the offsets exist exactly once; the caller never
  re-slices.

```rust
/// Wire protocol version 1 (§4).
pub(crate) const PROTO_V1: u8 = 0x01;
/// Byte ranges of the fixed header (§4 envelope table).
pub(crate) const CHANNEL_ID_RANGE: core::ops::Range<usize> = 1..17;
/// `enc_hdr` = encrypted `sender_pk ‖ counter` (§4, ADR 0018).
pub(crate) const ENC_HDR_RANGE: core::ops::Range<usize> = 17..57;
/// AEAD nonce (§4).
pub(crate) const NONCE_RANGE: core::ops::Range<usize> = 57..81;
/// Fixed header length = AAD length (§4).
pub(crate) const HEADER_LEN: usize = 81;
/// Ed25519 signature length.
pub(crate) const SIG_LEN: usize = 64;
/// Poly1305 tag length.
pub(crate) const TAG_LEN: usize = 16;
/// Padding block (§4 payload).
pub(crate) const PAD_BLOCK: usize = 1024;
/// Everything in a blob that is not padded payload: header + tag + signature (161).
pub(crate) const BLOB_OVERHEAD: usize = HEADER_LEN + TAG_LEN + SIG_LEN;
/// Smallest blob: one padding block (§4: 1 185).
pub(crate) const MIN_BLOB: usize = BLOB_OVERHEAD + PAD_BLOCK;
/// Largest blob: 63 padding blocks (§4: 64 673).
pub(crate) const MAX_BLOB: usize = BLOB_OVERHEAD + 63 * PAD_BLOCK;

/// Parsed view over a blob. Borrows; `pub(crate)` so the lifetime never reaches FFI.
pub(crate) struct Envelope<'a> {
    pub enc_hdr: &'a [u8; 40],
    pub nonce: &'a [u8; 24],
    pub ciphertext: &'a [u8],
    pub signature: &'a [u8; 64],
    /// `blob[0..81]`: the AEAD associated data, exactly as it travelled.
    pub aad: &'a [u8],
    /// `blob[0..len-64]`: the bytes the signature covers.
    pub signed_bytes: &'a [u8],
}

impl<'a> Envelope<'a> {
    /// §4 "Verification on receive", step 1: length class (1a), version (1b), channel (1c).
    ///
    /// # Errors
    /// `BadLength`, `UnsupportedVersion`, `WrongChannel`, in that order of precedence.
    pub(crate) fn parse(blob: &'a [u8], channel: &ChannelId) -> Result<Self, Error> {
        // 1a. Length class. `checked_sub` cannot fail once the range check passes;
        // the lint forbids bare `-` and keeping both facts in one place is the point.
        let len = blob.len();
        let padded = len.checked_sub(BLOB_OVERHEAD).ok_or(Error::BadLength)?;
        if !(MIN_BLOB..=MAX_BLOB).contains(&len) || !padded.is_multiple_of(PAD_BLOCK) {
            return Err(Error::BadLength);
        }
        // 1b. Version.
        if blob.first() != Some(&PROTO_V1) {
            return Err(Error::UnsupportedVersion);
        }
        // 1c. Channel. Constant-time: the id is public, but one rule beats a judgement call.
        let channel_id = blob.get(CHANNEL_ID_RANGE).ok_or(Error::BadLength)?;
        if !crate::crypto::ct_eq(channel_id, channel.as_bytes()) {
            return Err(Error::WrongChannel);
        }
        // Field views. Cannot fail after 1a; still `BadLength`, never `unwrap`.
        let sig_start = len.checked_sub(SIG_LEN).ok_or(Error::BadLength)?;
        let bytes = |r: core::ops::Range<usize>| blob.get(r).ok_or(Error::BadLength);
        Ok(Self {
            enc_hdr: bytes(ENC_HDR_RANGE)?.try_into().map_err(|_| Error::BadLength)?,
            nonce: bytes(NONCE_RANGE)?.try_into().map_err(|_| Error::BadLength)?,
            ciphertext: bytes(HEADER_LEN..sig_start)?,
            signature: bytes(sig_start..len)?.try_into().map_err(|_| Error::BadLength)?,
            aad: bytes(0..HEADER_LEN)?,
            signed_bytes: bytes(0..sig_start)?,
        })
    }
}
```

Tests for this function: the length boundaries (1 184, 1 185, 64 673, 64 674,
1 200 → `BadLength`), version and channel mutations, the constant-pinning
test, and a field-placement test (mutate one byte, assert it lands in the
expected field and nowhere else). The spec's **mutation table is a test of
`decrypt`, not of the parser**: for `enc_hdr`, `nonce`, `ciphertext` and
`signature` the parser accepts and the error (`BadSignature`, `Replay`, …)
comes from later steps. Say which level a mutation test is at in its name.

Fixtures may use indexing and plain arithmetic under the test-only relaxation
in SKILL.md "Errors and panics"; production code never gets it.

## 3. `Store` trait and `WriteBatch` — one commit per operation

```rust
pub trait Store {
    fn load(&mut self) -> Result<ChannelState, StoreError>;
    fn commit(&mut self, batch: WriteBatch) -> Result<(), StoreError>;
    fn compact(&mut self, now: u64) -> Result<u32, StoreError>;
}

#[derive(Default)]
pub struct WriteBatch {
    pub messages: Vec<StoredMessage>,
    pub peers: Vec<PeerUpdate>,
    pub outbox_add: Vec<(ClientRef, Vec<u8>)>,
    pub outbox_remove: Vec<ClientRef>,
    pub send_counter: Option<u64>,
    pub cursor: Option<u64>,
}
```

`Channel` builds one `WriteBatch` per logical operation and commits it once.
Rejections build a batch containing only `cursor`. Tests use two in-memory
stores: `CountingStore` (asserts `commits == 0` on rejection) and
`FailingStore { fail_at: n }` (returns `StoreError::Io` at the n-th commit;
tests reopen and compare state).

## 4. Sans-I/O `Session`

The session never touches a socket. The host drives it:

```rust
pub struct Session { /* nonce, subscriptions, per-channel cursors, outbox view */ }

pub enum Event {
    Subscribed(ChannelId),
    Received { channel: ChannelId, message: Received },
    Acked { channel: ChannelId, client_ref: ClientRef },
    Gap { channel: ChannelId, peer: PeerId, missing: u64 },
    Reconnect { after_ms: u64 },
    Fatal(Error),
}

impl Session {
    pub fn new(host: &str, channels: Vec<Channel>) -> Session;
    pub fn on_connect(&mut self, now: u64);
    pub fn on_frame(&mut self, frame: &[u8], now: u64) -> Result<Vec<Event>, Error>;
    pub fn outgoing(&mut self) -> Vec<Vec<u8>>;
}
```

Host loop (any platform): connect → `on_connect` → loop { write everything from
`outgoing()`; read a frame; `on_frame` } → on `Event::Reconnect`, back off and
reconnect. All protocol decisions — nonce expiry, `since` rounding, dedupe by
`server_id`, paging — live inside `on_frame`. One `Session` per server host.
The integration test runs two `Session`s against the real server binary in
Docker with a fake clock.

## 5. Encrypt: reserve before you emit

```rust
pub fn encrypt(&mut self, payload: &Payload, now: u64) -> Result<(ClientRef, Vec<u8>), Error> {
    payload.validate()?;
    let counter = self.send_counter;
    let next = counter.checked_add(1).ok_or(Error::CounterExhausted)?;
    let client_ref = ClientRef::random();
    let blob = self.seal(payload, counter, now)?;           // derives mk, encrypts, signs
    let mut batch = WriteBatch::default();
    batch.send_counter = Some(next);
    batch.outbox_add.push((client_ref, blob.clone()));
    self.store.commit(batch)?;                               // if this fails, no blob leaves
    self.send_counter = next;
    Ok((client_ref, blob))
}
```

The order is the requirement (`docs/spec.md` §4 "Send counter"): the
counter and the blob hit disk together, before the caller can send anything.

## 6. Test vector loader

```rust
// cfg(test) only. No serde: `core` carries no dependency beyond libsodium and
// zeroize, so the loader is a small JSON reader over `include_str!` (spec 015).
pub(crate) fn all(spec: &str) -> Vec<Vector>;          // every vector of specs/vectors/<spec>.json
pub(crate) fn load(spec: &str, name: &str) -> Vector;  // one by name; a missing name fails the test

#[test]
fn s013_t21_r01_every_vector_is_checked() {
    for v in vectors::all("013") {
        match v.name.as_str() {
            "text_k1" => check_text_k1(&v),
            // one arm per vector; an unknown name fails, so no vector is dead
            other => unreachable_vector(other),
        }
    }
}
```

The vectors in `specs/vectors/*.json` freeze when phase 1 closes; from then
on they are regenerated only with a `proto_version` change and an ADR. CI
(`adr-guard`) fails a diff that touches `specs/vectors/` without adding a new
ADR file, unless a human sets the `adr-not-needed` label (AGENTS 18).
