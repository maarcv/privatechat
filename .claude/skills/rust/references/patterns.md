# Rust patterns used in this repository

These are the shapes the spec assumes. Reuse them; do not invent parallel ones.
They are written to pass the workspace lints; when the implementing spec lands,
the real code supersedes the snippet and is re-checked against it. Signatures
that also appear in `docs/spec.md` §9 are copied from there and §9 wins.

Contents:
1. `Secret<N>` — key material
2. Fixed-offset parsing — the wire envelope (§4)
3. `Store` trait and `WriteBatch` — one commit per operation
4. Sans-I/O `Session`
5. Encrypt: reserve before you emit
6. Test vector loader

## 1. `Secret<N>` — the only home for key material (AGENTS 5, spec 010 R3)

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

## 2. Fixed-offset parsing (`docs/spec.md` §4 envelope)

Two conventions this shape fixes, so nobody decides them again:

- **Step 1 of "Verification on receive" is three conditions with three
  variants**, checked in order: 1a length class → `BadLength`, 1b version →
  `UnsupportedVersion`, 1c channel → `WrongChannel`. The spec writes them as
  one numbered step; tests name them 1a/1b/1c. 1c lives inside the parser,
  which therefore takes the expected `ChannelId`: `Envelope::parse(blob,
  &channel_id)`, not `TryFrom<&[u8]>`.
- The parser exposes `aad` (`blob[0..81]`) and `signed_bytes`
  (`blob[0..len-64]`) so the offsets exist exactly once; the caller never
  re-slices.
- The parser is the first half of `verify(blob, ctx, received_at, now)`
  (spec 013 R11): after step 1 come the expiry check, then the header is
  opened and the signature unmasked with bytes 40..104 of the `K_hdr`
  keystream (ADR 0032), then the signature check. The signature travels
  masked; the parser only locates it.

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
    /// The masked signature as it travels; `verify` unmasks it with keystream bytes 40..104 (ADR 0032).
    pub signature: &'a [u8; 64],
    /// `blob[0..81]`: the AEAD associated data, exactly as it travelled.
    pub aad: &'a [u8],
    /// `blob[0..len-64]`: the bytes the unmasked signature covers, after the tag (spec 013 R4).
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
        // `ct_eq` takes `&[u8; N]`, so the slice becomes an array first.
        let channel_id: &[u8; 16] = blob
            .get(CHANNEL_ID_RANGE)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(Error::BadLength)?;
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
expected field and nowhere else). The full mutation table belongs to
`verify` (spec 013 R17), not to the parser (rust skill, "Testing").

## 3. `Store` trait and `WriteBatch` — one commit per operation (AGENTS 23)

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
    pub outbox_add: Vec<(ClientRef, Vec<u8>, [u8; 64])>, // blob and its unmasked signature (ADR 0029)
    pub outbox_remove: Vec<ClientRef>,
    pub send_counter: Option<u64>,
    pub cursor: Option<u64>,
}
```

`Channel` builds one `WriteBatch` per logical operation and commits it once;
a rejection builds a batch containing only `cursor`. The two in-memory test
stores are `CountingStore` (counts commits other than the cursor's) and
`FailingStore { fail_at: n }` (returns `StoreError::Io` at the n-th commit;
tests reopen and compare state).

## 4. Sans-I/O `Session` (ADR 0020)

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
    pub fn new(server_url: &str, channels: Vec<Channel>) -> Session; // all channels of one server (host and port)
    pub fn on_connect(&mut self, now: u64);
    pub fn on_frame(&mut self, frame: &[u8], now: u64) -> Result<Vec<Event>, Error>;
    pub fn outgoing(&mut self) -> Vec<Vec<u8>>;
}
```

The host loop is `architecture` §7 "Talking to the core". All protocol
decisions — nonce expiry, `since` rounding, dedupe by `server_id`, paging —
live inside `on_frame`. The integration test runs two `Session`s against the
real server binary in Docker with a fake clock.

## 5. Encrypt: reserve before you emit (`docs/spec.md` §4 "Send counter")

```rust
pub fn encrypt(&mut self, body: &str, display_name: Option<&str>, now: u64) -> Result<(ClientRef, Vec<u8>), Error> {
    let payload = Payload::text(body, display_name, now)?; // the core builds and validates it
    let counter = self.send_counter;
    let next = counter.checked_add(1).ok_or(Error::CounterExhausted)?;
    let client_ref = ClientRef::random();
    let sealed = self.seal(&payload, counter, now)?;        // draws the nonce, derives mk, encrypts, signs and masks the signature (013 R16)
    let mut batch = WriteBatch::default();
    batch.send_counter = Some(next);
    batch.outbox_add.push((client_ref, sealed.blob.clone(), sealed.signature));
    self.store.commit(batch)?;                               // if this fails, no blob leaves
    self.send_counter = next;
    Ok((client_ref, sealed.blob))
}
```

## 6. Test vector loader (spec 015)

```rust
// cfg(test) only. No serde: `core` carries no dependency beyond libsodium and
// zeroize, so the loader is a small JSON reader over `include_str!`. The files
// are written by `scripts/reference/vectors.py`; Rust only reads and checks.
pub(crate) fn load(spec: &str, name: &str) -> Vector;  // spec 010's tests only
pub(crate) type Checker = fn(&Vector);                // an alias keeps clippy::type_complexity quiet
pub(crate) fn check_all(spec: &str, entries: &[(&str, Checker)]);  // fails on a vector with no entry or an entry with no vector

#[test] // the only code that loads 013.json (spec 015 R3)
fn s013_vectors_dispatch() {
    vectors::check_all("013", &[
        ("text_k1", check_text_k1),
        // one entry per vector: check_all fails on an unmatched name either way
    ]);
}
```
