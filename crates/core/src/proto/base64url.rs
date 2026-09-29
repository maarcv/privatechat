//! Strict base64url with no padding (RFC 4648 §5), the one base64 codec of
//! the workspace (spec 011 R12, shared with spec 014-fingerprint).
//!
//! Every byte string has exactly one text: no padding, no other alphabet and
//! no non-zero bits after the last byte. Failures are `None`, because the
//! config QR and the verification QR report them as different errors. Each
//! output is allocated once at its exact size and never grows, since it may
//! hold a key (spec 011 R19).

use zeroize::Zeroizing;

/// The alphabet of RFC 4648 §5.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// The text of `bytes`, or `None` when its length cannot be expressed.
pub(crate) fn encode(bytes: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let len = encoded_len(bytes.len())?;
    let mut text = Zeroizing::new(Vec::with_capacity(len));
    for chunk in bytes.chunks(3) {
        let mut group = [0u8; 4];
        for (slot, byte) in group.iter_mut().skip(1).zip(chunk) {
            *slot = *byte;
        }
        let group = u32::from_be_bytes(group);
        for shift in [18u32, 12, 6, 0]
            .into_iter()
            .take(chunk.len().saturating_add(1))
        {
            let sextet = group.checked_shr(shift)? & 0x3f;
            text.push(*ALPHABET.get(usize::try_from(sextet).ok()?)?);
        }
    }
    Some(text)
}

/// The bytes of `text`, or `None` for any text that is not the canonical
/// encoding of some bytes: a length that leaves one character over, a byte
/// outside the alphabet (padding included) or non-zero final bits.
pub(crate) fn decode(text: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let len = decoded_len(text.len())?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(len));
    for chunk in text.chunks(4) {
        let mut group = 0u32;
        for (at, character) in (0u32..).zip(chunk) {
            let sextet = u32::from(sextet(*character)?);
            group |= sextet.checked_shl(18u32.checked_sub(at.checked_mul(6)?)?)?;
        }
        let group = group.to_be_bytes();
        let (kept, rest) = group
            .get(1..)?
            .split_at_checked(chunk.len().checked_sub(1)?)?;
        if rest.iter().any(|bits| *bits != 0) {
            return None;
        }
        bytes.extend_from_slice(kept);
    }
    Some(bytes)
}

/// Four characters per three bytes, and two or three for a last group of one
/// or two.
fn encoded_len(len: usize) -> Option<usize> {
    let tail = [0, 2, 3].get(len % 3).copied()?;
    (len / 3).checked_mul(4)?.checked_add(tail)
}

/// The inverse of `encoded_len`; `None` for a length it never produces.
fn decoded_len(len: usize) -> Option<usize> {
    let tail = [Some(0), None, Some(1), Some(2)].get(len % 4).copied()??;
    (len / 4).checked_mul(3)?.checked_add(tail)
}

/// The value of one character of the alphabet.
fn sextet(character: u8) -> Option<u8> {
    let at = ALPHABET.iter().position(|letter| *letter == character)?;
    u8::try_from(at).ok()
}
