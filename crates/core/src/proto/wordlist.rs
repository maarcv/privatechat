//! The English BIP-39 word list (spec 011 R17), embedded once and shared with
//! spec 014-fingerprint.
//!
//! 2 048 words, so each word is exactly 11 bits. The file is pinned by its
//! BLAKE2b-256 digest in a test and by its SHA-256 in the reference script.

/// The list as committed: 2 048 lines, each ending in LF.
pub(crate) const WORDS: &str = include_str!("bip39_english.txt");

/// How many words the list holds: 2^11.
pub(crate) const WORD_COUNT: u16 = 2_048;

/// The word at `index`, or `None` above the list.
pub(crate) fn word(index: u16) -> Option<&'static str> {
    WORDS.lines().nth(usize::from(index))
}
