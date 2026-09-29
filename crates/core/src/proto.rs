//! The formats of the protocol other than the primitives: the record encoding
//! (spec 017-record-encoding), the config built on it (spec 011), the keys
//! and header of each message (spec 012), and, with specs 013 and 014, the
//! envelope, which is a fixed layout and not a record, and the fingerprint.

pub(crate) mod config;
pub(crate) mod header;
pub(crate) mod keys;
pub(crate) mod record;
pub(crate) mod wordlist;
