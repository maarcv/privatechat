//! The formats of the protocol other than the primitives: the record encoding
//! (spec 017-record-encoding) and, with specs 011–014, the records built on
//! it and the envelope, which is a fixed layout and not a record.

pub(crate) mod base64url;
pub(crate) mod config;
pub(crate) mod record;
pub(crate) mod wordlist;
