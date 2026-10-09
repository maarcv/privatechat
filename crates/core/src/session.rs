//! A channel's state machine over its store (spec 021-channel-session):
//! sealing and opening against the state, and one commit per operation
//! (AGENTS 23), and the frames of the connection that carries it (spec
//! 028-session-sans-io). The clients reach it only through the `Device` of
//! spec 027-core-api.

pub(crate) mod channel;
mod expiry;
pub(crate) mod frames;
mod names;
