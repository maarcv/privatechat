//! The message a `subscribe` signs (`docs/spec.md` §6, spec
//! 028-session-sans-io R6, spec 031-auth-channel-signature R2): the one
//! place it is built, for the session that signs it and the server that
//! checks it.

use super::config::ChannelId;

/// The domain tag of the subscription signature (`docs/spec.md` §4).
pub(crate) const AUTH_TAG: &[u8; 19] = b"privatechat/auth/v1";

/// `AUTH_TAG ‖ server_nonce ‖ channel_id ‖ BE32(ttl_seconds) ‖ host`, with
/// `host` from spec 011-config-format R6: the config's, never the socket's.
pub(crate) fn auth_message(
    server_nonce: &[u8; 32],
    channel_id: &ChannelId,
    ttl_seconds: u32,
    host: &str,
) -> Vec<u8> {
    [
        AUTH_TAG.as_slice(),
        server_nonce,
        &channel_id.0,
        &ttl_seconds.to_be_bytes(),
        host.as_bytes(),
    ]
    .concat()
}
