//! The names this device gives a channel and itself in it (spec
//! 027-core-api R7): the local name the user chose, and the name `send`
//! uses by default.

use super::Channel;
use crate::error::Error;
use crate::session::names::name_key;
use crate::storage::MAX_NAME;

impl Channel {
    /// Commits `name` as the channel's local name, or clears it for `""`
    /// (spec 027-core-api R7).
    ///
    /// # Errors
    ///
    /// `BadPayload`, with nothing committed, for a name longer than
    /// `MAX_NAME`, with a Cc character or whose key is empty; `Store` when
    /// the commit fails.
    pub(crate) fn set_local_name(&mut self, name: &str) -> Result<(), Error> {
        let local_name = if name.is_empty() {
            None
        } else {
            let valid = name.len() <= MAX_NAME
                && !name.chars().any(char::is_control)
                && !name_key(name).is_empty();
            if !valid {
                return Err(Error::BadPayload);
            }
            Some(name.to_owned())
        };
        let mut next = self.next_state();
        next.local_name = local_name;
        self.commit(next, Vec::new())
    }

    /// The local name, as committed.
    pub(crate) fn local_name(&self) -> Option<&str> {
        self.state.local_name.as_deref()
    }

    /// The name `send` uses by default, as committed.
    pub(crate) fn own_display_name(&self) -> Option<&str> {
        self.state.own_display_name.as_deref()
    }
}
