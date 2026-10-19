//! The `pub` surface of `server` (spec 035-server-ops R10, spec 027-core-api
//! R16): every `pub` function coerced to a function pointer of its exact
//! type, and `Bound::run` pinned by a call, so that a changed or missing
//! signature fails to compile.

use std::net::SocketAddr;
use std::sync::Arc;

use privatechat_server::{
    Bound, Clock, ConfigError, DbCause, Outcome, Settings, StartError, StartReason, SystemClock,
    bind,
};

#[test]
fn s035_t10_r10_pub_items() {
    let _: fn(Settings, Arc<dyn Clock>) -> Result<Bound, StartError> = bind;
    let _: fn(std::env::VarsOs) -> Result<Settings, ConfigError> = Settings::from_env;
    let _: fn(&Bound) -> Vec<SocketAddr> = Bound::local_addrs;
    let _: Arc<dyn Clock> = Arc::new(SystemClock);
    let _: [StartReason; 5] = [
        StartReason::Bind,
        StartReason::Database(DbCause::UserVersion),
        StartReason::Database(DbCause::JournalMode),
        StartReason::Database(DbCause::AutoVacuum),
        StartReason::Database(DbCause::Open),
    ];
    #[cfg(feature = "test-support")]
    {
        let _: fn(u64) -> privatechat_server::ManualClock = privatechat_server::ManualClock::new;
    }
}

/// `Bound::run` with concrete arguments, compiled and never called.
#[allow(dead_code, reason = "compiled for its signature only")]
async fn s035_t10_r10_run_signature(bound: Bound) {
    let _: Outcome = bound.run(std::future::ready(())).await;
}
