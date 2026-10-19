//! Exchange server: blind mailbox with TTL (`docs/spec.md` §6).
//!
//! The binary only reads the environment, wires the signals to the shutdown
//! future and maps the result to the exit code (spec 035-server-ops R8,
//! R10); everything else is the library's.

#![forbid(unsafe_code)]
// Tests may relax these four lints to build fixtures; production code never does (AGENTS 4).
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )
)]

use std::process::ExitCode;
use std::sync::Arc;

use privatechat_server::{Outcome, Settings, StartError, StartReason, SystemClock, bind};

/// The exit codes of R8 other than 0.
const FATAL: u8 = 1;
const CONFIG_ERROR: u8 = 2;
const DATABASE_REFUSED: u8 = 3;

fn main() -> ExitCode {
    let settings = match Settings::from_env(std::env::vars_os()) {
        Ok(settings) => settings,
        Err(error) => {
            #[allow(
                clippy::print_stderr,
                reason = "a configuration error comes before any log level is known (spec 035 R4)"
            )]
            {
                eprintln!("{error}");
            }
            return ExitCode::from(CONFIG_ERROR);
        }
    };
    let bound = match bind(settings, Arc::new(SystemClock)) {
        Ok(bound) => bound,
        Err(StartError {
            reason: StartReason::Database(_),
        }) => return ExitCode::from(DATABASE_REFUSED),
        Err(StartError {
            reason: StartReason::Bind,
        }) => return ExitCode::from(FATAL),
    };
    let Ok(runtime) = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    else {
        return ExitCode::from(FATAL);
    };
    match runtime.block_on(bound.run(signal())) {
        Outcome::Stopped => ExitCode::SUCCESS,
        Outcome::Fatal => ExitCode::from(FATAL),
    }
}

/// Resolves on SIGTERM or SIGINT; without a SIGTERM handler, on SIGINT alone.
async fn signal() {
    let interrupt = async {
        // A SIGINT that cannot be awaited never stops the server by itself.
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    if let Ok(mut terminate) =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        tokio::select! {
            _ = terminate.recv() => {}
            () = interrupt => {}
        }
        return;
    }
    interrupt.await;
}
