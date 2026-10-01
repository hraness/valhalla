//! Headless service implementation under qualification.

mod access;
mod backend;
mod catalog;
mod commands;
mod local;
mod managed;
mod mcp;
mod network;
mod peer;
mod private_delivery;
mod private_setup;
mod public_sync;
mod service;

/// The outer command owns runtime shutdown and writes each error once.
pub(crate) fn run(args: &[std::ffi::OsString]) -> i32 {
    use hraness_control_kit::{envelope::Envelope, ErrorBody, ErrorCode};
    use std::io::Write;
    let one_shot = args.first().is_none_or(|value| value != "run");
    let protocol_stdout = args
        .first()
        .is_some_and(|value| value == "run" || value == "mcp");
    let result = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(runtime) => {
            let result = runtime.block_on(commands::execute(args));
            if one_shot {
                // Tokio's blocking stdio cannot be cancelled. A one-shot
                // command has already joined any native initialization before
                // its final output. Do not let an idle input or full output
                // pipe hold this process beyond its protocol deadline.
                runtime.shutdown_timeout(std::time::Duration::from_millis(100));
            } else {
                drop(runtime);
            }
            result
        }
        Err(_) => Err(ErrorBody::new(
            ErrorCode::Internal,
            "Could not start the daemon client runtime.",
        )),
    };
    let Err(error) = result else { return 0 };
    let code = Envelope::<()>::error(error.clone()).exit_code() as i32;
    if protocol_stdout {
        crate::cli::report_error(&error.message);
    } else {
        let mut bytes = serde_json::to_vec(&serde_json::json!({"ok":false,"error":error}))
            .expect("serializable daemon error");
        bytes.push(b'\n');
        if std::io::stdout().write_all(&bytes).is_err() {
            return 1;
        }
    }
    code
}
