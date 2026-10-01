//! Thin owner CLI and grant-only MCP launcher. The service owns all room work.

use super::{catalog::Hash, local, managed, mcp, network::Listen, service::ServiceBackend};
use hraness_control_kit::{control, ErrorBody, ErrorCode};
use rustix::fs::{fstat, FileType};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    ffi::OsString,
    fs,
    future::Future,
    io,
    os::fd::AsFd,
    path::{Component, Path, PathBuf},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    signal::unix::{signal, Signal, SignalKind},
    time::timeout,
};
use vhalla_custody::{self as custody, Owner};
use zeroize::Zeroizing;

const MAX_CALL_BYTES: usize = 512 * 1024;
const MAX_GRANT_BYTES: usize = 16 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Action {
    Init,
    Run,
    Status,
    Stop,
    Call,
    Mcp,
    ManagedInstall,
    ManagedStatus,
    ManagedUninstall,
}

#[derive(Debug)]
struct Command {
    action: Action,
    home: PathBuf,
    grant: Option<PathBuf>,
    listen: Listen,
}

fn usage(message: &str) -> ErrorBody {
    ErrorBody::new(ErrorCode::Usage, message)
}

fn absolute_path(path: &Path) -> Result<PathBuf, ErrorBody> {
    if !path.is_absolute() || path.components().any(|part| part == Component::ParentDir) {
        return Err(usage("Use an absolute path without '..' components."));
    }
    // Remove a trailing slash or '/.' before no-symlink leaf checks. They can
    // otherwise turn an apparent leaf into an ancestor resolved by the kernel.
    Ok(path.components().collect())
}

fn parse(args: &[OsString]) -> Result<Command, ErrorBody> {
    let managed_action = args.first().is_some_and(|value| value == "managed");
    let action = if managed_action {
        match args.get(1).and_then(|value| value.to_str()) {
            Some("install") => Action::ManagedInstall,
            Some("status") => Action::ManagedStatus,
            Some("uninstall") => Action::ManagedUninstall,
            _ => {
                return Err(usage(
                    "Use daemon managed install, status, or uninstall with --home ABSOLUTE_PATH.",
                ))
            }
        }
    } else {
        match args.first().and_then(|value| value.to_str()) {
        Some("init") => Action::Init,
        Some("run") => Action::Run,
        Some("status") => Action::Status,
        Some("stop") => Action::Stop,
        Some("call") => Action::Call,
        Some("mcp") => Action::Mcp,
        _ => {
            return Err(usage(
                "Use daemon init, run, status, stop, call, mcp, or managed with --home ABSOLUTE_PATH.",
            ))
        }
    }
    };
    let mut home = None;
    let mut grant = None;
    let mut bind = None;
    let mut relay_url = None;
    let mut relay_only = false;
    let network_options = matches!(action, Action::Run | Action::ManagedInstall);
    let mut flags = args[if managed_action { 2 } else { 1 }..].iter();
    while let Some(flag) = flags.next() {
        if flag == "--relay-only" && network_options && !relay_only {
            relay_only = true;
            continue;
        }
        let value = flags
            .next()
            .ok_or_else(|| usage("This daemon option needs a value."))?;
        match flag.to_str() {
            Some("--home") if home.is_none() => home = Some(absolute_path(Path::new(value))?),
            Some("--grant") if action == Action::Mcp && grant.is_none() => {
                grant = Some(absolute_path(Path::new(value))?);
            }
            Some("--bind") if network_options && bind.is_none() => {
                bind = Some(
                    value
                        .to_str()
                        .and_then(|value| value.parse().ok())
                        .ok_or_else(|| usage("Pass --bind IP:PORT."))?,
                );
            }
            Some("--relay-url") if network_options && relay_url.is_none() => {
                relay_url = Some(
                    value
                        .to_str()
                        .ok_or_else(|| usage("Pass --relay-url HTTPS_URL."))?
                        .to_owned(),
                );
            }
            _ => return Err(usage("Remove unknown or repeated daemon options.")),
        }
    }
    let home = home.ok_or_else(|| usage("Pass --home ABSOLUTE_PATH."))?;
    if action == Action::Mcp && grant.is_none() {
        return Err(usage("Pass --grant ABSOLUTE_FILE for daemon mcp."));
    }
    let listen = Listen {
        bind: bind.unwrap_or_else(|| Listen::default().bind),
        relay_url,
        relay_only,
    };
    // Relay policy is checked before creating a home or acquiring any handles.
    listen.validate()?;
    Ok(Command {
        action,
        home,
        grant,
        listen,
    })
}

fn require_pipe(fd: impl AsFd) -> Result<(), ErrorBody> {
    if !matches!(
        FileType::from_raw_mode(
            fstat(fd)
                .map_err(|_| usage("Could not inspect the input or output pipe."))?
                .st_mode
        ),
        FileType::Fifo | FileType::Socket
    ) {
        return Err(usage(
            "Use a pipe or socket for daemon call input and for both daemon mcp streams.",
        ));
    }
    Ok(())
}

struct ShutdownSignals {
    interrupt: Signal,
    terminate: Signal,
}
impl ShutdownSignals {
    fn new() -> Result<Self, ErrorBody> {
        let error = |_| {
            ErrorBody::new(
                ErrorCode::Internal,
                "Could not listen for daemon shutdown signals.",
            )
        };
        Ok(Self {
            interrupt: signal(SignalKind::interrupt()).map_err(error)?,
            terminate: signal(SignalKind::terminate()).map_err(error)?,
        })
    }

    async fn wait(mut self) {
        tokio::select! {
            _ = self.interrupt.recv() => {},
            _ = self.terminate.recv() => {},
        }
    }
}

/// `args` contains only the tokens after `daemon`.
///
/// Successful owner calls and init print one local RPC success envelope. Every
/// error is returned unprinted: the outer CLI prints one JSON error envelope
/// for ordinary daemon commands, or stderr for run/MCP. Run is otherwise quiet;
/// MCP stdout contains only MCP responses. This wrapper never retries a call.
pub(crate) async fn execute(args: &[OsString]) -> Result<(), ErrorBody> {
    let command = parse(args)?;
    if matches!(command.action, Action::Call | Action::Mcp) {
        require_pipe(std::io::stdin())?;
    }
    if command.action == Action::Mcp {
        require_pipe(std::io::stdout())?;
    }
    // Register both handlers before service startup can acquire any handles.
    let signals = if command.action == Action::Run {
        Some(ShutdownSignals::new()?)
    } else {
        None
    };
    execute_with_io(
        command,
        tokio::io::stdin(),
        tokio::io::stdout(),
        async move {
            if let Some(signals) = signals {
                signals.wait().await;
            } else {
                std::future::pending::<()>().await;
            }
        },
    )
    .await
}

/// Descriptor checks stay at the real stdio boundary; tests inject only bytes.
async fn execute_with_io(
    command: Command,
    input: impl AsyncRead + Unpin,
    mut output: impl AsyncWrite + Unpin,
    shutdown: impl Future<Output = ()>,
) -> Result<(), ErrorBody> {
    let result = match command.action {
        Action::Init => {
            // Keep service state out of every client/MCP command future; an
            // async match otherwise reserves its largest branch for all calls.
            Box::pin(initialize_home(&command.home)).await?;
            json!({"initialized":true})
        }
        Action::Run => return Box::pin(run_home(&command.home, &command.listen, shutdown)).await,
        Action::Status => {
            local::admin_request(&command.home, json!({"op":"service.status"})).await?
        }
        Action::Stop => local::admin_request(&command.home, json!({"op":"control.stop"})).await?,
        Action::Call => {
            let request = read_request(input).await?;
            local::admin_request(&command.home, request).await?
        }
        Action::Mcp => {
            let path = command
                .grant
                .as_ref()
                .ok_or_else(|| usage("Pass --grant ABSOLUTE_FILE for daemon mcp."))?;
            let grant = read_grant(path)?;
            return mcp::run(
                &command.home,
                grant.generation,
                grant.token,
                BufReader::new(input),
                output,
            )
            .await;
        }
        Action::ManagedInstall => {
            Box::pin(verify_retained_home(&command.home)).await?;
            let executable = std::env::current_exe()
                .and_then(|path| path.canonicalize())
                .map_err(|_| {
                    ErrorBody::new(
                        ErrorCode::Internal,
                        "Could not locate the running executable.",
                    )
                })?;
            managed::install(&command.home, &executable, &command.listen)?
        }
        Action::ManagedStatus => managed::status(&command.home)?,
        Action::ManagedUninstall => managed::uninstall(&command.home)?,
    };
    write_success(&mut output, result).await
}

fn prepare_home(home: &Path) -> Result<(), ErrorBody> {
    let refused = || {
        ErrorBody::new(
            ErrorCode::PermissionDenied,
            "The daemon home must be a directory you own with mode 0700 and no symlink.",
        )
    };
    if !home.is_absolute() {
        return Err(usage("Daemon paths must be absolute."));
    }
    let created = match fs::symlink_metadata(home) {
        Ok(_) => false,
        Err(error) if error.kind() == io::ErrorKind::NotFound => true,
        Err(_) => return Err(refused()),
    };
    let (directory, owner) = if created {
        custody::create_private_directory(home)
    } else {
        custody::open_private_directory(home)
    }
    .map_err(|_| refused())?;
    if owner != Owner::current().map_err(|_| refused())? {
        return Err(refused());
    }
    directory.sync_all().map_err(|_| refused())?;
    if created {
        custody::sync_directory(home.parent().ok_or_else(refused)?).map_err(|_| refused())?;
    }
    Ok(())
}

async fn initialize_home(home: &Path) -> Result<(), ErrorBody> {
    let home = absolute_path(home)?;
    prepare_home(&home)?;
    // Even initialization is inside the same exclusive supervisor lifetime as
    // normal serving. The already-ready shutdown runs only after construction.
    local::serve_factory(
        &home,
        |generation| launch(&home, generation, true, None),
        async {},
    )
    .await
}

async fn run_home(
    home: &Path,
    listen: &Listen,
    shutdown: impl Future<Output = ()>,
) -> Result<(), ErrorBody> {
    let home = absolute_path(home)?;
    listen.validate()?;
    local::serve_factory(
        &home,
        |generation| launch(&home, generation, false, Some(listen)),
        shutdown,
    )
    .await
}

/// A stopped service must open its retained native state successfully before
/// supervisor installation. All writer handles and service custody are joined
/// and released before the supervisor may start the executable independently.
async fn verify_retained_home(home: &Path) -> Result<(), ErrorBody> {
    local::serve_factory(
        home,
        |generation| launch(home, generation, false, None),
        async {},
    )
    .await
}

/// Keep all launch construction here so network managers join this same owner.
async fn launch(
    home: &Path,
    generation: Hash,
    initialize: bool,
    listen: Option<&Listen>,
) -> Result<local::Launch<ServiceBackend>, ErrorBody> {
    if listen.is_some() {
        // Factory construction already holds service custody. Bound failure
        // logs too, before opening native data that might require recovery.
        crate::private_host::events::bound_supervisor_output(home);
    }
    let mut backend = if initialize {
        ServiceBackend::initialize(home, generation).await?
    } else {
        ServiceBackend::open(home, generation).await?
    };
    let endpoint = match listen {
        Some(listen) => Some(backend.bind_network(listen).await?),
        None => None,
    };
    Ok(local::Launch { backend, endpoint })
}

async fn read_request(input: impl AsyncRead + Unpin) -> Result<Value, ErrorBody> {
    let mut bytes = Zeroizing::new(Vec::new());
    timeout(
        IO_TIMEOUT,
        input
            .take((MAX_CALL_BYTES + 1) as u64)
            .read_to_end(&mut bytes),
    )
    .await
    .map_err(|_| usage("The request pipe did not finish within 30 seconds."))?
    .map_err(|_| usage("Could not read the request pipe."))?;
    if bytes.len() > MAX_CALL_BYTES {
        return Err(usage("The request must be at most 512 KiB."));
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| {
        usage("Provide exactly one JSON request object, then close the input pipe.")
    })?;
    if !value.is_object() {
        return Err(usage("The request must be a JSON object."));
    }
    Ok(value)
}

// Extra grant.issue display metadata is deliberately ignored. Only these two
// exact values are sent to the agent socket; file metadata cannot expand them.
#[derive(Deserialize)]
struct Grant {
    generation: Hash,
    token: Hash,
}

fn read_grant(path: &Path) -> Result<Grant, ErrorBody> {
    let path = absolute_path(path)?;
    let refused = || {
        ErrorBody::new(
            ErrorCode::PermissionDenied,
            "The grant must be a file you own with mode 0600, no links, and at most 16 KiB.",
        )
    };
    let owner = Owner::current().map_err(|_| refused())?;
    let bytes = Zeroizing::new(
        custody::read_private_file(&path, owner, MAX_GRANT_BYTES).map_err(|_| refused())?,
    );
    serde_json::from_slice(&bytes).map_err(|_| {
        usage("The grant file must contain the generation and token from a grant.issue result.")
    })
}

async fn write_success(
    output: &mut (impl AsyncWrite + Unpin),
    result: Value,
) -> Result<(), ErrorBody> {
    let mut bytes = Zeroizing::new(
        serde_json::to_vec(&json!({"ok":true,"result":result})).map_err(|_| {
            ErrorBody::new(ErrorCode::Internal, "Could not encode the daemon response.")
        })?,
    );
    bytes.push(b'\n');
    if bytes.len() > control::DEFAULT_MAX_BYTES {
        return Err(ErrorBody::new(
            ErrorCode::Internal,
            "The daemon response exceeds the supported size.",
        ));
    }
    let error = || {
        ErrorBody::new(
            ErrorCode::OwnerUnavailable,
            "The response may be incomplete; keep the same operation ID when checking or retrying.",
        )
    };
    timeout(IO_TIMEOUT, async {
        output.write_all(&bytes).await?;
        output.flush().await
    })
    .await
    .map_err(|_| error())?
    .map_err(|_| error())
}

#[cfg(test)]
#[path = "commands_tests.rs"]
mod tests;
