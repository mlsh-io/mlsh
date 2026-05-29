//! Native Windows Service (SCM) integration for the `mlshtund` daemon.
//!
//! When `mlshtund.exe --service` is launched by the Service Control Manager,
//! [`run`] hands control to the SCM dispatcher; `service_main` then registers a
//! control handler, reports `Running`, and drives the regular daemon loop with
//! shutdown wired to the SCM "Stop"/"Shutdown" control events.

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use tokio::sync::watch;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

/// Service key name registered with the SCM.
pub const SERVICE_NAME: &str = "mlshtund";

/// Human-readable name shown in services.msc.
pub const SERVICE_DISPLAY_NAME: &str = "MLSH Tunnel Daemon";

const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

define_windows_service!(ffi_service_main, service_main);

/// Hand control to the SCM dispatcher. Blocks until the service stops.
/// Only call this when launched by the SCM (i.e. `mlshtund.exe --service`).
pub fn run() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .map_err(|e| anyhow::anyhow!("failed to start service dispatcher: {e}"))
}

fn service_main(_arguments: Vec<OsString>) {
    // Logging is initialised inside `run_service`; errors before that point
    // have nowhere useful to go (the service has no console).
    if let Err(e) = run_service() {
        tracing::error!("mlshtund service error: {:#}", e);
    }
}

fn run_service() -> Result<()> {
    // Keep the appender guard alive for the lifetime of the service so the
    // background log writer flushes.
    let _log_guard = init_logging();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = shutdown_tx.send(true);
                ServiceControlHandlerResult::NoError
            }
            // Always handle Interrogate so the SCM can query our state.
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(crate::tund::daemon::run_with_shutdown(None, shutdown_rx));

    let exit_code = match &result {
        Ok(()) => ServiceExitCode::Win32(0),
        Err(e) => {
            tracing::error!("mlshtund daemon exited with error: {:#}", e);
            ServiceExitCode::ServiceSpecific(1)
        }
    };

    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code,
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    result
}

/// `%ProgramData%\mlsh\logs` — where the service writes its rolling log.
pub fn log_dir() -> PathBuf {
    let base = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
    PathBuf::from(base).join("mlsh").join("logs")
}

/// Install a daily-rolling file subscriber under [`log_dir`]. Returns the
/// worker guard which must be kept alive for logs to flush.
fn init_logging() -> Option<tracing_appender::non_blocking::WorkerGuard> {
    use tracing_subscriber::EnvFilter;

    let dir = log_dir();
    std::fs::create_dir_all(&dir).ok()?;

    let file_appender = tracing_appender::rolling::daily(&dir, "mlshtund.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("mlsh_cli=info")),
        )
        .with_writer(non_blocking)
        .with_ansi(false)
        .try_init();

    Some(guard)
}

/// Whether the current process token is elevated.
///
/// Returns true for LocalSystem (the service account) and for an elevated
/// terminal — both of which should bind the system control pipe and are
/// allowed to manage the service.
pub fn is_elevated() -> bool {
    use std::mem::size_of;

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut ret_len: u32 = 0;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut std::ffi::c_void,
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        );
        CloseHandle(token);

        ok != 0 && elevation.TokenIsElevated != 0
    }
}
