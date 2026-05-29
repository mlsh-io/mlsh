//! Windows named-pipe transport.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};

use super::Transport;

/// System pipe, used when the daemon runs as a Windows service.
const SYSTEM_PIPE: &str = r"\\.\pipe\mlshtund";

/// Holds the pipe name alongside the next pre-created server instance.
///
/// Windows named pipes require a fresh server instance per client; the
/// standard pattern is to pre-create one, wait for `connect().await`, then
/// spin up the next instance before handing the connected one off to the
/// handler.
pub struct PipeListener {
    pipe_name: String,
    next: NamedPipeServer,
}

pub struct WindowsTransport;

impl Transport for WindowsTransport {
    type Listener = PipeListener;
    type Stream = NamedPipeServerOrClient;

    fn endpoint_default(is_privileged: bool) -> PathBuf {
        if is_privileged {
            PathBuf::from(SYSTEM_PIPE)
        } else {
            let user = whoami::username().unwrap_or_else(|_| "user".to_string());
            PathBuf::from(format!(
                r"\\.\pipe\mlshtund-{}",
                sanitize_pipe_segment(&user)
            ))
        }
    }

    async fn bind(path: &Path) -> Result<Self::Listener> {
        let pipe_name = path_to_pipe_name(path);
        let next = create_pipe_instance(&pipe_name, true)?;
        Ok(PipeListener { pipe_name, next })
    }

    async fn accept(listener: &mut Self::Listener) -> Result<Self::Stream> {
        listener
            .next
            .connect()
            .await
            .context("Named pipe connect failed")?;
        let new_next = create_pipe_instance(&listener.pipe_name, false)?;
        let connected = std::mem::replace(&mut listener.next, new_next);
        Ok(NamedPipeServerOrClient::Server(connected))
    }

    async fn connect(path: &Path) -> Result<Self::Stream> {
        let pipe_name = path_to_pipe_name(path);
        let client = ClientOptions::new()
            .open(&pipe_name)
            .with_context(|| format!("Failed to connect to daemon at {}", pipe_name))?;
        Ok(NamedPipeServerOrClient::Client(client))
    }

    fn cleanup(_path: &Path) {
        // Named pipes are cleaned up automatically when the last handle drops.
    }
}

/// Create a named-pipe server instance.
///
/// For the system control pipe (the daemon running as a LocalSystem service)
/// the default DACL only grants non-elevated users read access, so the desktop
/// GUI/CLI — which open the pipe for read+write — get ACCESS_DENIED. Attach an
/// explicit DACL that keeps SYSTEM/Administrators in full control but also
/// grants authenticated users read+write. The per-user pipe needs no custom SD
/// (its creator already has full access).
fn create_pipe_instance(pipe_name: &str, first: bool) -> Result<NamedPipeServer> {
    let mut opts = ServerOptions::new();
    opts.first_pipe_instance(first);

    if pipe_name != SYSTEM_PIPE {
        return opts
            .create(pipe_name)
            .with_context(|| format!("Failed to create named pipe {}", pipe_name));
    }

    use std::ffi::{c_void, OsStr};
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

    // SYSTEM (SY) + Administrators (BA): full control. Authenticated users (AU):
    // generic read + write, enough for a client to open and use the pipe.
    let sddl: Vec<u16> = OsStr::new("D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1, // SDDL_REVISION_1
            &mut psd,
            std::ptr::null_mut(),
        ) == 0
        {
            anyhow::bail!(
                "Failed to build pipe security descriptor: {}",
                std::io::Error::last_os_error()
            );
        }

        let mut sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: psd,
            bInheritHandle: 0,
        };

        let result = opts
            .create_with_security_attributes_raw(pipe_name, &mut sa as *mut _ as *mut c_void);

        LocalFree(psd as _);

        result.with_context(|| format!("Failed to create named pipe {}", pipe_name))
    }
}

/// Unified stream type so the control loop can hold either side.
///
/// Server instances come from `accept`, client instances from `connect`;
/// both implement `AsyncRead + AsyncWrite` and are the same type from the
/// caller's perspective.
pub enum NamedPipeServerOrClient {
    Server(NamedPipeServer),
    Client(NamedPipeClient),
}

use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

impl AsyncRead for NamedPipeServerOrClient {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Server(s) => Pin::new(s).poll_read(cx, buf),
            Self::Client(c) => Pin::new(c).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for NamedPipeServerOrClient {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Server(s) => Pin::new(s).poll_write(cx, buf),
            Self::Client(c) => Pin::new(c).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Server(s) => Pin::new(s).poll_flush(cx),
            Self::Client(c) => Pin::new(c).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Server(s) => Pin::new(s).poll_shutdown(cx),
            Self::Client(c) => Pin::new(c).poll_shutdown(cx),
        }
    }
}

fn path_to_pipe_name(path: &Path) -> String {
    // PathBuf round-trips through OS strings which can turn `\\.\pipe\foo`
    // into just `\.\pipe\foo` on some backends. Normalize back.
    let s = path.to_string_lossy().to_string();
    if s.starts_with(r"\\.\pipe\") {
        s
    } else if s.starts_with(r"\.\pipe\") {
        format!(r"\{}", s)
    } else {
        // Bare name: assume caller meant the local pipe namespace.
        format!(r"\\.\pipe\{}", s.trim_start_matches('\\'))
    }
}

/// Strip characters that aren't valid in a pipe name.
fn sanitize_pipe_segment(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}
