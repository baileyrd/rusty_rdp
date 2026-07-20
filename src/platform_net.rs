//! Optional bridge to `platform::net::TcpStream` (feature `platform`).
//!
//! `platform` ([github.com/baileyrd/rustils](https://github.com/baileyrd/rustils))
//! is rustils' own hand-rolled OS abstraction layer — not a third-party
//! black box, just written in a sibling repo — so depending on it here
//! doesn't compromise this crate's "no opaque dependency" ethos the way
//! pulling in a networking framework would. [`PlatformTcpStream`] wraps
//! any `Box<dyn platform::net::TcpStream>` (Linux, Windows, or the
//! in-memory mock backend — whichever the caller picked) in
//! `std::io::Read` + `Write`, so it drops straight into
//! [`crate::net::RdpTransport::new`] exactly like a `std::net::TcpStream`
//! does.
//!
//! This module is entirely optional and off by default; enabling it
//! pulls in `platform` and raises the effective MSRV to whatever it
//! requires (see the crate-level README, the same shape the `tls`
//! feature's `rustls` dependency already has). This crate only depends
//! on `platform` itself (the trait crate) — the caller picks a concrete
//! backend (`platform-linux`, `platform-windows`, or `platform-mock` for
//! a test with no real socket at all) and adds it as their own
//! dependency, so this module stays backend-agnostic:
//!
//! ```ignore
//! use rusty_rdp::net::RdpTransport;
//! use rusty_rdp::platform_net::PlatformTcpStream;
//! use platform::net::Net;
//!
//! // `platform_linux` (or `platform_windows`, or `platform_mock`) is the
//! // caller's own dependency, not this crate's.
//! let net = platform_linux::LinuxNet;
//! let tcp = net.tcp_connect("127.0.0.1:3389".parse().unwrap())?;
//! let mut rdp = RdpTransport::new(PlatformTcpStream::new(tcp));
//! ```

use std::io::{self, Read, Write};
use std::time::Duration;

use platform::error::{ErrorKind, PlatformError};
use platform::net::TcpStream as PlatformNetTcpStream;

/// Adapts a `platform::net::TcpStream` (any backend) to `std::io::Read` +
/// `Write`, so it can drive [`crate::net::RdpTransport`] exactly like a
/// `std::net::TcpStream`.
pub struct PlatformTcpStream(Box<dyn PlatformNetTcpStream>);

impl PlatformTcpStream {
    /// Wrap an already-connected `platform::net::TcpStream`.
    pub fn new(inner: Box<dyn PlatformNetTcpStream>) -> Self {
        Self(inner)
    }

    /// Bound how long `read` will block waiting for data — an idle
    /// timeout (each `read` gets its own fresh clock, not a per-call
    /// deadline); `None` blocks indefinitely. A timeout expiring
    /// surfaces as `io::ErrorKind::WouldBlock` **or** `TimedOut` — the
    /// same ambiguity `std::net::TcpStream::set_read_timeout` itself
    /// documents, not resolved here either. This is the one capability
    /// the `connect` example (`examples/connect.rs`) needs and a plain
    /// `std::net::TcpStream` already has.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.0.set_read_timeout(timeout).map_err(to_io_error)
    }

    /// Toggle Nagle's algorithm (`TCP_NODELAY`).
    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.0.set_nodelay(nodelay).map_err(to_io_error)
    }
}

impl Read for PlatformTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf).map_err(to_io_error)
    }
}

impl Write for PlatformTcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf).map_err(to_io_error)
    }

    fn flush(&mut self) -> io::Result<()> {
        // Every `platform::net::TcpStream::write` is a synchronous
        // `send`/`write` syscall with no userspace buffering to flush.
        Ok(())
    }
}

/// Map a `platform::error::PlatformError` onto the closest
/// `std::io::ErrorKind`, preserving the original error as the `io::Error`
/// source rather than discarding it — just re-classified into
/// `std::io`'s narrower taxonomy, the one this crate's own
/// `io::Result`-returning API already speaks.
fn to_io_error(e: PlatformError) -> io::Error {
    let kind = match e.kind {
        ErrorKind::NotFound => io::ErrorKind::NotFound,
        ErrorKind::PermissionDenied => io::ErrorKind::PermissionDenied,
        ErrorKind::AlreadyExists => io::ErrorKind::AlreadyExists,
        ErrorKind::InvalidInput => io::ErrorKind::InvalidInput,
        ErrorKind::WouldBlock => io::ErrorKind::WouldBlock,
        ErrorKind::Interrupted => io::ErrorKind::Interrupted,
        ErrorKind::BrokenPipe => io::ErrorKind::BrokenPipe,
        ErrorKind::Unsupported => io::ErrorKind::Unsupported,
        ErrorKind::ConnectionRefused => io::ErrorKind::ConnectionRefused,
        ErrorKind::ConnectionReset => io::ErrorKind::ConnectionReset,
        ErrorKind::ConnectionAborted => io::ErrorKind::ConnectionAborted,
        ErrorKind::NotConnected => io::ErrorKind::NotConnected,
        ErrorKind::AddrInUse => io::ErrorKind::AddrInUse,
        ErrorKind::AddrNotAvailable => io::ErrorKind::AddrNotAvailable,
        ErrorKind::TimedOut => io::ErrorKind::TimedOut,
        // `platform::error::ErrorKind` is `#[non_exhaustive]`, and the
        // rest (`NotADirectory`/`IsADirectory`/`DirectoryNotEmpty`/
        // `Other`) are Fs-surface kinds with no socket-relevant
        // `io::ErrorKind` counterpart at this crate's MSRV anyway.
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, e)
}
