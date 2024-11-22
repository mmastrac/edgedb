//! This module provides functionality to connect to Tokio TCP and Unix sockets.

use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;

use derive_more::From;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// Represents a socket address for Tokio connections, supporting both TCP and Unix sockets.
#[derive(From, Debug)]
pub enum TokioSocketAddress {
    /// TCP socket address
    Tcp(SocketAddr),
    /// Unix socket address (only available on Unix systems)
    #[cfg(unix)]
    Unix(PathBuf),
}

impl TokioSocketAddress {
    /// Creates a new TCP socket address
    #[inline(always)]
    pub fn new_tcp(addr: SocketAddr) -> Self {
        TokioSocketAddress::Tcp(addr)
    }

    /// Creates a new Unix socket address (only available on Unix systems)
    #[inline(always)]
    #[cfg(unix)]
    pub fn new_unix<P: AsRef<Path>>(path: P) -> Self {
        TokioSocketAddress::Unix(path.as_ref().into())
    }
}

impl TokioSocketAddress {
    /// Connects to the socket address and returns a TokioStream
    pub async fn connect(&self) -> std::io::Result<TokioStream> {
        match self {
            TokioSocketAddress::Tcp(addr) => {
                let stream = TcpStream::connect(addr).await?;
                Ok(TokioStream::Tcp(stream))
            }
            #[cfg(unix)]
            TokioSocketAddress::Unix(path) => {
                let stream = UnixStream::connect(path).await?;
                Ok(TokioStream::Unix(stream))
            }
        }
    }
}

/// Represents a connected Tokio stream, either TCP or Unix
pub enum TokioStream {
    /// TCP stream
    Tcp(TcpStream),
    /// Unix stream (only available on Unix systems)
    #[cfg(unix)]
    Unix(UnixStream),
}

impl AsyncRead for TokioStream {
    #[inline(always)]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            TokioStream::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(unix)]
            TokioStream::Unix(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TokioStream {
    #[inline(always)]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match self.get_mut() {
            TokioStream::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(unix)]
            TokioStream::Unix(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    #[inline(always)]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            TokioStream::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(unix)]
            TokioStream::Unix(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    #[inline(always)]
    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            TokioStream::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(unix)]
            TokioStream::Unix(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }

    #[inline(always)]
    fn is_write_vectored(&self) -> bool {
        match self {
            TokioStream::Tcp(stream) => stream.is_write_vectored(),
            #[cfg(unix)]
            TokioStream::Unix(stream) => stream.is_write_vectored(),
        }
    }

    #[inline(always)]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        match self.get_mut() {
            TokioStream::Tcp(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
            #[cfg(unix)]
            TokioStream::Unix(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
        }
    }
}
