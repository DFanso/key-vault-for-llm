//! Connections to database servers: TCP with a time limit, then TLS
//! checked against the platform's trust store.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls_platform_verifier::BuilderVerifierExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Largest single message kv reads from a database server or a leased
/// client: a Postgres message, or one Redis string. Each is held whole
/// while it is scrubbed.
pub const MAX_WIRE_MESSAGE: usize = 16 * 1024 * 1024;

/// A connection to a database server, with or without TLS.
pub enum Upstream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

pub async fn tcp(host: &str, port: u16) -> io::Result<TcpStream> {
    match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port))).await {
        Ok(connected) => connected,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "the server did not answer in time",
        )),
    }
}

/// Starts TLS on `stream`, checking the certificate for `host`.
pub async fn tls(stream: TcpStream, host: &str) -> io::Result<Upstream> {
    let config = tls_config().map_err(io::Error::other)?;
    let name = ServerName::try_from(host.to_owned())
        .map_err(|_| io::Error::other("the host name is not valid for TLS"))?;
    let connecting = TlsConnector::from(Arc::new(config)).connect(name, stream);
    match tokio::time::timeout(CONNECT_TIMEOUT, connecting).await {
        Ok(connected) => connected.map(|s| Upstream::Tls(Box::new(s))),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "the TLS handshake did not finish in time",
        )),
    }
}

/// Certificates are always checked against the platform's trust store.
pub fn tls_config() -> Result<rustls::ClientConfig, String> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .and_then(|builder| builder.with_platform_verifier())
        .map(|builder| builder.with_no_client_auth())
        .map_err(|e| format!("could not set up TLS: {e}"))
}

/// Reads protocol messages from a stream into a buffer. Only `fill` waits,
/// and it keeps what it read in the buffer, so a read that is cancelled in
/// a `select!` loses nothing.
pub struct Buffered<R> {
    inner: R,
    buf: Vec<u8>,
    start: usize,
}

impl<R: AsyncRead + Unpin> Buffered<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            buf: Vec::new(),
            start: 0,
        }
    }

    /// Like `new`, with bytes already read from the stream.
    pub fn with_data(inner: R, data: Vec<u8>) -> Self {
        Self {
            inner,
            buf: data,
            start: 0,
        }
    }

    /// The stream, and what was read from it but not consumed.
    pub fn into_parts(self) -> (R, Vec<u8>) {
        let rest = self.buf[self.start..].to_vec();
        (self.inner, rest)
    }

    /// The bytes read but not yet consumed.
    pub fn data(&self) -> &[u8] {
        &self.buf[self.start..]
    }

    pub fn consume(&mut self, n: usize) {
        self.start += n;
        if self.start == self.buf.len() {
            self.buf.clear();
            self.start = 0;
        }
    }

    /// Reads more; `false` at the end of the stream.
    pub async fn fill(&mut self) -> io::Result<bool> {
        if self.start > 0 && self.start * 2 >= self.buf.len() {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        let mut chunk = [0u8; 16 * 1024];
        let n = self.inner.read(&mut chunk).await?;
        self.buf.extend_from_slice(&chunk[..n]);
        Ok(n > 0)
    }

    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }
}

impl AsyncRead for Upstream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Upstream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}
