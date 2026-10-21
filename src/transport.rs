//! HTTP/1 over pinned TCP/TLS with bounded parser and stream budgets.
use crate::{Denial, Target, HTTP_IDLE_TIMEOUT, MAX_RESPONSE_HEADERS, MAX_RESPONSE_HEADER_BYTES};
use bytes::Bytes;
use http_body_util::Empty;
use hyper::{body::Incoming, client::conn::http1, Request, Response};
use hyper_util::rt::TokioIo;
use rustls::{
    pki_types::{CertificateDer, ServerName},
    ClientConfig, RootCertStore,
};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    task::JoinHandle,
    time::{Instant, Sleep},
};
use tokio_rustls::TlsConnector;

pub const MAX_REQUEST_BYTES: usize = 4096;
const HTTP_OVERHEAD_BYTES: usize = 32 * 1024;
const MAX_TLS_READ_BYTES: usize = 1024 * 1024;
const MAX_TLS_WRITE_BYTES: usize = 64 * 1024;

#[derive(Default)]
pub struct Flags {
    read: AtomicBool,
    write: AtomicBool,
}
impl Flags {
    pub fn denial(&self) -> Option<Denial> {
        if self.write.load(Ordering::Acquire) {
            Some(Denial::new(
                "EGRESS_REQUEST_LIMIT",
                "Use a shorter request; the serialized HTTP request budget is 4096 bytes.",
            ))
        } else if self.read.load(Ordering::Acquire) {
            Some(Denial::new(
                "EGRESS_RESPONSE_WIRE_LIMIT",
                "Reduce HTTP framing or response size; the stream byte budget was exhausted.",
            ))
        } else {
            None
        }
    }
}

struct BudgetIo<S> {
    inner: S,
    read_left: usize,
    write_left: usize,
    flags: Arc<Flags>,
    idle: Pin<Box<Sleep>>,
}
impl<S> BudgetIo<S> {
    fn new(inner: S, read: usize, write: usize, flags: Arc<Flags>) -> Self {
        Self {
            inner,
            read_left: read,
            write_left: write,
            flags,
            idle: Box::pin(tokio::time::sleep(HTTP_IDLE_TIMEOUT)),
        }
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for BudgetIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.read_left == 0 {
            this.flags.read.store(true, Ordering::Release);
            return Poll::Ready(Err(io::Error::other("Response stream budget exhausted")));
        }
        if this.idle.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "HTTP read deadline exceeded",
            )));
        }
        let limit = this.read_left.min(buf.remaining());
        let mut limited = ReadBuf::new(buf.initialize_unfilled_to(limit));
        match Pin::new(&mut this.inner).poll_read(cx, &mut limited) {
            Poll::Ready(Ok(())) => {
                let count = limited.filled().len();
                buf.advance(count);
                this.read_left -= count;
                if count != 0 {
                    this.idle.as_mut().reset(Instant::now() + HTTP_IDLE_TIMEOUT);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for BudgetIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.write_left == 0 {
            this.flags.write.store(true, Ordering::Release);
            return Poll::Ready(Err(io::Error::other("Request stream budget exhausted")));
        }
        match Pin::new(&mut this.inner).poll_write(cx, &bytes[..bytes.len().min(this.write_left)]) {
            Poll::Ready(Ok(count)) => {
                this.write_left -= count;
                Poll::Ready(Ok(count))
            }
            other => other,
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

pub struct GuardedResponse {
    pub response: Response<Incoming>,
    pub flags: Arc<Flags>,
    driver: JoinHandle<()>,
}
impl Drop for GuardedResponse {
    fn drop(&mut self) {
        self.driver.abort();
    }
}
fn network_failure() -> Denial {
    Denial::new(
        "EGRESS_NETWORK_FAILURE",
        "The approved endpoint could not be reached securely.",
    )
}

pub async fn send(
    target: &Target,
    extra_ca: &Option<CertificateDer<'static>>,
) -> Result<GuardedResponse, Denial> {
    let flags = Arc::new(Flags::default());
    // All addresses were validated before this function; never resolve here.
    let connection = tokio::time::timeout(Duration::from_secs(3), async {
        let mut connected = None;
        for address in &target.addresses {
            if let Ok(stream) = TcpStream::connect(address).await {
                connected = Some(stream);
                break;
            }
        }
        let tcp = connected.ok_or_else(network_failure)?;
        let raw = BudgetIo::new(
            tcp,
            MAX_TLS_READ_BYTES,
            MAX_TLS_WRITE_BYTES,
            Arc::clone(&flags),
        );
        let stream: Box<dyn Stream> = if target.url.scheme() == "https" {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            if let Some(cert) = extra_ca {
                roots.add(cert.clone()).map_err(|_| network_failure())?;
            }
            let mut config = ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .map_err(|_| network_failure())?
            .with_root_certificates(roots)
            .with_no_client_auth();
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            let name = ServerName::try_from(target.host.clone()).map_err(|_| network_failure())?;
            Box::new(
                TlsConnector::from(Arc::new(config))
                    .connect(name, raw)
                    .await
                    .map_err(|_| network_failure())?,
            )
        } else {
            Box::new(raw)
        };
        Ok::<_, Denial>(stream)
    })
    .await
    .map_err(|_| network_failure())??;
    let io = BudgetIo::new(
        connection,
        target.max_return_bytes + HTTP_OVERHEAD_BYTES,
        MAX_REQUEST_BYTES,
        Arc::clone(&flags),
    );
    let mut builder = http1::Builder::new();
    builder
        .max_headers(MAX_RESPONSE_HEADERS)
        .max_buf_size(MAX_RESPONSE_HEADER_BYTES);
    let (mut sender, connection) = builder
        .handshake(TokioIo::new(io))
        .await
        .map_err(|_| network_failure())?;
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .method(target.method)
        .uri(target.url.path())
        .header("Host", &target.host)
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .body(Empty::<Bytes>::new())
        .map_err(|_| network_failure())?;
    match sender.send_request(request).await {
        Ok(response) => Ok(GuardedResponse {
            response,
            flags,
            driver,
        }),
        Err(error) => {
            driver.abort();
            Err(flags.denial().unwrap_or_else(|| {
                if error.is_parse() {
                    Denial::new(
                        "EGRESS_INVALID_FRAMING",
                        "Use bounded, well-formed HTTP response headers.",
                    )
                } else {
                    network_failure()
                }
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn stream_read_budget_stops_before_consuming_excess_bytes() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let (mut peer, socket) = tokio::io::duplex(64);
                peer.write_all(b"abcdef").await.unwrap();
                drop(peer);
                let flags = Arc::new(Flags::default());
                let mut guarded = BudgetIo::new(socket, 4, 4, Arc::clone(&flags));
                let mut received = Vec::new();
                assert!(guarded.read_to_end(&mut received).await.is_err());
                assert_eq!(received, b"abcd");
                let mut rest = Vec::new();
                guarded.inner.read_to_end(&mut rest).await.unwrap();
                assert_eq!(rest, b"ef");
                assert_eq!(flags.denial().unwrap().rule, "EGRESS_RESPONSE_WIRE_LIMIT");
            });
    }

    #[test]
    fn stream_write_budget_never_emits_excess_bytes() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let (socket, mut peer) = tokio::io::duplex(64);
                let flags = Arc::new(Flags::default());
                let mut guarded = BudgetIo::new(socket, 4, 4, Arc::clone(&flags));
                assert!(guarded.write_all(b"abcdef").await.is_err());
                drop(guarded);
                let mut received = Vec::new();
                peer.read_to_end(&mut received).await.unwrap();
                assert_eq!(received, b"abcd");
                assert_eq!(flags.denial().unwrap().rule, "EGRESS_REQUEST_LIMIT");
            });
    }
}
