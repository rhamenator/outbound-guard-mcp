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

// An independent oracle for a deliberately narrow raw-wire grammar. The outer
// Option distinguishes out-of-scope input from an expected allowed response.
// Hyper does not participate in parsing these bytes or computing this rule.
#[cfg(feature = "policy-fuzz")]
fn wire_framing_expectation(input: &[u8]) -> Option<Option<&'static str>> {
    let end = input.windows(4).position(|part| part == b"\r\n\r\n")?;
    let header = std::str::from_utf8(&input[..end]).ok()?;
    let mut lines = header.split("\r\n");
    let status = lines.next()?;
    if !matches!(
        status,
        "HTTP/1.0 200 OK"
            | "HTTP/1.1 200 OK"
            | "HTTP/1.0 206 Partial Content"
            | "HTTP/1.1 206 Partial Content"
            | "HTTP/1.1 204 No Content"
            | "HTTP/1.1 205 Reset Content"
    ) {
        return None;
    }
    let mut lengths = Vec::new();
    let mut codings = Vec::new();
    for line in lines {
        if line.contains(['\r', '\n']) {
            return None;
        }
        let (name, value) = line.split_once(':')?;
        let value = value.trim_matches([' ', '\t']);
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ' || byte == b'\t')
        {
            return None;
        }
        if name.eq_ignore_ascii_case("Content-Length") {
            lengths.push(value);
        } else if name.eq_ignore_ascii_case("Transfer-Encoding") {
            codings.push(value);
        } else {
            return None;
        }
    }
    if lengths.len() > 1 || (!lengths.is_empty() && !codings.is_empty()) {
        return Some(Some("EGRESS_INVALID_FRAMING"));
    }
    if lengths.first().is_some_and(|value| {
        value.is_empty()
            || value
                .bytes()
                .try_fold(0u64, |n, byte| {
                    if !byte.is_ascii_digit() {
                        return None;
                    }
                    n.checked_mul(10)?.checked_add(u64::from(byte - b'0'))
                })
                .is_none()
    }) {
        return Some(Some("EGRESS_INVALID_FRAMING"));
    }
    if codings.len() > 1
        || codings
            .first()
            .is_some_and(|value| !value.eq_ignore_ascii_case("chunked"))
    {
        return Some(Some("EGRESS_UNSUPPORTED_TRANSFER_CODING"));
    }
    if status == "HTTP/1.1 204 No Content" && (!lengths.is_empty() || !codings.is_empty()) {
        return Some(Some("EGRESS_INVALID_FRAMING"));
    }
    if status == "HTTP/1.1 205 Reset Content"
        && lengths
            .first()
            .is_some_and(|value| value.parse::<u64>().is_ok_and(|length| length != 0))
    {
        return Some(Some("EGRESS_INVALID_FRAMING"));
    }
    Some(None)
}

// Only these exact 205 bodies have an independent raw-byte body oracle. Keep
// malformed or more general chunk streams outside this semantic comparison.
#[cfg(feature = "policy-fuzz")]
fn wire_205_body_expectation(input: &[u8]) -> Option<bool> {
    let end = input.windows(4).position(|part| part == b"\r\n\r\n")?;
    let header = &input[..end];
    let body = &input[end + 4..];
    match header {
        b"HTTP/1.1 205 Reset Content\r\nContent-Length: 0" if body.is_empty() => Some(false),
        b"HTTP/1.1 205 Reset Content\r\nTransfer-Encoding: chunked" => match body {
            b"0\r\n\r\n" => Some(false),
            b"1\r\na\r\n0\r\n\r\n" => Some(true),
            _ => None,
        },
        b"HTTP/1.1 205 Reset Content" if body == b"a" => Some(true),
        _ => None,
    }
}

// Development-only raw-wire parser campaign. The duplex peer is entirely in
// process; this exercises Hyper's configured HTTP/1 parser and body framing
// without DNS, a TCP socket, or TLS.
#[cfg(feature = "policy-fuzz")]
pub fn fuzz_http_wire(input: &[u8]) -> bool {
    use http_body_util::BodyExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    thread_local! {
        static RUNTIME: tokio::runtime::Runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("fuzz runtime");
    }
    RUNTIME.with(|runtime| {
        runtime.block_on(async {
            let expected = wire_framing_expectation(input);
            let (mut peer, socket) = tokio::io::duplex(8192);
            let wire = input.to_vec();
            let peer_task = tokio::spawn(async move {
                let mut request = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    let count = peer.read(&mut chunk).await.expect("fixture request read");
                    assert!(count != 0, "fixture request closed before headers");
                    request.extend_from_slice(&chunk[..count]);
                    assert!(
                        request.len() <= MAX_REQUEST_BYTES,
                        "fixture request over budget"
                    );
                    if request.windows(4).any(|part| part == b"\r\n\r\n") {
                        break;
                    }
                }
                peer.write_all(&wire).await.expect("bounded fixture write");
                peer.shutdown().await.expect("fixture EOF");
            });
            let flags = Arc::new(Flags::default());
            let io = BudgetIo::new(socket, 4096, MAX_REQUEST_BYTES, flags);
            let mut builder = http1::Builder::new();
            builder
                .max_headers(MAX_RESPONSE_HEADERS)
                .max_buf_size(MAX_RESPONSE_HEADER_BYTES);
            let Ok((mut sender, connection)) = builder.handshake(TokioIo::new(io)).await else {
                peer_task.abort();
                if let Err(error) = peer_task.await {
                    if error.is_panic() {
                        std::panic::resume_unwind(error.into_panic());
                    }
                }
                return false;
            };
            let driver = tokio::spawn(async move {
                let _ = connection.await;
            });
            let request = Request::builder()
                .uri("/")
                .header("Host", "fixture.test")
                .body(Empty::<Bytes>::new())
                .expect("fixed request");
            let parsed =
                tokio::time::timeout(Duration::from_millis(100), sender.send_request(request))
                    .await
                    .expect("closed fixture response parser stalled");
            let accepted = parsed.is_ok();
            if let Ok(mut response) = parsed {
                let body_expected = wire_205_body_expectation(input);
                let actual =
                    crate::response_status_framing_denial(response.status(), response.headers());
                if let Some(expected) = expected {
                    assert_eq!(actual.as_ref().map(|denial| denial.rule), expected);
                }
                if actual.is_none() {
                    let mut completed = false;
                    let mut body_ok = false;
                    let mut body_bytes = Vec::new();
                    for _ in 0..1024 {
                        let frame = tokio::time::timeout(
                            Duration::from_millis(100),
                            response.body_mut().frame(),
                        )
                        .await
                        .expect("closed fixture body parser stalled");
                        match frame {
                            Some(Ok(frame)) => {
                                if let Some(data) = frame.data_ref() {
                                    body_bytes.extend_from_slice(data);
                                    assert!(body_bytes.len() <= 4096, "fixture body over budget");
                                }
                            }
                            other => {
                                body_ok = other.is_none();
                                completed = true;
                                break;
                            }
                        }
                    }
                    assert!(completed, "bounded fixture yielded too many body frames");
                    if let Some(expected_nonempty) = body_expected {
                        assert!(body_ok, "classified 205 fixture body failed to parse");
                        assert_eq!(body_bytes.is_empty(), !expected_nonempty);
                        let body_denial =
                            crate::response_status_body_denial(response.status(), &body_bytes);
                        assert_eq!(
                            body_denial.as_ref().map(|denial| denial.rule),
                            expected_nonempty.then_some("EGRESS_INVALID_FRAMING")
                        );
                    }
                }
            }
            driver.abort();
            if let Err(error) = driver.await {
                if error.is_panic() {
                    std::panic::resume_unwind(error.into_panic());
                }
            }
            peer_task.abort();
            if let Err(error) = peer_task.await {
                if error.is_panic() {
                    std::panic::resume_unwind(error.into_panic());
                }
            }
            accepted
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[cfg(feature = "policy-fuzz")]
    #[test]
    fn raw_wire_oracle_tracks_strict_framing_cases_through_hyper() {
        let cases: &[(&[u8], Option<Option<&str>>)] = &[
            (b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", Some(None)),
            (b"HTTP/1.1 200 OK\r\nContent-Length: 1, 1\r\n\r\na", Some(Some("EGRESS_INVALID_FRAMING"))),
            (b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\na", Some(Some("EGRESS_INVALID_FRAMING"))),
            (b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", Some(Some("EGRESS_INVALID_FRAMING"))),
            (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", Some(Some("EGRESS_UNSUPPORTED_TRANSFER_CODING"))),
            (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", Some(None)),
            (b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok", Some(None)),
            (b"HTTP/1.0 206 Partial Content\r\nContent-Length: 1, 1\r\n\r\na", Some(Some("EGRESS_INVALID_FRAMING"))),
            (b"HTTP/1.1 206 Partial Content\r\nContent-Length: 2\r\n\r\nok", Some(None)),
            (b"HTTP/1.1 206 Partial Content\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", Some(Some("EGRESS_UNSUPPORTED_TRANSFER_CODING"))),
            (b"HTTP/1.1 204 No Content\r\n\r\n", Some(None)),
            (b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n", Some(Some("EGRESS_INVALID_FRAMING"))),
            (b"HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", Some(Some("EGRESS_INVALID_FRAMING"))),
            (b"HTTP/1.1 205 Reset Content\r\nContent-Length: 0\r\n\r\n", Some(None)),
            (b"HTTP/1.1 205 Reset Content\r\nContent-Length: 2\r\n\r\nok", Some(Some("EGRESS_INVALID_FRAMING"))),
            (b"HTTP/1.1 205 Reset Content\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", Some(None)),
            (b"HTTP/1.1 205 Reset Content\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\n\r\n", Some(None)),
            (b"HTTP/1.1 205 Reset Content\r\n\r\na", Some(None)),
            (b"HTTP/1.1 200 OK\r\nX-Other: 1\r\n\r\n", None),
        ];
        for (wire, expected) in cases {
            assert_eq!(wire_framing_expectation(wire), *expected);
            let accepted = fuzz_http_wire(wire);
            if *expected == Some(None) {
                assert!(
                    accepted,
                    "valid framing control must reach Hyper response: {wire:?}"
                );
            }
        }
        assert_eq!(
            wire_205_body_expectation(
                b"HTTP/1.1 205 Reset Content\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
            ),
            Some(false)
        );
        assert_eq!(
            wire_205_body_expectation(b"HTTP/1.1 205 Reset Content\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\n\r\n"),
            Some(true)
        );
        assert_eq!(
            wire_205_body_expectation(b"HTTP/1.1 205 Reset Content\r\n\r\na"),
            Some(true)
        );
    }

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
