//! Atomic outbound GET/HEAD policy. Only this tool's own sockets are guarded.

mod transport;
use http_body_util::BodyExt;
use hyper::header;
use rustls::pki_types::{pem::PemObject, CertificateDer};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, VecDeque},
    io::{self, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, LazyLock, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use url::Url;

const DEFAULT_RETURN_BYTES: usize = 64 * 1024;
const MAX_RETURN_BYTES: usize = 256 * 1024;
const DNS_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_DNS_ADDRESSES: usize = 16;
const HTTP_IDLE_TIMEOUT: Duration = Duration::from_secs(3);
const HTTP_TOTAL_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE_HEADERS: usize = 64;
const MAX_RESPONSE_HEADER_BYTES: usize = 16 * 1024;
const HOST_PER_MINUTE: usize = 60;
const CALLS_PER_HOUR: usize = 1000;
const MAX_CA_BYTES: u64 = 64 * 1024;
static FETCH_ACTIVE: AtomicBool = AtomicBool::new(false);
static EXTRA_CA: LazyLock<Result<Option<CertificateDer<'static>>, &'static str>> =
    LazyLock::new(load_extra_ca);

fn load_extra_ca() -> Result<Option<CertificateDer<'static>>, &'static str> {
    let Some(path) = std::env::var_os("OUTBOUND_GUARD_EXTRA_CA_CERT") else {
        return Ok(None);
    };
    let error = "OUTBOUND_GUARD_EXTRA_CA_CERT must name a regular file containing one valid PEM certificate, at most 64 KiB, without private keys";
    if !std::fs::metadata(&path).map_err(|_| error)?.is_file() {
        return Err(error);
    }
    let file = std::fs::File::open(path).map_err(|_| error)?;
    if !file.metadata().map_err(|_| error)?.is_file() {
        return Err(error);
    }
    let mut bytes = Vec::new();
    file.take(MAX_CA_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| error)?;
    if bytes.len() as u64 > MAX_CA_BYTES || bytes.windows(11).any(|part| part == b"PRIVATE KEY") {
        return Err(error);
    }
    let mut certs = CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| error)?;
    if certs.len() != 1 {
        return Err(error);
    }
    let cert = certs.pop().ok_or(error)?;
    rustls::RootCertStore::empty()
        .add(cert.clone())
        .map_err(|_| error)?;
    Ok(Some(cert))
}

pub fn validate_tls_configuration() -> Result<(), &'static str> {
    EXTRA_CA.as_ref().map(|_| ()).map_err(|error| *error)
}
static DNS_WORKER_ACTIVE: AtomicBool = AtomicBool::new(false);
static EGRESS_BUDGET: LazyLock<Mutex<CallBudget>> =
    LazyLock::new(|| Mutex::new(CallBudget::default()));
const AUDIT_CAPACITY: usize = 256;
pub const AUDIT_URI: &str = "outbound-guard://logs/audit.json";
static AUDIT: LazyLock<Mutex<AuditLog>> = LazyLock::new(|| Mutex::new(AuditLog::default()));

#[derive(Default)]
struct AuditLog {
    sequence: u64,
    events: VecDeque<Value>,
}

impl AuditLog {
    fn begin(&mut self) -> Option<String> {
        self.sequence = self.sequence.checked_add(1)?;
        Some(format!("egress-{}", self.sequence))
    }

    fn record(&mut self, correlation_id: &str, decision: &Value) {
        if self.events.len() == AUDIT_CAPACITY {
            self.events.pop_front();
        }
        // Whitelist fields: never retain URLs, arguments, response text, or RPC IDs.
        self.events.push_back(json!({
            "correlation_id": correlation_id,
            "status": decision["status"],
            "rule": decision["rule"],
        }));
    }

    fn snapshot(&self) -> Value {
        json!({"capacity": AUDIT_CAPACITY, "scope": "process", "events": self.events})
    }
}

pub fn audit_snapshot() -> Result<Value, &'static str> {
    AUDIT
        .lock()
        .map(|log| log.snapshot())
        .map_err(|_| "Audit unavailable")
}

// Four one-second buckets: current partial second plus three completed seconds.
// Fixed storage prevents a byte-at-a-time peer from growing timing state.
#[derive(Default)]
struct TransferRate {
    buckets: [usize; 4],
    tick: u64,
}

impl TransferRate {
    fn observe(&mut self, elapsed: Duration, bytes: usize) -> bool {
        let tick = elapsed.as_secs();
        for offset in 1..=tick.saturating_sub(self.tick).min(4) {
            self.buckets[((self.tick + offset) % 4) as usize] = 0;
        }
        self.tick = tick;
        self.buckets[(tick % 4) as usize] += bytes;
        tick < 3
            || (1..=3)
                .map(|age| self.buckets[((tick - age) % 4) as usize])
                .sum::<usize>()
                >= 1500
    }
}

#[derive(Default)]
struct CallBudget {
    per_host: HashMap<String, VecDeque<Instant>>,
    all_calls: VecDeque<Instant>,
}

impl CallBudget {
    fn reserve(&mut self, host: &str, now: Instant) -> bool {
        self.all_calls
            .retain(|at| now.saturating_duration_since(*at) < Duration::from_secs(3600));
        self.per_host.retain(|_, calls| {
            calls.retain(|at| now.saturating_duration_since(*at) < Duration::from_secs(60));
            !calls.is_empty()
        });
        if self.all_calls.len() >= CALLS_PER_HOUR
            || self
                .per_host
                .get(host)
                .is_some_and(|calls| calls.len() >= HOST_PER_MINUTE)
        {
            return false;
        }
        self.all_calls.push_back(now);
        self.per_host
            .entry(host.to_owned())
            .or_default()
            .push_back(now);
        true
    }
}

fn reserve_egress_call(host: &str) -> Result<(), Denial> {
    let mut budget = EGRESS_BUDGET.lock().map_err(|_| {
        Denial::new(
            "EGRESS_BUDGET_FAILURE",
            "The local egress budget is unavailable; restart the server.",
        )
    })?;
    if budget.reserve(host, Instant::now()) {
        Ok(())
    } else {
        Err(Denial::new(
            "EGRESS_RATE_LIMIT",
            "Wait for the per-host minute or process-hour budget to reset.",
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denial {
    pub rule: &'static str,
    pub remediation: &'static str,
}

impl Denial {
    fn new(rule: &'static str, remediation: &'static str) -> Self {
        Self { rule, remediation }
    }
    pub fn value(&self) -> Value {
        json!({"status":"BLOCKED","rule":self.rule,"remediation":self.remediation})
    }
}

pub trait Resolver {
    fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>>;
}

pub struct SystemResolver;
impl Resolver for SystemResolver {
    fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        CancellableSystemResolver(&AtomicBool::new(false)).resolve(host, port)
    }
}

struct CancellableSystemResolver<'a>(&'a AtomicBool);
impl Resolver for CancellableSystemResolver<'_> {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        // A terminal dot makes the lookup absolute: resolver search/ndots
        // settings must not select a different name than the approved host.
        // Keep this resolver-only; URL, Host and TLS SNI retain the original.
        let mut host = host.to_owned();
        if !host.ends_with('.') {
            host.push('.');
        }
        resolve_bounded(&DNS_WORKER_ACTIVE, DNS_TIMEOUT, self.0, move || {
            (host.as_str(), port)
                .to_socket_addrs()
                .map(|answers| answers.take(MAX_DNS_ADDRESSES + 1).collect())
        })
    }
}

// getaddrinfo cannot be cancelled portably. Keep at most one outstanding OS lookup;
// after timeout or waiter cancellation, deny requests until the worker exits.
fn resolve_bounded<F>(
    gate: &'static AtomicBool,
    timeout: Duration,
    cancel: &AtomicBool,
    lookup: F,
) -> io::Result<Vec<SocketAddr>>
where
    F: FnOnce() -> io::Result<Vec<SocketAddr>> + Send + 'static,
{
    if cancel.load(Ordering::Acquire) {
        return Err(io::Error::from(io::ErrorKind::Interrupted));
    }
    let started = Instant::now();
    if gate
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(io::Error::new(io::ErrorKind::WouldBlock, "DNS worker busy"));
    }
    struct ReleaseGate(&'static AtomicBool);
    impl Drop for ReleaseGate {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }
    let (sender, receiver) = mpsc::sync_channel(1);
    if let Err(error) = thread::Builder::new()
        .name("outbound-guard-dns".into())
        .spawn(move || {
            let release = ReleaseGate(gate);
            let result = lookup();
            drop(release);
            let _ = sender.send(result);
        })
    {
        gate.store(false, Ordering::Release);
        return Err(error);
    }
    loop {
        if cancel.load(Ordering::Acquire) {
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "DNS deadline exceeded",
            ));
        }
        match receiver.recv_timeout(remaining.min(Duration::from_millis(25))) {
            Ok(result) => return result,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "DNS worker exited without a result",
                ));
            }
        }
    }
}

pub struct Target {
    pub url: Url,
    pub host: String,
    pub addresses: Vec<SocketAddr>,
    pub max_return_bytes: usize,
    pub method: &'static str,
}

pub fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => public_v4(ip),
        IpAddr::V6(ip) => public_v6(ip),
    }
}

fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113))
}

fn public_v6(ip: Ipv6Addr) -> bool {
    if ip.to_ipv4_mapped().is_some() {
        return false;
    }
    let segments = ip.segments();
    let first = segments[0];
    // Conservative global-unicast policy. Exclude transition and documentation ranges.
    (first & 0xe000) == 0x2000
        && first != 0x2002
        && !(first == 0x3fff && (segments[1] & 0xf000) == 0)
        && !(first == 0x2001 && (segments[1] <= 0x01ff || segments[1] == 0x0db8))
}

fn has_known_secret(text: &str) -> bool {
    let bytes = text.as_bytes();
    for (prefix, count) in [
        (b"AKIA".as_slice(), 16),
        (b"ASIA".as_slice(), 16),
        (b"ghp_".as_slice(), 20),
        (b"gho_".as_slice(), 20),
        (b"github_pat_".as_slice(), 20),
        (b"ghu_".as_slice(), 20),
        (b"ghs_".as_slice(), 20),
        (b"ghr_".as_slice(), 20),
        (b"sk-".as_slice(), 20),
        (b"glpat-".as_slice(), 20),
        (b"gloas-".as_slice(), 20),
        (b"gldt-".as_slice(), 20),
        (b"glrt-".as_slice(), 20),
        (b"glrtr-".as_slice(), 20),
        (b"glcbt-".as_slice(), 20),
        (b"glptt-".as_slice(), 20),
        (b"glft-".as_slice(), 20),
        (b"glimt-".as_slice(), 20),
        (b"glagent-".as_slice(), 20),
        (b"glwt-".as_slice(), 20),
        (b"glsoat-".as_slice(), 20),
        (b"glffct-".as_slice(), 20),
        (b"pypi-".as_slice(), 20),
    ] {
        for item in bytes.windows(prefix.len() + count) {
            if item.starts_with(prefix)
                && item[prefix.len()..]
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_' || *byte == b'-')
            {
                return true;
            }
        }
    }
    text.contains("-----BEGIN PRIVATE KEY-----")
}

fn high_entropy_segment(text: &str) -> bool {
    text.split(|ch: char| !ch.is_ascii_alphanumeric() && !matches!(ch, '_' | '-' | '+' | '='))
        .filter(|segment| segment.len() >= 40)
        .any(|segment| {
            let mut counts = [0usize; 256];
            for byte in segment.bytes() {
                counts[byte as usize] += 1;
            }
            counts
                .into_iter()
                .filter(|count| *count > 0)
                .map(|count| {
                    let p = count as f64 / segment.len() as f64;
                    -p * p.log2()
                })
                .sum::<f64>()
                >= 4.5
        })
}

pub fn validate<R: Resolver>(
    args: &Value,
    allowed_hosts: &[String],
    resolver: &R,
) -> Result<Target, Denial> {
    validate_with_reservation(args, allowed_hosts, resolver, |_| Ok(()))
}

fn validate_with_reservation<R: Resolver, F: FnOnce(&str) -> Result<(), Denial>>(
    args: &Value,
    allowed_hosts: &[String],
    resolver: &R,
    reserve: F,
) -> Result<Target, Denial> {
    let obj = args
        .as_object()
        .ok_or_else(|| Denial::new("EGRESS_INVALID_INPUT", "Provide a JSON object."))?;
    if obj
        .keys()
        .any(|key| !matches!(key.as_str(), "url" | "method" | "max_return_bytes"))
    {
        return Err(Denial::new(
            "EGRESS_INVALID_INPUT",
            "Only url, method, and max_return_bytes are supported.",
        ));
    }
    let raw = obj
        .get("url")
        .and_then(Value::as_str)
        .ok_or_else(|| Denial::new("EGRESS_INVALID_URL", "Provide an HTTP(S) URL."))?;
    if raw.len() > 2048
        || raw.bytes().any(|byte| {
            byte.is_ascii_control() || byte.is_ascii_whitespace() || byte == b'\\' || byte == b'%'
        })
    {
        return Err(Denial::new(
            "EGRESS_INVALID_URL",
            "Use a short URL without ASCII controls, whitespace, backslashes, or percent encoding.",
        ));
    }
    if has_known_secret(raw) || high_entropy_segment(raw) {
        return Err(Denial::new(
            "EGRESS_SECRET_DETECTED",
            "Remove secret-like material from the URL.",
        ));
    }
    let url = Url::parse(raw)
        .map_err(|_| Denial::new("EGRESS_INVALID_URL", "Provide a valid HTTP(S) URL."))?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
    {
        return Err(Denial::new(
            "EGRESS_INVALID_URL",
            "Only HTTP(S) URLs without userinfo, query, or fragment are supported.",
        ));
    }
    let port = url.port_or_known_default().ok_or_else(|| {
        Denial::new(
            "EGRESS_INVALID_PORT",
            "Use the standard HTTP or HTTPS port.",
        )
    })?;
    if !matches!((url.scheme(), port), ("http", 80) | ("https", 443)) {
        return Err(Denial::new(
            "EGRESS_INVALID_PORT",
            "Use the standard HTTP or HTTPS port.",
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| Denial::new("EGRESS_INVALID_HOST", "Use an approved DNS hostname."))?
        .to_owned();
    if host.parse::<IpAddr>().is_ok() || !valid_dns_name(&host) {
        return Err(Denial::new(
            "EGRESS_INVALID_HOST",
            "Use an approved DNS hostname, not an IP literal or local name.",
        ));
    }
    if !allowed_hosts
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&host))
    {
        return Err(Denial::new(
            "EGRESS_HOST_NOT_ALLOWED",
            "Ask the operator to add this exact hostname to OUTBOUND_GUARD_ALLOWED_HOSTS.",
        ));
    }
    if url.path().len() + host.len() + 128 > transport::MAX_REQUEST_BYTES {
        return Err(Denial::new(
            "EGRESS_REQUEST_LIMIT",
            "Use a shorter URL; serialized request bytes are bounded to 4096.",
        ));
    }
    let method = match obj.get("method") {
        None => "GET",
        Some(Value::String(value)) if value == "GET" => "GET",
        Some(Value::String(value)) if value == "HEAD" => "HEAD",
        _ => {
            return Err(Denial::new(
                "EGRESS_METHOD_DENIED",
                "Only GET and HEAD are supported.",
            ))
        }
    };
    let max_return_bytes = match obj.get("max_return_bytes") {
        None => DEFAULT_RETURN_BYTES,
        Some(Value::Number(number)) => number
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .filter(|n| (1..=MAX_RETURN_BYTES).contains(n))
            .ok_or_else(|| {
                Denial::new(
                    "EGRESS_RESPONSE_LIMIT",
                    "Use max_return_bytes from 1 to 262144.",
                )
            })?,
        _ => {
            return Err(Denial::new(
                "EGRESS_RESPONSE_LIMIT",
                "Use max_return_bytes from 1 to 262144.",
            ))
        }
    };
    reserve(&host)?;
    let addresses = resolver
        .resolve(&host, port)
        .map_err(|error| match error.kind() {
            io::ErrorKind::TimedOut => Denial::new(
                "EGRESS_DNS_TIMEOUT",
                "The DNS lookup exceeded its deadline; retry later.",
            ),
            io::ErrorKind::WouldBlock => Denial::new(
                "EGRESS_DNS_BUSY",
                "A previous DNS lookup is still running; retry later.",
            ),
            _ => Denial::new(
                "EGRESS_DNS_FAILURE",
                "Try the approved hostname again later.",
            ),
        })?;
    if addresses.is_empty() {
        return Err(Denial::new(
            "EGRESS_DNS_FAILURE",
            "The hostname returned no addresses.",
        ));
    }
    if addresses.len() > MAX_DNS_ADDRESSES {
        return Err(Denial::new(
            "EGRESS_DNS_ANSWER_LIMIT",
            "Reduce the hostname's DNS answer set to at most 16 addresses.",
        ));
    }
    if addresses
        .iter()
        .any(|addr| addr.port() != port || !public_ip(addr.ip()))
    {
        return Err(Denial::new(
            "EGRESS_FORBIDDEN_ADDRESS",
            "The hostname resolved to a non-public address; review DNS and policy.",
        ));
    }
    Ok(Target {
        url,
        host,
        addresses,
        max_return_bytes,
        method,
    })
}

fn valid_dns_name(host: &str) -> bool {
    host.len() <= 253
        && host.contains('.')
        && !host.ends_with('.')
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn supported_content_type(value: &str) -> bool {
    let mut parts = value.split(';');
    let media_type = parts.next().unwrap_or("").trim();
    if !media_type.eq_ignore_ascii_case("text/plain")
        && !media_type.eq_ignore_ascii_case("application/json")
    {
        return false;
    }
    // Deliberately narrow: no charset guessing or general MIME parameter parser.
    // Accept only one optional UTF-8 declaration; reject unknown/duplicate params.
    match parts.next() {
        None => true,
        Some(parameter) => {
            let Some((name, value)) = parameter.trim().split_once('=') else {
                return false;
            };
            name.trim().eq_ignore_ascii_case("charset")
                && matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "utf-8" | "\"utf-8\""
                )
                && parts.next().is_none()
        }
    }
}

fn looks_like_html(text: &str) -> bool {
    fn tag_boundary(byte: &u8) -> bool {
        matches!(byte, b'>' | b'/' | b' ' | b'\t' | b'\r' | b'\n' | 0x0c)
    }
    let start = text.trim_start_matches(|ch: char| ch.is_whitespace() || ch == '\u{feff}');
    let bytes = start.as_bytes();
    if [b"<!doctype".as_slice(), b"<!--"].iter().any(|tag| {
        bytes
            .get(..tag.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(tag))
            && (tag == b"<!--" || bytes.get(tag.len()).is_some_and(tag_boundary))
    }) {
        return true;
    }
    [
        "html", "head", "body", "script", "style", "iframe", "svg", "a", "div", "span", "form",
        "input", "button", "img", "meta", "link", "object", "embed", "template", "noscript", "p",
    ]
    .iter()
    .any(|tag| {
        let prefix = format!("<{tag}");
        bytes
            .get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix.as_bytes()))
            && bytes.get(prefix.len()).is_some_and(tag_boundary)
    })
}

pub fn parse_allowed_hosts(value: &str) -> Result<Vec<String>, &'static str> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let mut hosts = Vec::new();
    for raw in value.split(',') {
        let host = raw.trim().to_ascii_lowercase();
        if !valid_dns_name(&host) || host.parse::<IpAddr>().is_ok() {
            return Err("OUTBOUND_GUARD_ALLOWED_HOSTS must contain only exact DNS hostnames separated by commas");
        }
        if !hosts.contains(&host) {
            hosts.push(host);
        }
    }
    Ok(hosts)
}

pub fn allowed_hosts_from_env() -> Result<Vec<String>, &'static str> {
    match std::env::var("OUTBOUND_GUARD_ALLOWED_HOSTS") {
        Ok(value) => parse_allowed_hosts(&value),
        Err(std::env::VarError::NotPresent) => Ok(Vec::new()),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err("OUTBOUND_GUARD_ALLOWED_HOSTS must be valid UTF-8")
        }
    }
}

pub fn guarded_fetch(args: &Value, allowed_hosts: &[String]) -> Value {
    guarded_fetch_cancellable(args, allowed_hosts, &AtomicBool::new(false))
}

/// Cooperative library cancellation. Pending DNS/HTTP operations finish or hit
/// their existing deadlines before observing cancellation.
pub fn guarded_fetch_cancellable(
    args: &Value,
    allowed_hosts: &[String],
    cancel: &AtomicBool,
) -> Value {
    audited_fetch(&AUDIT, || {
        limited_fetch(&FETCH_ACTIVE, || {
            guarded_fetch_inner(args, allowed_hosts, cancel)
        })
    })
}

fn cancellation_denial() -> Denial {
    Denial::new(
        "EGRESS_CANCELLED",
        "The caller cancelled this fetch; no response body is returned.",
    )
}

fn cancelled(cancel: &AtomicBool) -> Option<Value> {
    cancel
        .load(Ordering::Acquire)
        .then(|| cancellation_denial().value())
}

// A permit spans validation, DNS, TLS, and response reading. Excess library
// callers do not queue, reserve a budget slot, or start a resolver/socket.
fn limited_fetch(active: &AtomicBool, fetch: impl FnOnce() -> Value) -> Value {
    if active
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return Denial::new(
            "EGRESS_CONCURRENCY_LIMIT",
            "Retry after the active fetch completes; each process permits one active fetch.",
        )
        .value();
    }
    struct Permit<'a>(&'a AtomicBool);
    impl Drop for Permit<'_> {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }
    let _permit = Permit(active);
    fetch()
}

fn audited_fetch(audit: &Mutex<AuditLog>, fetch: impl FnOnce() -> Value) -> Value {
    let correlation_id = match audit.lock().ok().and_then(|mut log| log.begin()) {
        Some(id) => id,
        None => {
            return Denial::new(
                "EGRESS_AUDIT_FAILURE",
                "Restart the server; the audit log is unavailable.",
            )
            .value()
        }
    };
    let mut decision = fetch();
    decision["correlation_id"] = json!(correlation_id);
    match audit.lock() {
        Ok(mut log) => log.record(&correlation_id, &decision),
        Err(_) => {
            let mut failure = Denial::new(
                "EGRESS_AUDIT_FAILURE",
                "Restart the server; the audit log is unavailable.",
            )
            .value();
            failure["correlation_id"] = json!(correlation_id);
            return failure;
        }
    }
    decision
}

fn guarded_fetch_inner(args: &Value, allowed_hosts: &[String], cancel: &AtomicBool) -> Value {
    if tokio::runtime::Handle::try_current().is_ok() {
        return Denial::new("EGRESS_CLIENT_FAILURE", "Invoke the synchronous API outside an async runtime, for example from a blocking worker.").value();
    }
    if let Some(denial) = cancelled(cancel) {
        return denial;
    }
    let extra_ca = match EXTRA_CA.as_ref() {
        Ok(cert) => cert,
        Err(_) => {
            return Denial::new(
                "EGRESS_TLS_CONFIG_FAILURE",
                "Fix the operator CA certificate configuration and restart the server.",
            )
            .value()
        }
    };
    let validation = validate_with_reservation(
        args,
        allowed_hosts,
        &CancellableSystemResolver(cancel),
        |host| {
            if cancel.load(Ordering::Acquire) {
                Err(cancellation_denial())
            } else {
                reserve_egress_call(host)
            }
        },
    );
    if let Some(denial) = cancelled(cancel) {
        return denial;
    }
    let target = match validation {
        Ok(target) => target,
        Err(denial) => return denial.value(),
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            return Denial::new(
                "EGRESS_CLIENT_FAILURE",
                "The bounded HTTP runtime could not start.",
            )
            .value()
        }
    };
    runtime.block_on(async {
        match tokio::time::timeout(
            HTTP_TOTAL_TIMEOUT,
            guarded_http_fetch(&target, extra_ca, cancel),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Denial::new(
                "EGRESS_RESPONSE_TIMEOUT",
                "The response exceeded the total time limit.",
            )
            .value(),
        }
    })
}

async fn guarded_http_fetch(
    target: &Target,
    extra_ca: &Option<CertificateDer<'static>>,
    cancel: &AtomicBool,
) -> Value {
    let http_started = Instant::now();
    if let Some(denial) = cancelled(cancel) {
        return denial;
    }
    let mut guarded = match transport::send(target, extra_ca).await {
        Ok(response) => response,
        Err(denial) => return denial.value(),
    };
    if let Some(denial) = cancelled(cancel) {
        return denial;
    }
    let response = &mut guarded.response;
    if response.headers().len() > MAX_RESPONSE_HEADERS
        || response
            .headers()
            .iter()
            .map(|(name, value)| name.as_str().len() + value.as_bytes().len() + 4)
            .try_fold(0usize, |total, size| total.checked_add(size))
            .is_none_or(|total| total > MAX_RESPONSE_HEADER_BYTES)
    {
        return Denial::new(
            "EGRESS_RESPONSE_HEADERS_LIMIT",
            "Reduce response header count or size.",
        )
        .value();
    }
    if response.status().is_redirection() {
        return Denial::new(
            "EGRESS_REDIRECT_DENIED",
            "Use the final approved URL directly after policy review.",
        )
        .value();
    }
    if response
        .headers()
        .get_all(header::CONTENT_LENGTH)
        .iter()
        .count()
        > 1
        || (response.headers().contains_key(header::CONTENT_LENGTH)
            && response.headers().contains_key(header::TRANSFER_ENCODING))
    {
        return Denial::new(
            "EGRESS_INVALID_FRAMING",
            "Use a response with unambiguous HTTP message framing.",
        )
        .value();
    }
    if response
        .headers()
        .get_all(header::TRANSFER_ENCODING)
        .iter()
        .count()
        > 1
        || response
            .headers()
            .get(header::TRANSFER_ENCODING)
            .is_some_and(|value| !value.as_bytes().eq_ignore_ascii_case(b"chunked"))
    {
        return Denial::new(
            "EGRESS_UNSUPPORTED_TRANSFER_CODING",
            "Use a response with only chunked transfer coding or no transfer coding.",
        )
        .value();
    }
    if response
        .headers()
        .get_all(header::CONTENT_TYPE)
        .iter()
        .count()
        > 1
        || response
            .headers()
            .get_all(header::CONTENT_ENCODING)
            .iter()
            .count()
            > 1
    {
        return Denial::new(
            "EGRESS_AMBIGUOUS_RESPONSE_METADATA",
            "Use one Content-Type and at most one Content-Encoding field.",
        )
        .value();
    }
    if response
        .headers()
        .get(header::CONTENT_ENCODING)
        .is_some_and(|value| value != "identity")
    {
        return Denial::new(
            "EGRESS_ENCODED_RESPONSE",
            "Request unencoded text from this endpoint.",
        )
        .value();
    }
    if target.method != "HEAD"
        && response
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|length| length > target.max_return_bytes as u64)
    {
        return Denial::new(
            "EGRESS_RESPONSE_LIMIT",
            "Reduce the response size or raise the bounded per-call limit.",
        )
        .value();
    }
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if target.method != "HEAD" && !supported_content_type(content_type) {
        return Denial::new(
            "EGRESS_UNSUPPORTED_CONTENT",
            "Use text/plain or application/json with no parameters or one charset=utf-8 declaration.",
        )
        .value();
    }
    let plain_text = content_type
        .split(';')
        .next()
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("text/plain"));
    let json_content = content_type
        .split(';')
        .next()
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"));
    let status_code = response.status().as_u16();
    let mut body = Vec::new();
    let body_started = Instant::now();
    let mut transfer_rate = TransferRate::default();
    loop {
        if let Some(denial) = cancelled(cancel) {
            return denial;
        }
        if http_started.elapsed() >= HTTP_TOTAL_TIMEOUT {
            return Denial::new(
                "EGRESS_RESPONSE_TIMEOUT",
                "The response exceeded the total time limit.",
            )
            .value();
        }
        let read = match response.body_mut().frame().await {
            None => Ok(None),
            Some(Ok(frame)) => match frame.into_data() {
                Ok(bytes) => Ok(Some(bytes)),
                Err(_) => {
                    return Denial::new(
                        "EGRESS_UNSUPPORTED_TRAILERS",
                        "Return response metadata in headers, not trailers.",
                    )
                    .value()
                }
            },
            Some(Err(error)) => Err(error),
        };
        if let Some(denial) = cancelled(cancel) {
            return denial;
        }
        // Keep deadline classification ahead of rate, EOF and read errors.
        // The async total timer also interrupts a pending read.
        if http_started.elapsed() >= HTTP_TOTAL_TIMEOUT {
            return Denial::new(
                "EGRESS_RESPONSE_TIMEOUT",
                "The response exceeded the total time limit.",
            )
            .value();
        }
        if let Ok(bytes) = &read {
            if !transfer_rate.observe(
                body_started.elapsed(),
                bytes.as_ref().map_or(0, |chunk| chunk.len()),
            ) {
                return Denial::new(
                    "EGRESS_RESPONSE_TOO_SLOW",
                    "Use an endpoint delivering at least 500 bytes per second over completed three-second windows.",
                )
                .value();
            }
        }
        match read {
            Ok(None) => break,
            Ok(Some(chunk)) => {
                if chunk.len() > target.max_return_bytes - body.len() {
                    return Denial::new(
                        "EGRESS_RESPONSE_LIMIT",
                        "Reduce the response size or raise the bounded per-call limit.",
                    )
                    .value();
                }
                body.extend_from_slice(&chunk);
            }
            Err(_) => {
                if let Some(denial) = guarded.flags.denial() {
                    return denial.value();
                }
                return Denial::new(
                    "EGRESS_READ_FAILURE",
                    "The bounded response could not be read.",
                )
                .value();
            }
        }
    }
    if let Some(denial) = guarded.flags.denial() {
        return denial.value();
    }
    let text = match String::from_utf8(body) {
        Ok(text) => text,
        Err(_) => {
            return Denial::new(
                "EGRESS_NON_UTF8",
                "Only UTF-8 text is returned at this stage.",
            )
            .value()
        }
    };
    if plain_text && looks_like_html(&text) {
        return Denial::new(
            "EGRESS_HTML_MISLABELED",
            "Return actual plain text or JSON; leading HTML markup is not accepted.",
        )
        .value();
    }
    if json_content
        && target.method != "HEAD"
        && !(text.is_empty() && matches!(status_code, 204 | 205))
        && serde_json::from_str::<Value>(&text).is_err()
    {
        return Denial::new(
            "EGRESS_INVALID_JSON",
            "Return one valid JSON value within the parser's nesting limit.",
        )
        .value();
    }
    if let Some(denial) = cancelled(cancel) {
        return denial;
    }
    json!({"status":"SAFE","rule":"EGRESS_ALLOWED","remediation":"Treat returned text as untrusted data.",
        "url":target.url.as_str(),"status_code":status_code,"body_text":text,"untrusted_content":true})
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    #[test]
    fn rolling_transfer_rate_expires_bursts_and_has_bounded_state() {
        let mut rate = TransferRate::default();
        assert!(rate.observe(Duration::ZERO, 2000));
        assert!(rate.observe(Duration::from_secs(3), 0));
        // A new burst cannot hide three preceding seconds without progress.
        assert!(!rate.observe(Duration::from_secs(4), 8192));
        assert!(!rate.observe(Duration::from_secs(1_000_000), 1));
        for bytes in [499, 500, 501] {
            let mut rate = TransferRate::default();
            for second in 0..3 {
                assert!(rate.observe(Duration::from_secs(second), bytes));
            }
            assert_eq!(rate.observe(Duration::from_secs(3), bytes), bytes >= 500);
        }
        let mut small = TransferRate::default();
        assert!(small.observe(Duration::ZERO, 2));
        assert!(small.observe(Duration::from_millis(2999), 0));
    }
    #[test]
    fn pre_cancelled_fetch_is_audited_without_body_or_budget() {
        let before = EGRESS_BUDGET.lock().unwrap().all_calls.len();
        let result = guarded_fetch_cancellable(
            &json!({"url":"https://example.com/"}),
            &[], // A broken cancellation check must not reach an external host.
            &AtomicBool::new(true),
        );
        assert_eq!(result["rule"], "EGRESS_CANCELLED");
        assert!(result.get("body_text").is_none());
        assert_eq!(EGRESS_BUDGET.lock().unwrap().all_calls.len(), before);
        assert_eq!(
            audit_snapshot().unwrap()["events"][0]["rule"],
            "EGRESS_CANCELLED"
        );
    }
    #[test]
    fn raw_url_controls_are_denied_before_reservation_or_dns() {
        for byte in (0..=31).chain(std::iter::once(127)) {
            let control = char::from(byte);
            for url in [
                format!("{control}https://example.com/plain"),
                format!("https://example.com/plain{control}"),
                format!("https://example.com/a{control}b"),
            ] {
                let result = validate_with_reservation(
                    &json!({"url":url}),
                    &allowed(),
                    &Fake(vec![]),
                    |_| panic!("Raw controls must fail before reservation or DNS"),
                );
                assert_eq!(result.err().unwrap().rule, "EGRESS_INVALID_URL");
            }
        }
    }
    #[test]
    fn audit_failure_blocks_execution_or_suppresses_completed_body() {
        let audit = Mutex::new(AuditLog::default());
        let poison = || {
            let _ = std::panic::catch_unwind(|| {
                let _guard = audit.lock().unwrap();
                panic!("injected audit failure");
            });
        };
        let result = audited_fetch(&audit, || {
            poison();
            json!({"status":"SAFE", "rule":"EGRESS_ALLOWED", "body_text":"private payload"})
        });
        assert_eq!(result["rule"], "EGRESS_AUDIT_FAILURE");
        assert_eq!(result["correlation_id"], "egress-1");
        assert!(result.get("body_text").is_none());
        let result = audited_fetch(&audit, || panic!("must not execute without audit"));
        assert_eq!(result["rule"], "EGRESS_AUDIT_FAILURE");
    }
    #[test]
    fn audit_evicts_old_events_and_retains_only_safe_fields() {
        let mut log = AuditLog::default();
        for index in 1..=300 {
            let id = log.begin().unwrap();
            assert_eq!(id, format!("egress-{index}"));
            let decision = json!({"status":"SAFE", "rule":"EGRESS_ALLOWED",
                "url":"https://sensitive.example/secret", "body_text":"private payload"});
            log.record(&id, &decision);
        }
        let snapshot = log.snapshot();
        assert_eq!(snapshot["events"].as_array().unwrap().len(), AUDIT_CAPACITY);
        assert_eq!(snapshot["events"][0]["correlation_id"], "egress-45");
        assert_eq!(snapshot["events"][255]["correlation_id"], "egress-300");
        let text = snapshot.to_string();
        assert!(!text.contains("sensitive.example"));
        assert!(!text.contains("private payload"));
        assert_eq!(snapshot["events"][0].as_object().unwrap().len(), 3);
        log.sequence = u64::MAX;
        assert!(log.begin().is_none());
    }
    #[test]
    fn async_context_is_rejected_before_validation_without_panicking() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let decision = runtime.block_on(async {
            guarded_fetch_inner(
                &json!({"url":"http://127.0.0.1/"}),
                &[],
                &AtomicBool::new(false),
            )
        });
        assert_eq!(decision["rule"], "EGRESS_CLIENT_FAILURE");
        assert!(decision.get("body_text").is_none());
    }

    #[test]
    fn content_type_requires_an_exact_supported_media_type() {
        assert!(supported_content_type("text/plain; charset=utf-8"));
        assert!(supported_content_type("application/json"));
        assert!(!supported_content_type("text/plaintext"));
        assert!(!supported_content_type("application/json+html"));
        assert!(!supported_content_type("text/html"));
        assert!(!supported_content_type(""));
        for value in [
            "Text/Plain; CHARSET=\"UTF-8\"",
            "application/json; charset = utf-8",
        ] {
            assert!(supported_content_type(value), "{value}");
        }
        for value in [
            "text/plain; charset=iso-8859-1",
            "application/json; charset=utf-16",
            "text/plain; charset=utf-8; charset=utf-8",
            "text/plain; profile=custom",
            "text/plain; charset=\"utf-8",
            "text/plain;",
        ] {
            assert!(!supported_content_type(value), "{value}");
        }
    }
    #[test]
    fn leading_html_signatures_are_quarantined() {
        for text in [
            "<!DOCTYPE html><html></html>",
            "<!DOCTYPE\u{000c}html>",
            " \u{feff}\n<HTML lang=en>",
            "<a style=\"display:none\" href=\"/trap\">hidden</a>",
            "<script>alert(1)</script>",
            "<script\u{000c}src=x>",
            "<!-- hidden -->",
            "<div style=\"display:none\"><a href=\"/trap\">hidden</a></div>",
            "<span hidden>trap</span>",
        ] {
            assert!(looks_like_html(text), "{text}");
        }
        for tag in [
            "div", "span", "form", "input", "button", "img", "meta", "link", "object", "embed",
            "template", "noscript", "p",
        ] {
            for suffix in [">", "/>", " hidden>", "\tstyle=hidden>", "\u{000c}hidden>"] {
                assert!(looks_like_html(&format!(
                    " \u{feff}<{}{suffix}",
                    tag.to_uppercase()
                )));
            }
            assert!(!looks_like_html(&format!("<{tag}-custom>")));
            assert!(!looks_like_html(&format!("<{tag}example>")));
        }
        for text in [
            "ordinary plain text",
            "This is <html> in a sentence",
            "<algorithm>",
            "<a-not-a-tag>",
        ] {
            assert!(!looks_like_html(text), "{text}");
        }
    }
    struct Fake(Vec<SocketAddr>);
    impl Resolver for Fake {
        fn resolve(&self, _: &str, _: u16) -> std::io::Result<Vec<SocketAddr>> {
            Ok(self.0.clone())
        }
    }
    fn allowed() -> Vec<String> {
        vec!["example.com".into()]
    }
    fn addr(ip: &str) -> SocketAddr {
        SocketAddr::new(ip.parse().unwrap(), 443)
    }
    #[test]
    fn provider_token_shapes_are_denied_before_budget_or_dns() {
        struct NoDns;
        impl Resolver for NoDns {
            fn resolve(&self, _: &str, _: u16) -> io::Result<Vec<SocketAddr>> {
                panic!("token reached DNS")
            }
        }
        for prefix in [
            "github_pat_",
            "ghu_",
            "ghs_",
            "ghr_",
            "glpat-",
            "gloas-",
            "gldt-",
            "glrt-",
            "glrtr-",
            "glcbt-",
            "glptt-",
            "glft-",
            "glimt-",
            "glagent-",
            "glwt-",
            "glsoat-",
            "glffct-",
            "pypi-",
        ] {
            for suffix in ["A".repeat(20), "a0_-".repeat(9)] {
                let token = format!("{prefix}{suffix}");
                for path in [token.clone(), format!("docs/{token}/data")] {
                    let args = json!({"url":format!("https://example.com/{path}")});
                    let result = validate_with_reservation(&args, &allowed(), &NoDns, |_| {
                        panic!("token reached budget reservation")
                    });
                    assert_eq!(result.err().unwrap().rule, "EGRESS_SECRET_DETECTED");
                }
            }
            for path in [
                format!("{prefix}{}", "A".repeat(19)),
                format!("{prefix}guide"),
            ] {
                assert!(validate(
                    &json!({"url":format!("https://example.com/{path}")}),
                    &allowed(),
                    &Fake(vec![addr("8.8.8.8")])
                )
                .is_ok());
            }
        }
    }

    #[test]
    fn rejects_private_and_mixed_dns() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "169.254.1.1",
            "100.64.1.1",
            "192.88.99.2",
            "192.168.1.1",
            "::1",
            "::ffff:8.8.8.8",
            "2001:db8::1",
            "3fff::1",
            "3fff:0fff::1",
        ] {
            let result = validate(
                &json!({"url":"https://example.com/"}),
                &allowed(),
                &Fake(vec![addr(ip)]),
            );
            assert_eq!(
                result.err().unwrap().rule,
                "EGRESS_FORBIDDEN_ADDRESS",
                "{ip}"
            );
        }
        let mixed = Fake(vec![addr("8.8.8.8"), addr("127.0.0.1")]);
        assert_eq!(
            validate(&json!({"url":"https://example.com/"}), &allowed(), &mixed)
                .err()
                .unwrap()
                .rule,
            "EGRESS_FORBIDDEN_ADDRESS"
        );
        let mixed_v6 = Fake(vec![addr("2606:4700:4700::1111"), addr("3fff::1")]);
        assert_eq!(
            validate(
                &json!({"url":"https://example.com/"}),
                &allowed(),
                &mixed_v6
            )
            .err()
            .unwrap()
            .rule,
            "EGRESS_FORBIDDEN_ADDRESS"
        );
        assert!(public_ip("3fff:1000::1".parse().unwrap()));
    }
    #[test]
    fn special_use_prefix_boundaries_stay_denied() {
        // Independent boundary matrix from the IANA IPv4/IPv6 special-purpose registries.
        // Sample both edges and the interior so a narrowed mask cannot admit part of a block.
        let denied_v4 = [
            ("0.0.0.0", 8),
            ("10.0.0.0", 8),
            ("100.64.0.0", 10),
            ("127.0.0.0", 8),
            ("169.254.0.0", 16),
            ("172.16.0.0", 12),
            ("192.0.0.0", 24),
            ("192.0.2.0", 24),
            ("192.88.99.0", 24),
            ("192.168.0.0", 16),
            ("198.18.0.0", 15),
            ("198.51.100.0", 24),
            ("203.0.113.0", 24),
            ("224.0.0.0", 4),
            ("240.0.0.0", 4),
        ];
        for (base, prefix) in denied_v4 {
            let first = u32::from(base.parse::<Ipv4Addr>().unwrap());
            let last = first | (u32::MAX >> prefix);
            for value in [first, first + 1, first + (last - first) / 2, last - 1, last] {
                let ip = Ipv4Addr::from(value);
                assert!(!public_v4(ip), "{base}/{prefix} admitted {ip}");
            }
        }
        for ip in [
            "1.1.1.1",
            "8.8.8.8",
            "100.63.255.255",
            "100.128.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "198.17.255.255",
            "198.20.0.0",
        ] {
            assert!(public_v4(ip.parse().unwrap()), "{ip}");
        }

        let denied_v6 = [
            ("::", 128),
            ("::1", 128),
            ("::ffff:0:0", 96),
            ("64:ff9b:1::", 48),
            ("100::", 64),
            ("2001::", 23),
            ("2001:db8::", 32),
            ("2002::", 16),
            ("3fff::", 20),
            ("5f00::", 16),
            ("fc00::", 7),
            ("fe80::", 10),
        ];
        for (base, prefix) in denied_v6 {
            let first = u128::from(base.parse::<Ipv6Addr>().unwrap());
            let last = first
                | if prefix == 128 {
                    0
                } else {
                    u128::MAX >> prefix
                };
            let samples = if first == last {
                vec![first]
            } else {
                vec![first, first + 1, first + (last - first) / 2, last - 1, last]
            };
            for value in samples {
                let ip = Ipv6Addr::from(value);
                assert!(!public_v6(ip), "{base}/{prefix} admitted {ip}");
            }
        }
        for ip in ["2606:4700:4700::1111", "3fff:1000::1"] {
            assert!(public_v6(ip.parse().unwrap()), "{ip}");
        }
    }
    #[test]
    fn oversized_dns_answer_set_is_denied_before_connection() {
        let answers: Vec<_> = (1..=MAX_DNS_ADDRESSES + 1)
            .map(|n| addr(&format!("11.0.0.{n}")))
            .collect();
        assert!(validate(
            &json!({"url":"https://example.com/"}),
            &allowed(),
            &Fake(answers[..MAX_DNS_ADDRESSES].to_vec())
        )
        .is_ok());
        let denial = validate(
            &json!({"url":"https://example.com/"}),
            &allowed(),
            &Fake(answers),
        )
        .err()
        .unwrap();
        assert_eq!(denial.rule, "EGRESS_DNS_ANSWER_LIMIT");
    }
    #[test]
    fn validates_public_pinned_target() {
        let result = validate(
            &json!({"url":"https://example.com/","method":"HEAD"}),
            &allowed(),
            &Fake(vec![addr("8.8.8.8")]),
        )
        .unwrap();
        assert_eq!(result.addresses, vec![addr("8.8.8.8")]);
        assert_eq!(result.method, "HEAD");
        let args =
            serde_json::from_str(r#"{"url":"https://example.com/","max_return_bytes":1e400}"#)
                .unwrap();
        let result = validate_with_reservation(&args, &allowed(), &Fake(vec![]), |_| {
            panic!("Oversized numeric limits must fail before reservation or DNS")
        });
        assert_eq!(result.err().unwrap().rule, "EGRESS_RESPONSE_LIMIT");
    }
    #[test]
    fn rejects_ambiguous_or_secret_urls() {
        let fake = Fake(vec![addr("8.8.8.8")]);
        for url in [
            "http://127.0.0.1/",
            "http://2130706433/",
            "file:///etc/passwd",
            "https://user@example.com/",
            "https://example.com:8443/",
            "https://example.com/?token=x",
            "https://example.com/AKIAABCDEFGHIJKLMNOP",
            "https://example.com/%41KIAABCDEFGHIJKLMNOP",
            "https://example.com/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "https://example.com\\@evil.com/",
        ] {
            assert!(
                validate(&json!({"url":url}), &allowed(), &fake).is_err(),
                "{url}"
            );
        }
        assert_eq!(
            validate(
                &json!({"url":"https://example.com/AKIAABCDEFGHIJKLMNOP"}),
                &allowed(),
                &fake
            )
            .err()
            .unwrap()
            .rule,
            "EGRESS_SECRET_DETECTED"
        );
    }
    #[test]
    fn allowlist_precedes_dns() {
        struct PanicResolver;
        impl Resolver for PanicResolver {
            fn resolve(&self, _: &str, _: u16) -> std::io::Result<Vec<SocketAddr>> {
                panic!("DNS was reached")
            }
        }
        assert_eq!(
            validate(
                &json!({"url":"https://other.example/"}),
                &allowed(),
                &PanicResolver
            )
            .err()
            .unwrap()
            .rule,
            "EGRESS_HOST_NOT_ALLOWED"
        );
    }
    #[test]
    fn allowlist_configuration_is_strict_and_deduplicated() {
        assert!(parse_allowed_hosts("").unwrap().is_empty());
        assert_eq!(
            parse_allowed_hosts("Example.COM, example.com, api.example.com").unwrap(),
            vec!["example.com", "api.example.com"]
        );
        for value in [
            "example.com,",
            ",example.com",
            "example.com,,api.example.com",
            "*.example.com",
            "localhost",
            "127.0.0.1",
            "https://example.com",
            "example.com:443",
        ] {
            assert!(parse_allowed_hosts(value).is_err(), "{value}");
        }
    }
    #[test]
    fn dns_deadline_fails_closed_without_spawning_more_workers() {
        static TEST_GATE: AtomicBool = AtomicBool::new(false);
        let (release_sender, release_receiver) = mpsc::channel();
        let timed_out = resolve_bounded(
            &TEST_GATE,
            Duration::from_millis(20),
            &AtomicBool::new(false),
            move || {
                release_receiver.recv().unwrap();
                Ok(vec![addr("8.8.8.8")])
            },
        );
        assert_eq!(timed_out.unwrap_err().kind(), io::ErrorKind::TimedOut);
        let busy = resolve_bounded(
            &TEST_GATE,
            Duration::from_millis(20),
            &AtomicBool::new(false),
            || panic!("a second DNS worker must not start"),
        );
        assert_eq!(busy.unwrap_err().kind(), io::ErrorKind::WouldBlock);
        release_sender.send(()).unwrap();
        for _ in 0..100 {
            if !TEST_GATE.load(Ordering::Acquire) {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert!(!TEST_GATE.load(Ordering::Acquire));
        assert_eq!(
            resolve_bounded(
                &TEST_GATE,
                Duration::from_secs(1),
                &AtomicBool::new(false),
                || Ok(vec![addr("8.8.8.8")])
            )
            .unwrap(),
            vec![addr("8.8.8.8")]
        );
    }
    #[test]
    fn dns_cancellation_retains_worker_until_lookup_exits() {
        static GATE: AtomicBool = AtomicBool::new(false);
        let cancel = AtomicBool::new(true);
        assert_eq!(
            resolve_bounded(&GATE, DNS_TIMEOUT, &cancel, || {
                panic!("pre-cancelled lookup must not start")
            })
            .unwrap_err()
            .kind(),
            io::ErrorKind::Interrupted
        );
        assert!(!GATE.load(Ordering::Acquire));
        cancel.store(false, Ordering::Release);
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        thread::scope(|scope| {
            let cancel_ref = &cancel;
            scope.spawn(move || {
                entered_rx.recv().unwrap();
                cancel_ref.store(true, Ordering::Release);
            });
            let started = Instant::now();
            let result = resolve_bounded(&GATE, DNS_TIMEOUT, &cancel, move || {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(vec![addr("8.8.8.8")])
            });
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
            assert!(started.elapsed() < Duration::from_secs(1));
        });
        assert!(GATE.load(Ordering::Acquire));
        assert_eq!(
            resolve_bounded(&GATE, DNS_TIMEOUT, &AtomicBool::new(false), || {
                panic!("cancelled native worker still owns the gate")
            })
            .unwrap_err()
            .kind(),
            io::ErrorKind::WouldBlock
        );
        release_tx.send(()).unwrap();
        for _ in 0..200 {
            if !GATE.load(Ordering::Acquire) {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert!(!GATE.load(Ordering::Acquire));
        assert!(
            resolve_bounded(&GATE, DNS_TIMEOUT, &AtomicBool::new(false), || {
                Ok(vec![addr("8.8.8.8")])
            })
            .is_ok()
        );
    }
    #[test]
    fn dns_error_kinds_have_stable_denial_rules() {
        struct ErrorResolver(io::ErrorKind);
        impl Resolver for ErrorResolver {
            fn resolve(&self, _: &str, _: u16) -> io::Result<Vec<SocketAddr>> {
                Err(io::Error::from(self.0))
            }
        }
        for (kind, rule) in [
            (io::ErrorKind::TimedOut, "EGRESS_DNS_TIMEOUT"),
            (io::ErrorKind::WouldBlock, "EGRESS_DNS_BUSY"),
            (io::ErrorKind::Other, "EGRESS_DNS_FAILURE"),
        ] {
            assert_eq!(
                validate(
                    &json!({"url":"https://example.com/"}),
                    &allowed(),
                    &ErrorResolver(kind)
                )
                .err()
                .unwrap()
                .rule,
                rule
            );
        }
    }
    #[test]
    fn concurrent_fetches_fail_before_execution_and_release_after_failure() {
        let active = AtomicBool::new(false);
        thread::scope(|scope| {
            let (entered_tx, entered_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let active_ref = &active;
            let holder = scope.spawn(move || {
                limited_fetch(active_ref, || {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Denial::new("EGRESS_HTTP_FAILURE", "Fixture failure.").value()
                })
            });
            entered_rx.recv().unwrap();
            let contenders: Vec<_> = (0..32)
                .map(|_| {
                    scope.spawn(|| {
                        let audit = Mutex::new(AuditLog::default());
                        let result = audited_fetch(&audit, || {
                            limited_fetch(&active, || {
                                panic!("excess fetch reached validation/budget/DNS/HTTP")
                            })
                        });
                        assert_eq!(result["rule"], "EGRESS_CONCURRENCY_LIMIT");
                        assert_eq!(
                            audit.lock().unwrap().snapshot()["events"][0]["rule"],
                            "EGRESS_CONCURRENCY_LIMIT"
                        );
                    })
                })
                .collect();
            for contender in contenders {
                contender.join().unwrap();
            }
            release_tx.send(()).unwrap();
            assert_eq!(holder.join().unwrap()["rule"], "EGRESS_HTTP_FAILURE");
        });
        assert_eq!(
            limited_fetch(&active, || json!({"status":"ALLOWED"}))["status"],
            "ALLOWED"
        );
        let unwind =
            std::panic::catch_unwind(|| limited_fetch(&active, || panic!("fixture panic")));
        assert!(unwind.is_err());
        assert_eq!(
            limited_fetch(&active, || json!({"status":"ALLOWED"}))["status"],
            "ALLOWED"
        );
    }

    #[test]
    fn call_budget_is_atomic_across_host_and_hour_windows() {
        let mut budget = CallBudget::default();
        let now = Instant::now();
        for _ in 0..HOST_PER_MINUTE {
            assert!(budget.reserve("one.example", now));
        }
        assert!(!budget.reserve("one.example", now));
        assert_eq!(budget.all_calls.len(), HOST_PER_MINUTE);
        assert!(budget.reserve("two.example", now));
        for index in 0..CALLS_PER_HOUR {
            if budget.all_calls.len() == CALLS_PER_HOUR {
                break;
            }
            let host = format!("host-{index}.example");
            assert!(budget.reserve(&host, now));
        }
        assert_eq!(budget.all_calls.len(), CALLS_PER_HOUR);
        assert!(!budget.reserve("new.example", now));
        assert_eq!(budget.all_calls.len(), CALLS_PER_HOUR);
        assert!(budget.reserve("one.example", now + Duration::from_secs(3600)));
        assert_eq!(budget.all_calls.len(), 1);
        assert_eq!(budget.per_host.len(), 1);
    }
    #[test]
    fn budget_denial_happens_before_dns() {
        struct PanicResolver;
        impl Resolver for PanicResolver {
            fn resolve(&self, _: &str, _: u16) -> io::Result<Vec<SocketAddr>> {
                panic!("DNS was reached after budget denial")
            }
        }
        let denied = validate_with_reservation(
            &json!({"url":"https://example.com/"}),
            &allowed(),
            &PanicResolver,
            |_| Err(Denial::new("EGRESS_RATE_LIMIT", "Retry later.")),
        );
        assert_eq!(denied.err().unwrap().rule, "EGRESS_RATE_LIMIT");
    }
}
