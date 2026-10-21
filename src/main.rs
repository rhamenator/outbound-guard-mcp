use outbound_guard_mcp::{
    allowed_hosts_from_env, audit_snapshot, guarded_fetch_cancellable, validate_tls_configuration,
    AUDIT_URI,
};
use serde_json::{json, Value};
use std::{
    io::{self, BufRead, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

const MAX_LINE: usize = 64 * 1024;
const FRAME_TIMEOUT: Duration = Duration::from_secs(10);

fn frame_timeout() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "Input frame deadline exceeded")
}

fn check_frame_clock(clock: &Mutex<Option<Instant>>) -> io::Result<()> {
    if clock
        .lock()
        .map_err(|_| io::Error::other("Input clock unavailable"))?
        .is_some_and(|start| start.elapsed() >= FRAME_TIMEOUT)
    {
        return Err(frame_timeout());
    }
    Ok(())
}

enum Frame {
    Eof,
    Data(Vec<u8>),
    TooLarge,
}

#[derive(Default, PartialEq, Eq)]
enum Session {
    #[default]
    New,
    AwaitingInitialized,
    Ready,
}

#[cfg(test)]
fn read_frame<R: BufRead>(reader: &mut R) -> io::Result<Frame> {
    read_frame_tracked(reader, &Mutex::new(None))
}

fn read_frame_tracked<R: BufRead>(
    reader: &mut R,
    clock: &Mutex<Option<Instant>>,
) -> io::Result<Frame> {
    let mut data = Vec::new();
    let mut too_large = false;
    loop {
        let available = reader.fill_buf()?;
        check_frame_clock(clock)?;
        if available.is_empty() {
            return if data.is_empty() && !too_large {
                Ok(Frame::Eof)
            } else if too_large {
                Ok(Frame::TooLarge)
            } else {
                Ok(Frame::Data(data))
            };
        }
        {
            let mut start = clock
                .lock()
                .map_err(|_| io::Error::other("Input clock unavailable"))?;
            start.get_or_insert_with(Instant::now);
        }
        let length = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        let end = available.get(length - 1) == Some(&b'\n');
        if !too_large {
            let room = MAX_LINE.saturating_sub(data.len());
            if length > room {
                too_large = true;
            }
            data.extend_from_slice(&available[..length.min(room)]);
        }
        reader.consume(length);
        if end {
            return Ok(if too_large {
                Frame::TooLarge
            } else {
                Frame::Data(data)
            });
        }
    }
}

fn rpc_error(id: Value, code: i32, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}

fn valid_initialize_params(message: &Value) -> bool {
    let Some(params) = message.get("params").and_then(Value::as_object) else {
        return false;
    };
    let Some(capabilities) = params.get("capabilities").and_then(Value::as_object) else {
        return false;
    };
    let Some(info) = params.get("clientInfo").and_then(Value::as_object) else {
        return false;
    };
    let known_capabilities_are_objects = ["roots", "sampling", "elicitation"]
        .into_iter()
        .all(|name| capabilities.get(name).is_none_or(Value::is_object));
    let experimental_is_valid = capabilities.get("experimental").is_none_or(|value| {
        value
            .as_object()
            .is_some_and(|entries| entries.values().all(Value::is_object))
    });
    let roots_is_valid = capabilities
        .get("roots")
        .and_then(Value::as_object)
        .is_none_or(|roots| roots.get("listChanged").is_none_or(Value::is_boolean));
    params
        .get("protocolVersion")
        .and_then(Value::as_str)
        .is_some_and(|version| !version.is_empty())
        && known_capabilities_are_objects
        && experimental_is_valid
        && roots_is_valid
        && ["name", "version"].into_iter().all(|field| {
            info.get(field)
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty())
        })
        && info.get("title").is_none_or(Value::is_string)
}

fn valid_mcp_params(message: &Value, request: bool) -> bool {
    let Some(params) = message.get("params") else {
        return true;
    };
    let Some(params) = params.as_object() else {
        return false;
    };
    let Some(meta) = params.get("_meta") else {
        return true;
    };
    let Some(meta) = meta.as_object() else {
        return false;
    };
    !request
        || meta
            .get("progressToken")
            .is_none_or(|token| token.is_string() || token.is_number())
}

fn fetch_output_schema() -> Value {
    let correlation = json!({"type":"string","pattern":"^egress-[1-9][0-9]*$"});
    json!({"type":"object","oneOf":[
        {"type":"object","properties":{
            "status":{"const":"BLOCKED"},
            "rule":{"type":"string","pattern":"^EGRESS_[A-Z0-9_]+$","not":{"const":"EGRESS_ALLOWED"}},
            "remediation":{"type":"string","minLength":1},
            "correlation_id":correlation.clone()},
         "required":["status","rule","remediation"],"additionalProperties":false},
        {"type":"object","properties":{
            "status":{"const":"SAFE"},"rule":{"const":"EGRESS_ALLOWED"},
            "remediation":{"type":"string","minLength":1},"correlation_id":correlation,
            "url":{"type":"string"},
            "status_code":{"type":"integer","minimum":100,"maximum":999},
            "body_text":{"type":"string","maxLength":262144},"untrusted_content":{"const":true}},
         "required":["status","rule","remediation","correlation_id","url","status_code","body_text","untrusted_content"],
         "additionalProperties":false}
    ]})
}

#[cfg(test)]
fn handle(message: Value, hosts: &[String], session: &mut Session) -> Option<Value> {
    handle_cancellable(message, hosts, session, &AtomicBool::new(false))
}

fn handle_cancellable(
    message: Value,
    hosts: &[String],
    session: &mut Session,
    cancel: &AtomicBool,
) -> Option<Value> {
    let Some(object) = message.as_object() else {
        return Some(rpc_error(Value::Null, -32600, "Invalid Request"));
    };
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Some(rpc_error(Value::Null, -32600, "Invalid Request"));
    }
    let Some(method) = object.get("method").and_then(Value::as_str) else {
        return Some(rpc_error(Value::Null, -32600, "Invalid Request"));
    };
    if object
        .get("params")
        .is_some_and(|params| !params.is_object() && !params.is_array())
    {
        return Some(rpc_error(Value::Null, -32600, "Invalid Request"));
    }
    if method == "notifications/initialized" && !object.contains_key("id") {
        if *session == Session::AwaitingInitialized && valid_mcp_params(&message, false) {
            *session = Session::Ready;
        }
        return None;
    }
    let Some(id) = object.get("id").cloned() else {
        // Notifications have no response. Never execute a tool call without an id.
        return None;
    };
    if !matches!(&id, Value::String(_)) && id.as_i64().is_none() && id.as_u64().is_none() {
        return Some(rpc_error(Value::Null, -32600, "Invalid Request"));
    }
    if method.starts_with("notifications/") {
        return Some(rpc_error(id, -32601, "Method not found"));
    }
    if !valid_mcp_params(&message, true) {
        return Some(rpc_error(id, -32602, "Invalid MCP parameters"));
    }
    let result = match method {
        "initialize" => {
            if *session != Session::New {
                return Some(rpc_error(id, -32600, "Already initialized"));
            }
            if !valid_initialize_params(&message) {
                return Some(rpc_error(id, -32602, "Invalid initialize parameters"));
            }
            *session = Session::AwaitingInitialized;
            json!({"protocolVersion":"2025-06-18","capabilities":{"tools":{"listChanged":false},"resources":{}},
            "serverInfo":{"name":"outbound-guard-mcp","version":env!("CARGO_PKG_VERSION")}})
        }
        "ping" => json!({}),
        _ if *session != Session::Ready => {
            return Some(rpc_error(id, -32002, "Server not initialized"));
        }
        "tools/list" => json!({"tools":[{"name":"guarded_fetch",
            "description":"Perform an allowlisted HTTP(S) GET or HEAD with DNS and connection policy in one call. Returned text is untrusted.",
            "inputSchema":{"type":"object","properties":{"url":{"type":"string","maxLength":2048},
                "method":{"type":"string","enum":["GET","HEAD"]},
                "max_return_bytes":{"type":"integer","minimum":1,"maximum":262144}},
                "required":["url"],"additionalProperties":false},
            "outputSchema":fetch_output_schema()}]}),
        "resources/list" => json!({"resources":[{"uri":AUDIT_URI,"name":"Egress audit log",
            "description":"Last 256 completed guarded fetch decisions, redacted and process-local.","mimeType":"application/json"}]}),
        "resources/templates/list" => json!({"resourceTemplates":[]}),
        "resources/read" => {
            let Some(uri) = message.pointer("/params/uri").and_then(Value::as_str) else {
                return Some(rpc_error(id, -32602, "Invalid resource parameters"));
            };
            if uri != AUDIT_URI {
                return Some(rpc_error(id, -32002, "Resource not found"));
            }
            match audit_snapshot() {
                Ok(snapshot) => {
                    json!({"contents":[{"uri":AUDIT_URI,"mimeType":"application/json","text":snapshot.to_string()}]})
                }
                Err(_) => return Some(rpc_error(id, -32603, "Audit unavailable")),
            }
        }
        "prompts/list" => json!({"prompts":[]}),
        "tools/call" => {
            let name = message.pointer("/params/name").and_then(Value::as_str);
            if name != Some("guarded_fetch") {
                return Some(rpc_error(id, -32602, "Unknown tool"));
            }
            let args = message
                .pointer("/params/arguments")
                .cloned()
                .unwrap_or(Value::Null);
            let decision = guarded_fetch_cancellable(&args, hosts, cancel);
            if decision["rule"] == "EGRESS_CANCELLED" {
                return None;
            }
            let blocked = decision.get("status").and_then(Value::as_str) != Some("SAFE");
            json!({"isError":blocked,"structuredContent":decision,
                "content":[{"type":"text","text":decision.to_string()}]})
        }
        _ => return Some(rpc_error(id, -32601, "Method not found")),
    };
    Some(json!({"jsonrpc":"2.0","id":id,"result":result}))
}

struct PendingFetch {
    id: Value,
    cancel: Arc<AtomicBool>,
}
struct Incoming {
    frame: Frame,
    cancel: Arc<AtomicBool>,
}
fn valid_id(id: &Value) -> bool {
    id.is_string() || id.as_i64().is_some() || id.as_u64().is_some()
}
fn apply_cancellation(message: &Value, pending: &Mutex<Vec<PendingFetch>>) -> io::Result<bool> {
    if message.get("method").and_then(Value::as_str) != Some("notifications/cancelled")
        || message.get("id").is_some()
    {
        return Ok(false);
    }
    // Malformed/unknown cancellation notifications are fire-and-forget. Never
    // retain or echo the optional reason, which can contain sensitive content.
    if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || !valid_mcp_params(message, false)
        || message
            .pointer("/params/reason")
            .is_some_and(|reason| !reason.is_string())
    {
        return Ok(true);
    }
    let Some(id) = message
        .pointer("/params/requestId")
        .filter(|id| valid_id(id))
    else {
        return Ok(true);
    };
    for fetch in pending
        .lock()
        .map_err(|_| io::Error::other("Cancellation registry unavailable"))?
        .iter()
    {
        if fetch.id == *id {
            fetch.cancel.store(true, Ordering::Release);
        }
    }
    Ok(true)
}

fn main() -> io::Result<()> {
    let mut arguments = std::env::args_os().skip(1);
    let first = arguments.next();
    let extra = arguments.next().is_some();
    let check_config = match first.as_deref() {
        None if !extra => false,
        Some(value) if !extra && value == "--help" => {
            writeln!(io::stdout().lock(), "outbound-guard-mcp [--help | --version | --check-config]\n\nNo arguments: run the MCP stdio server (2025-06-18).\n--check-config: validate startup configuration and exit; no DNS or HTTP probe.\n\nEnvironment:\n  OUTBOUND_GUARD_ALLOWED_HOSTS   Comma-separated exact DNS hosts; empty denies all.\n  OUTBOUND_GUARD_EXTRA_CA_CERT   Optional operator-owned single PEM certificate.\n\nExperimental. Only guarded_fetch traffic is covered; fetched content is untrusted.")?;
            return Ok(());
        }
        Some(value) if !extra && value == "--version" => {
            writeln!(
                io::stdout().lock(),
                "outbound-guard-mcp {}",
                env!("CARGO_PKG_VERSION")
            )?;
            return Ok(());
        }
        Some(value) if !extra && value == "--check-config" => true,
        _ => return Err(io::Error::other("Unsupported arguments; run --help")),
    };
    validate_tls_configuration().map_err(io::Error::other)?;
    let hosts = allowed_hosts_from_env().map_err(io::Error::other)?;
    if check_config {
        writeln!(
            io::stdout().lock(),
            "{}",
            json!({"valid":true,"scope":"startup",
            "allowed_host_count":hosts.len(),"network_checked":false})
        )?;
        return Ok(());
    }
    let pending = Arc::new(Mutex::new(Vec::<PendingFetch>::new()));
    let reader_pending = Arc::clone(&pending);
    let frame_clock = Arc::new(Mutex::new(None));
    let reader_clock = Arc::clone(&frame_clock);
    // A rendezvous channel retains no queued frames. The reader can hold one
    // pending non-control frame; backpressure then pauses further input reads.
    let (tx, rx) = mpsc::sync_channel::<io::Result<Incoming>>(0);
    let input_thread = thread::Builder::new()
        .name("mcp-stdin".into())
        .spawn(move || {
            let run = || -> io::Result<()> {
                let stdin = io::stdin();
                let mut reader = stdin.lock();
                loop {
                    let frame = read_frame_tracked(&mut reader, &reader_clock)?;
                    *reader_clock
                        .lock()
                        .map_err(|_| io::Error::other("Input clock unavailable"))? = None;
                    let eof = matches!(frame, Frame::Eof);
                    let cancel = Arc::new(AtomicBool::new(false));
                    if let Frame::Data(data) = &frame {
                        if let Ok(message) = serde_json::from_slice::<Value>(data) {
                            if apply_cancellation(&message, &reader_pending)? {
                                continue;
                            }
                            if message.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
                                && message.get("method").and_then(Value::as_str)
                                    == Some("tools/call")
                            {
                                if let Some(id) = message.get("id").filter(|id| valid_id(id)) {
                                    reader_pending
                                        .lock()
                                        .map_err(|_| {
                                            io::Error::other("Cancellation registry unavailable")
                                        })?
                                        .push(PendingFetch {
                                            id: id.clone(),
                                            cancel: Arc::clone(&cancel),
                                        });
                                }
                            }
                        }
                    }
                    tx.send(Ok(Incoming { frame, cancel })).map_err(|_| {
                        io::Error::new(io::ErrorKind::BrokenPipe, "Dispatcher stopped")
                    })?;
                    if eof {
                        return Ok(());
                    }
                }
            };
            if let Err(error) = run() {
                let _ = tx.send(Err(error));
            }
        })?;
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    let mut session = Session::New;
    loop {
        let Incoming { frame, cancel } = loop {
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(incoming) => break incoming?,
                Err(mpsc::RecvTimeoutError::Timeout) => check_frame_clock(&frame_clock)?,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(io::Error::other("Input reader stopped"))
                }
            }
        };
        let response = match frame {
            Frame::Eof => break,
            Frame::TooLarge => Some(rpc_error(Value::Null, -32600, "Request too large")),
            Frame::Data(data) => match serde_json::from_slice::<Value>(&data) {
                Ok(message) => handle_cancellable(message, &hosts, &mut session, &cancel),
                Err(_) => Some(rpc_error(Value::Null, -32700, "Parse error")),
            },
        };
        pending
            .lock()
            .map_err(|_| io::Error::other("Cancellation registry unavailable"))?
            .retain(|fetch| !Arc::ptr_eq(&fetch.cancel, &cancel));
        if let Some(response) = response {
            serde_json::to_writer(&mut writer, &response)?;
            writer.write_all(b"\n")?;
            writer.flush()?;
        }
    }
    input_thread
        .join()
        .map_err(|_| io::Error::other("Input reader failed"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn expired_partial_frame_is_never_dispatched_even_after_completion() {
        let clock = std::sync::Mutex::new(Some(std::time::Instant::now() - super::FRAME_TIMEOUT));
        for bytes in [b"\n".as_slice(), b"".as_slice(), b"ping\n".as_slice()] {
            let error = super::read_frame_tracked(&mut std::io::Cursor::new(bytes), &clock)
                .err()
                .unwrap();
            assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        }
    }

    // These protocol tests share the production process-wide fetch permit.
    static FETCH_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    use super::*;
    fn ready_session() -> Session {
        let mut session = Session::New;
        assert!(handle(
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-06-18","capabilities":{},
            "clientInfo":{"name":"test-client","version":"1.0"}}}),
            &[],
            &mut session
        )
        .unwrap()
        .get("result")
        .is_some());
        assert!(handle(
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            &[],
            &mut session
        )
        .is_none());
        assert!(session == Session::Ready);
        session
    }
    #[test]
    fn lists_only_atomic_tool() {
        let result = handle(
            json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
            &[],
            &mut ready_session(),
        )
        .unwrap();
        assert_eq!(result["result"]["tools"][0]["name"], "guarded_fetch");
        assert_eq!(result["result"]["tools"].as_array().unwrap().len(), 1);
    }
    #[test]
    fn blocked_calls_have_structured_error_result() {
        let _fetch_test = FETCH_TEST_LOCK.lock().unwrap();
        let result = handle(json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"guarded_fetch","arguments":{"url":"http://127.0.0.1/"}}}), &[], &mut ready_session()).unwrap();
        assert_eq!(result["result"]["isError"], true);
        assert_eq!(result["result"]["structuredContent"]["status"], "BLOCKED");
    }
    #[test]
    fn oversized_frame_is_drained_before_next_message() {
        let mut input = vec![b'x'; MAX_LINE + 1];
        input.extend_from_slice(b"\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n");
        let mut reader = io::BufReader::new(input.as_slice());
        assert!(matches!(read_frame(&mut reader).unwrap(), Frame::TooLarge));
        assert!(matches!(read_frame(&mut reader).unwrap(), Frame::Data(_)));
    }
    #[test]
    fn generated_frames_match_line_oracle_across_buffer_boundaries() {
        // Independent oracle: split the complete byte stream at LF, then classify
        // each intact slice by length. The production reader must agree for all
        // fragmentation capacities, retaining exact bytes and recovering at LF.
        let mut seed = 0x6672616d696e6721_u64;
        let mut input = Vec::new();
        for length in [0, 1, MAX_LINE - 2, MAX_LINE - 1, MAX_LINE, MAX_LINE + 1] {
            input.extend(std::iter::repeat_n(b'x', length));
            input.push(b'\n');
            input.extend_from_slice(b"valid-after-boundary\r\n");
        }
        for _ in 0..128 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let length = (seed % 1024) as usize;
            for index in 0..length {
                // Arbitrary bytes include invalid UTF-8, NUL, CR, and embedded LF.
                input.push(seed.wrapping_add(index as u64) as u8);
            }
            input.push(b'\n');
        }
        input.extend_from_slice(b"unterminated-at-eof");
        for capacity in [1, 2, 3, 7, 64, 8192, MAX_LINE + 1] {
            let mut reader = io::BufReader::with_capacity(capacity, input.as_slice());
            for (index, expected) in input.split_inclusive(|byte| *byte == b'\n').enumerate() {
                match read_frame(&mut reader).unwrap() {
                    Frame::Data(actual) => {
                        assert!(
                            expected.len() <= MAX_LINE,
                            "capacity={capacity} frame={index}"
                        );
                        assert_eq!(actual, expected, "capacity={capacity} frame={index}");
                    }
                    Frame::TooLarge => assert!(
                        expected.len() > MAX_LINE,
                        "capacity={capacity} frame={index}"
                    ),
                    Frame::Eof => panic!("early EOF: capacity={capacity} frame={index}"),
                }
            }
            assert!(matches!(read_frame(&mut reader).unwrap(), Frame::Eof));
        }
        // EOF has no delimiter byte: exactly MAX_LINE bytes remain a valid frame.
        for length in [0, MAX_LINE, MAX_LINE + 1] {
            let bytes = vec![b'x'; length];
            let mut reader = io::BufReader::with_capacity(7, bytes.as_slice());
            match read_frame(&mut reader).unwrap() {
                Frame::Eof => assert_eq!(length, 0),
                Frame::Data(actual) => assert_eq!(actual.len(), MAX_LINE),
                Frame::TooLarge => assert_eq!(length, MAX_LINE + 1),
            }
            assert!(matches!(read_frame(&mut reader).unwrap(), Frame::Eof));
        }
    }
    #[test]
    fn missing_method_is_a_protocol_error() {
        let result = handle(json!({"jsonrpc":"2.0","id":1}), &[], &mut Session::New).unwrap();
        assert_eq!(result["error"]["code"], -32600);
    }
    #[test]
    fn invalid_id_type_is_rejected() {
        for id in [
            json!({"x":1}),
            serde_json::from_str("1e400").unwrap(),
            serde_json::from_str("18446744073709551616").unwrap(),
        ] {
            let result = handle(
                json!({"jsonrpc":"2.0","id":id,"method":"ping"}),
                &[],
                &mut Session::New,
            )
            .unwrap();
            assert_eq!(result["error"]["code"], -32600);
        }
    }
    #[test]
    fn notifications_never_execute_tools_or_get_responses() {
        for method in ["notifications/initialized", "tools/call", "ping"] {
            assert!(handle(
                json!({"jsonrpc":"2.0","method":method,"params":{"name":"guarded_fetch","arguments":{"url":"https://example.com/"}}}),
                &[],
                &mut Session::New,
            )
            .is_none());
        }
    }
    #[test]
    fn malformed_initialized_request_is_not_silently_accepted() {
        let result = handle(
            json!({"jsonrpc":"2.0","id":7,"method":"notifications/initialized"}),
            &[],
            &mut Session::New,
        )
        .unwrap();
        assert_eq!(result["error"]["code"], -32601);
        let result = handle(
            json!({"jsonrpc":"1.0","method":"notifications/initialized"}),
            &[],
            &mut Session::New,
        )
        .unwrap();
        assert_eq!(result["error"]["code"], -32600);
    }

    #[test]
    fn cancellation_matches_typed_ids_and_ignores_malformed_notifications() {
        let flag = Arc::new(AtomicBool::new(false));
        let pending = Mutex::new(vec![PendingFetch {
            id: json!("1"),
            cancel: Arc::clone(&flag),
        }]);
        for message in [
            json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}),
            json!({"jsonrpc":"1.0","method":"notifications/cancelled","params":{"requestId":"1"}}),
            json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"1","reason":false}}),
            json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"1","_meta":[]}}),
            json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":[]}}),
            json!({"jsonrpc":"2.0","method":"notifications/cancelled"}),
        ] {
            assert!(apply_cancellation(&message, &pending).unwrap());
            assert!(!flag.load(Ordering::Acquire));
        }
        assert!(!apply_cancellation(
            &json!({"jsonrpc":"2.0","id":9,"method":"notifications/cancelled",
            "params":{"requestId":"1"}}),
            &pending
        )
        .unwrap());
        assert!(!flag.load(Ordering::Acquire));
        assert!(apply_cancellation(
            &json!({"jsonrpc":"2.0","method":"notifications/cancelled",
            "params":{"requestId":"1","reason":"sensitive marker"}}),
            &pending
        )
        .unwrap());
        assert!(flag.load(Ordering::Acquire));
    }

    #[test]
    fn malformed_mcp_metadata_does_not_dispatch_or_advance_handshake() {
        for params in [
            json!([]),
            json!({"_meta":null}),
            json!({"_meta":[]}),
            json!({"_meta":"marker"}),
            json!({"_meta":{"progressToken":null}}),
            json!({"_meta":{"progressToken":true}}),
            json!({"_meta":{"progressToken":{}}}),
            json!({"_meta":{"progressToken":[]}}),
        ] {
            for method in [
                "ping",
                "tools/list",
                "tools/call",
                "resources/read",
                "initialize",
            ] {
                let mut session = if method == "initialize" {
                    Session::New
                } else {
                    Session::Ready
                };
                let mut request_params = params.clone();
                if let Some(fields) = request_params.as_object_mut() {
                    if method == "initialize" {
                        fields.insert("protocolVersion".into(), json!("2025-06-18"));
                        fields.insert("capabilities".into(), json!({}));
                        fields.insert("clientInfo".into(), json!({"name":"test", "version":"1"}));
                    } else if method == "resources/read" {
                        fields.insert("uri".into(), json!(AUDIT_URI));
                    } else if method == "tools/call" {
                        fields.insert("name".into(), json!("guarded_fetch"));
                        fields.insert("arguments".into(), json!({"url":"http://127.0.0.1/"}));
                    }
                }
                let reply = handle(
                    json!({"jsonrpc":"2.0","id":42,"method":method,"params":request_params}),
                    &[],
                    &mut session,
                )
                .unwrap();
                assert_eq!(reply["id"], 42);
                assert_eq!(reply["error"]["code"], -32602, "{reply}");
                if method == "initialize" {
                    assert!(session == Session::New);
                }
            }
        }
        for meta in [json!(null), json!([]), json!("marker")] {
            let mut session = Session::AwaitingInitialized;
            assert!(handle(
                json!({"jsonrpc":"2.0","method":"notifications/initialized",
                "params":{"_meta":meta}}),
                &[],
                &mut session
            )
            .is_none());
            assert!(session == Session::AwaitingInitialized);
        }
        for token in [json!("progress"), json!(0), json!(-1), json!(1.5)] {
            let reply = handle(
                json!({"jsonrpc":"2.0","id":43,"method":"ping",
                "params":{"_meta":{"progressToken":token,"example/custom":[null,true]}}}),
                &[],
                &mut Session::Ready,
            )
            .unwrap();
            assert_eq!(reply["result"], json!({}));
        }
    }

    #[test]
    fn initialize_requires_version_capabilities_and_client_identity() {
        let valid = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-06-18","capabilities":{},
            "clientInfo":{"name":"test-client","version":"1.0"}}});
        assert_eq!(
            handle(valid.clone(), &[], &mut Session::New).unwrap()["result"]["protocolVersion"],
            "2025-06-18"
        );
        let mut valid_nested = valid.clone();
        valid_nested["params"]["capabilities"] = json!({
            "roots":{"listChanged":true}, "sampling":{}, "elicitation":{},
            "experimental":{"vendor":{}}
        });
        valid_nested["params"]["clientInfo"]["title"] = json!("Probe client");
        assert_eq!(
            handle(valid_nested, &[], &mut Session::New).unwrap()["result"]["protocolVersion"],
            "2025-06-18"
        );
        for params in [
            json!(null),
            json!([]),
            json!({"protocolVersion":"2025-06-18"}),
            json!({"protocolVersion":"", "capabilities":{}, "clientInfo":{"name":"client","version":"1"}}),
            json!({"protocolVersion":"2025-06-18", "capabilities":[], "clientInfo":{"name":"client","version":"1"}}),
            json!({"protocolVersion":"2025-06-18", "capabilities":{}, "clientInfo":{"name":"client"}}),
            json!({"protocolVersion":"2025-06-18", "capabilities":{}, "clientInfo":{"name":"client","version":1}}),
            json!({"protocolVersion":"2025-06-18", "capabilities":{"roots":false}, "clientInfo":{"name":"client","version":"1"}}),
            json!({"protocolVersion":"2025-06-18", "capabilities":{"roots":{"listChanged":"yes"}}, "clientInfo":{"name":"client","version":"1"}}),
            json!({"protocolVersion":"2025-06-18", "capabilities":{"sampling":1}, "clientInfo":{"name":"client","version":"1"}}),
            json!({"protocolVersion":"2025-06-18", "capabilities":{"elicitation":null}, "clientInfo":{"name":"client","version":"1"}}),
            json!({"protocolVersion":"2025-06-18", "capabilities":{"experimental":{"x":false}}, "clientInfo":{"name":"client","version":"1"}}),
            json!({"protocolVersion":"2025-06-18", "capabilities":{}, "clientInfo":{"name":"client","version":"1","title":2}}),
        ] {
            let mut request = valid.clone();
            request["params"] = params;
            let reply = handle(request, &[], &mut Session::New).unwrap();
            assert!(reply.get("result").is_none(), "{reply}");
            assert!(reply["error"]["code"] == -32602 || reply["error"]["code"] == -32600);
        }
    }

    #[test]
    fn tools_require_completed_handshake() {
        let _fetch_test = FETCH_TEST_LOCK.lock().unwrap();
        let mut session = Session::New;
        let call = json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
            "name":"guarded_fetch","arguments":{"url":"http://127.0.0.1/"}}});
        assert_eq!(
            handle(call.clone(), &[], &mut session).unwrap()["error"]["code"],
            -32002
        );
        assert!(handle(
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            &[],
            &mut session
        )
        .is_none());
        assert_eq!(
            handle(call.clone(), &[], &mut session).unwrap()["error"]["code"],
            -32002
        );
        let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-06-18","capabilities":{},
            "clientInfo":{"name":"test-client","version":"1.0"}}});
        assert_eq!(
            handle(init.clone(), &[], &mut session).unwrap()["result"]["protocolVersion"],
            "2025-06-18"
        );
        assert_eq!(
            handle(call.clone(), &[], &mut session).unwrap()["error"]["code"],
            -32002
        );
        assert!(handle(
            json!({"jsonrpc":"2.0","method":"notifications/initialized","params":[]}),
            &[],
            &mut session
        )
        .is_none());
        assert_eq!(
            handle(call.clone(), &[], &mut session).unwrap()["error"]["code"],
            -32002
        );
        assert_eq!(
            handle(init, &[], &mut session).unwrap()["error"]["code"],
            -32600
        );
        assert!(handle(
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            &[],
            &mut session
        )
        .is_none());
        assert_eq!(
            handle(call, &[], &mut session).unwrap()["result"]["structuredContent"]["rule"],
            "EGRESS_INVALID_HOST"
        );
    }
}
