use outbound_guard_mcp::{
    allowed_hosts_from_env, audit_snapshot, guarded_fetch, validate_tls_configuration, AUDIT_URI,
};
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

const MAX_LINE: usize = 64 * 1024;

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

fn read_frame<R: BufRead>(reader: &mut R) -> io::Result<Frame> {
    let mut data = Vec::new();
    let mut too_large = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if data.is_empty() && !too_large {
                Ok(Frame::Eof)
            } else if too_large {
                Ok(Frame::TooLarge)
            } else {
                Ok(Frame::Data(data))
            };
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

fn handle(message: Value, hosts: &[String], session: &mut Session) -> Option<Value> {
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
                "required":["url"],"additionalProperties":false}}]}),
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
            let decision = guarded_fetch(&args, hosts);
            let blocked = decision.get("status").and_then(Value::as_str) != Some("SAFE");
            json!({"isError":blocked,"structuredContent":decision,
                "content":[{"type":"text","text":decision.to_string()}]})
        }
        _ => return Some(rpc_error(id, -32601, "Method not found")),
    };
    Some(json!({"jsonrpc":"2.0","id":id,"result":result}))
}

fn main() -> io::Result<()> {
    validate_tls_configuration().map_err(io::Error::other)?;
    let hosts = allowed_hosts_from_env().map_err(io::Error::other)?;
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    let mut session = Session::New;
    loop {
        let response = match read_frame(&mut reader)? {
            Frame::Eof => break,
            Frame::TooLarge => Some(rpc_error(Value::Null, -32600, "Request too large")),
            Frame::Data(data) => match serde_json::from_slice::<Value>(&data) {
                Ok(message) => handle(message, &hosts, &mut session),
                Err(_) => Some(rpc_error(Value::Null, -32700, "Parse error")),
            },
        };
        if let Some(response) = response {
            serde_json::to_writer(&mut writer, &response)?;
            writer.write_all(b"\n")?;
            writer.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
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
