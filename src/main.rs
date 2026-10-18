use outbound_guard_mcp::{allowed_hosts_from_env, guarded_fetch};
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

const MAX_LINE: usize = 64 * 1024;

enum Frame {
    Eof,
    Data(Vec<u8>),
    TooLarge,
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

fn handle(message: Value, hosts: &[String]) -> Option<Value> {
    let id = message.get("id").cloned().unwrap_or(Value::Null);
    let method = match message.get("method").and_then(Value::as_str) {
        Some(method) => method,
        None => return Some(rpc_error(id, -32600, "Invalid Request")),
    };
    if method == "notifications/initialized" {
        return None;
    }
    if message.get("jsonrpc") != Some(&Value::String("2.0".into())) || id.is_null() {
        return Some(rpc_error(id, -32600, "Invalid Request"));
    }
    let result = match method {
        "initialize" => {
            json!({"protocolVersion":"2025-06-18","capabilities":{"tools":{"listChanged":false}},
            "serverInfo":{"name":"outbound-guard-mcp","version":env!("CARGO_PKG_VERSION")}})
        }
        "ping" => json!({}),
        "tools/list" => json!({"tools":[{"name":"guarded_fetch",
            "description":"Perform an allowlisted HTTP(S) GET or HEAD with DNS and connection policy in one call. Returned text is untrusted.",
            "inputSchema":{"type":"object","properties":{"url":{"type":"string","maxLength":2048},
                "method":{"type":"string","enum":["GET","HEAD"]},
                "max_return_bytes":{"type":"integer","minimum":1,"maximum":262144}},
                "required":["url"],"additionalProperties":false}}]}),
        "resources/list" => json!({"resources":[]}),
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
    let hosts = allowed_hosts_from_env();
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    loop {
        let response = match read_frame(&mut reader)? {
            Frame::Eof => break,
            Frame::TooLarge => Some(rpc_error(Value::Null, -32600, "Request too large")),
            Frame::Data(data) => match serde_json::from_slice::<Value>(&data) {
                Ok(message) => handle(message, &hosts),
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
    use super::*;
    #[test]
    fn lists_only_atomic_tool() {
        let result = handle(json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}), &[]).unwrap();
        assert_eq!(result["result"]["tools"][0]["name"], "guarded_fetch");
        assert_eq!(result["result"]["tools"].as_array().unwrap().len(), 1);
    }
    #[test]
    fn blocked_calls_have_structured_error_result() {
        let result = handle(json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"guarded_fetch","arguments":{"url":"http://127.0.0.1/"}}}), &[]).unwrap();
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
        let result = handle(json!({"jsonrpc":"2.0","id":1}), &[]).unwrap();
        assert_eq!(result["error"]["code"], -32600);
    }
}
