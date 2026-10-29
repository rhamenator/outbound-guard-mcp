//! Development-only JSON response scanner fuzz target; no network or MCP transport.
#[cfg(not(feature = "policy-fuzz"))]
fn main() {
    eprintln!("Use tools/policy_fuzz.sh to build this development harness.");
    std::process::exit(2);
}

#[cfg(feature = "policy-fuzz")]
mod fuzz {
    use outbound_guard_mcp::fuzz_json_instruction_scan;
    use serde_json::Value;
    use std::ffi::{c_char, c_int};

    extern "C" {
        fn LLVMFuzzerRunDriver(
            argc: *mut c_int,
            argv: *mut *mut *mut c_char,
            callback: unsafe extern "C" fn(*const u8, usize) -> c_int,
        ) -> c_int;
    }

    fn has_instruction_key(value: &Value) -> bool {
        match value {
            Value::Object(map) => map.iter().any(|(key, child)| {
                [
                    "instruction",
                    "instructions",
                    "system_prompt",
                    "system_message",
                    "developer_message",
                ]
                .iter()
                .any(|blocked| key.eq_ignore_ascii_case(blocked))
                    || has_instruction_key(child)
            }),
            Value::Array(items) => items.iter().any(has_instruction_key),
            _ => false,
        }
    }

    unsafe extern "C" fn input(data: *const u8, size: usize) -> c_int {
        let bytes = if size == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(data, size) }
        };
        if let Ok(text) = std::str::from_utf8(bytes) {
            let scanned = fuzz_json_instruction_scan(text);
            if let Ok(value) = serde_json::from_str::<Value>(text) {
                // Value serialization removes duplicate object keys. The scanner
                // must accept this canonical form and match a recursive oracle.
                let canonical = value.to_string();
                assert_eq!(
                    fuzz_json_instruction_scan(&canonical).unwrap(),
                    has_instruction_key(&value)
                );
                if let Ok(found) = scanned {
                    assert_eq!(found, has_instruction_key(&value));
                }
            }
        }
        0
    }

    pub fn run() {
        let args: Vec<std::ffi::CString> = std::env::args()
            .map(|s| std::ffi::CString::new(s).expect("NUL-free CLI argument"))
            .collect();
        let mut pointers: Vec<*mut c_char> = args.iter().map(|s| s.as_ptr().cast_mut()).collect();
        pointers.push(std::ptr::null_mut());
        let mut argc = (pointers.len() - 1) as c_int;
        let mut argv = pointers.as_mut_ptr();
        let result = unsafe { LLVMFuzzerRunDriver(&mut argc, &mut argv, input) };
        std::process::exit(result);
    }
}

#[cfg(feature = "policy-fuzz")]
fn main() {
    fuzz::run();
}
