//! Development-only, network-free LLVM libFuzzer entry point.
#[cfg(not(feature = "policy-fuzz"))]
fn main() {
    eprintln!("Use tools/policy_fuzz.sh to build this development harness.");
    std::process::exit(2);
}

#[cfg(feature = "policy-fuzz")]
mod fuzz {
    use outbound_guard_mcp::{validate, Resolver};
    use serde_json::{json, Value};
    use std::ffi::{c_char, c_int};
    use std::net::SocketAddr;

    struct Fixture;
    impl Resolver for Fixture {
        fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
            assert_eq!(host, "allowed.test");
            Ok(vec![SocketAddr::from(([11, 0, 0, 1], port))])
        }
    }

    extern "C" {
        fn LLVMFuzzerRunDriver(
            argc: *mut c_int,
            argv: *mut *mut *mut c_char,
            callback: unsafe extern "C" fn(*const u8, usize) -> c_int,
        ) -> c_int;
    }

    unsafe extern "C" fn input(data: *const u8, size: usize) -> c_int {
        // libFuzzer owns this valid buffer for the callback lifetime.
        let bytes = if size == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(data, size) }
        };
        let args: Value = serde_json::from_slice(bytes)
            .unwrap_or_else(|_| json!({"url": String::from_utf8_lossy(bytes)}));
        if let Ok(target) = validate(&args, &["allowed.test".into()], &Fixture) {
            assert_eq!(target.host, "allowed.test");
            assert_eq!(target.url.host_str(), Some("allowed.test"));
            assert!(matches!(target.method, "GET" | "HEAD"));
            assert!(matches!(target.url.scheme(), "http" | "https"));
            assert_eq!(target.addresses.len(), 1);
            assert_eq!(target.addresses[0].ip().to_string(), "11.0.0.1");
            assert!(target.url.username().is_empty() && target.url.password().is_none());
            assert!(target.url.query().is_none() && target.url.fragment().is_none());
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
        // Pointers remain live and NUL-terminated throughout the driver call.
        let result = unsafe { LLVMFuzzerRunDriver(&mut argc, &mut argv, input) };
        std::process::exit(result);
    }
}

#[cfg(feature = "policy-fuzz")]
fn main() {
    fuzz::run();
}
