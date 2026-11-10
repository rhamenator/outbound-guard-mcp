//! Development-only DNS answer-set policy campaign; no network or resolver process.
#[cfg(not(feature = "policy-fuzz"))]
fn main() {
    eprintln!("Use tools/policy_fuzz.sh with POLICY_FUZZ_TARGET=dns.");
    std::process::exit(2);
}

#[cfg(feature = "policy-fuzz")]
mod fuzz {
    use outbound_guard_mcp::{validate, Resolver};
    use serde_json::json;
    use std::ffi::{c_char, c_int};
    use std::net::SocketAddr;

    const ADDRESSES: [&str; 12] = [
        "11.0.0.1:80",
        "8.8.8.8:80",
        "1.1.1.1:80",
        "127.0.0.1:80",
        "10.0.0.1:80",
        "169.254.169.254:80",
        "100.64.0.1:80",
        "192.0.2.1:80",
        "[2606:4700:4700::1111]:80",
        "[fc00::1]:80",
        "[::1]:80",
        "11.0.0.1:81",
    ];

    struct Answers(Vec<SocketAddr>);
    impl Resolver for Answers {
        fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
            assert_eq!((host, port), ("allowed.test", 80));
            Ok(self.0.clone())
        }
    }

    fn exercise(bytes: &[u8]) {
        let count = usize::from(bytes.first().copied().unwrap_or(0)) % 19;
        let selectors: Vec<_> = (0..count)
            .map(|index| usize::from(bytes.get(index + 1).copied().unwrap_or(0)) % ADDRESSES.len())
            .collect();
        let addresses: Vec<SocketAddr> = selectors
            .iter()
            .map(|&index| ADDRESSES[index].parse().expect("fixed fixture address"))
            .collect();
        // This oracle uses a finite, explicitly classified answer vocabulary.
        // It does not call the production public_ip classifier.
        let expected_rule = if count == 0 {
            Some("EGRESS_DNS_FAILURE")
        } else if count > 16 {
            Some("EGRESS_DNS_ANSWER_LIMIT")
        } else if selectors
            .iter()
            .any(|index| !matches!(index, 0 | 1 | 2 | 8))
        {
            Some("EGRESS_FORBIDDEN_ADDRESS")
        } else {
            None
        };
        match (
            validate(
                &json!({"url":"http://allowed.test/plain"}),
                &["allowed.test".into()],
                &Answers(addresses.clone()),
            ),
            expected_rule,
        ) {
            (Ok(target), None) => {
                assert_eq!(target.host, "allowed.test");
                assert_eq!(target.addresses, addresses);
                assert_eq!(target.url.host_str(), Some("allowed.test"));
            }
            (Err(denial), Some(rule)) => assert_eq!(denial.rule, rule),
            (result, expected) => panic!(
                "DNS decision mismatch: result={:?}, expected={expected:?}",
                result.err().map(|denial| denial.rule)
            ),
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
        let bytes = if size == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(data, size) }
        };
        exercise(bytes);
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
