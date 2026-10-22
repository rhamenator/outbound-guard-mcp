//! Development-only, network-free LLVM libFuzzer entry point.
#[cfg(not(feature = "policy-fuzz"))]
fn main() {
    eprintln!("Use tools/policy_fuzz.sh to build this development harness.");
    std::process::exit(2);
}

#[cfg(feature = "policy-fuzz")]
#[allow(dead_code)]
#[path = "../src/main.rs"]
mod server;

#[cfg(feature = "policy-fuzz")]
mod fuzz {
    use std::ffi::{c_char, c_int};

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
        super::server::fuzz_frame_stream(bytes);
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
