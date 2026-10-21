//! Controlled-fixture library consumer; not an MCP server or shipped binary.
use outbound_guard_mcp::{audit_snapshot, guarded_fetch, guarded_fetch_cancellable};
use serde_json::json;
use std::{
    io::{self, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
    time::Duration,
};

fn main() {
    let flag = Arc::new(AtomicBool::new(false));
    let worker_flag = Arc::clone(&flag);
    let (tx, rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        tx.send(guarded_fetch_cancellable(
            &json!({"url":"http://allowed.test/cancel-drip"}),
            &["allowed.test".into()],
            &worker_flag,
        ))
        .unwrap();
    });
    let mut command = String::new();
    io::stdin().read_line(&mut command).unwrap();
    assert_eq!(command.trim(), "cancel");
    flag.store(true, Ordering::Release);
    let decision = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    worker.join().unwrap();
    assert_eq!(decision["rule"], "EGRESS_CANCELLED");
    assert!(decision.get("body_text").is_none());
    assert_eq!(
        audit_snapshot().unwrap()["events"][0]["rule"],
        "EGRESS_CANCELLED"
    );
    // A fresh normal fetch proves the active-fetch permit was released.
    let recovered = guarded_fetch(
        &json!({"url":"http://allowed.test/plain"}),
        &["allowed.test".into()],
    );
    assert_eq!(recovered["rule"], "EGRESS_ALLOWED");
    println!("{}", json!({"cancelled":decision,"recovered":recovered}));
    io::stdout().flush().unwrap();
    // Remain alive until the harness observes peer-side socket cleanup.
    let mut finish = String::new();
    io::stdin().read_line(&mut finish).unwrap();
    assert_eq!(finish.trim(), "finish");
}
