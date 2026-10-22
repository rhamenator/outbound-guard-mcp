//! Network-free adapter for external address-classification oracles.
use std::io::{self, BufRead};
use std::net::IpAddr;

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.expect("read IP input");
        let ip: IpAddr = line.parse().expect("valid IP input");
        println!("{}", outbound_guard_mcp::public_ip(ip));
    }
}
