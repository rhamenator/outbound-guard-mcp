//! Deterministic, network-free checks against the documented CIDR policy.
use outbound_guard_mcp::{public_ip, validate, Resolver};
use serde_json::json;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

const SEED: u64 = 0x6f75_7462_6f75_6e64;
const V4_DENY: &[(&str, u32)] = &[
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
    ("224.0.0.0", 3),
];
const V6_DENY: &[(&str, u32)] = &[
    ("2001::", 23),
    ("2001:db8::", 32),
    ("2002::", 16),
    ("3fff::", 20),
];

fn next(state: &mut u64) -> u64 {
    // Explicit wrapping arithmetic makes replay independent of debug/release.
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state
}
fn ranges(entries: &[(&str, u32)], v4: bool) -> Vec<(u128, u128)> {
    entries
        .iter()
        .map(|(base, prefix)| {
            let start = if v4 {
                u32::from(base.parse::<Ipv4Addr>().unwrap()) as u128
            } else {
                u128::from(base.parse::<Ipv6Addr>().unwrap())
            };
            let bits = if v4 { 32 } else { 128 };
            let end = start | (u128::MAX >> (128 - (bits - prefix)));
            (start, end)
        })
        .collect()
}
fn inside(value: u128, entries: &[(u128, u128)]) -> bool {
    entries
        .iter()
        .any(|(first, last)| (*first..=*last).contains(&value))
}
fn check(ip: IpAddr, denied: &[(u128, u128)]) {
    let expected = match ip {
        IpAddr::V4(ip) => !inside(u32::from(ip) as u128, denied),
        IpAddr::V6(ip) => {
            let value = u128::from(ip);
            let global_start = u128::from("2000::".parse::<Ipv6Addr>().unwrap());
            let global_end = u128::from(
                "3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
                    .parse::<Ipv6Addr>()
                    .unwrap(),
            );
            (global_start..=global_end).contains(&value) && !inside(value, denied)
        }
    };
    assert_eq!(public_ip(ip), expected, "seed={SEED:#x}, ip={ip}");
}

#[test]
fn generated_addresses_match_cidr_oracle() {
    let v4 = ranges(V4_DENY, true);
    let v6 = ranges(V6_DENY, false);
    let mut state = SEED;
    for _ in 0..65536 {
        check(Ipv4Addr::from((next(&mut state) >> 32) as u32).into(), &v4);
        let value = ((next(&mut state) as u128) << 64) | next(&mut state) as u128;
        check(Ipv6Addr::from(value).into(), &v6);
        // Uniform sampling rarely hits small deny ranges. Sample every range's
        // interior and both neighbors as well, including all allowed neighbors.
        for (entries, is_v4) in [(&v4, true), (&v6, false)] {
            for &(first, last) in entries {
                let random = ((next(&mut state) as u128) << 64) | next(&mut state) as u128;
                let value = first + random % (last - first + 1);
                if is_v4 {
                    check(Ipv4Addr::from(value as u32).into(), entries);
                } else {
                    check(Ipv6Addr::from(value).into(), entries);
                }
            }
        }
    }
    for (entries, is_v4) in [(&v4, true), (&v6, false)] {
        for &(first, last) in entries {
            for value in [first.saturating_sub(1), first, last, last + 1] {
                if is_v4 && value > u32::MAX as u128 {
                    continue;
                }
                if is_v4 {
                    check(Ipv4Addr::from(value as u32).into(), entries);
                } else {
                    check(Ipv6Addr::from(value).into(), entries);
                }
            }
        }
    }
}

struct Answers(Vec<SocketAddr>);
impl Resolver for Answers {
    fn resolve(&self, _: &str, _: u16) -> io::Result<Vec<SocketAddr>> {
        Ok(self.0.clone())
    }
}
#[test]
fn forbidden_dns_answer_blocks_at_every_position() {
    let allowed = vec!["example.com".to_owned()];
    let args = json!({"url":"https://example.com/"});
    let mut state = SEED;
    for (entries, is_v4) in [
        (ranges(V4_DENY, true), true),
        (ranges(V6_DENY, false), false),
    ] {
        for (first, last) in entries {
            let value = first + next(&mut state) as u128 % (last - first + 1);
            let ip: IpAddr = if is_v4 {
                Ipv4Addr::from(value as u32).into()
            } else {
                Ipv6Addr::from(value).into()
            };
            for position in 0..16 {
                let mut addresses = vec!["11.0.0.1:443".parse().unwrap(); 16];
                addresses[position] = SocketAddr::new(ip, 443);
                let denial = validate(&args, &allowed, &Answers(addresses))
                    .err()
                    .expect("mixed DNS admitted");
                assert_eq!(
                    denial.rule, "EGRESS_FORBIDDEN_ADDRESS",
                    "{ip}, position={position}"
                );
            }
        }
    }
    let addresses = vec!["11.0.0.1:443".parse().unwrap(); 16];
    assert!(validate(&args, &allowed, &Answers(addresses)).is_ok());
}
