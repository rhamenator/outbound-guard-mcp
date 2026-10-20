# Address policy review

`guarded_fetch` accepts DNS hostnames only. It checks **every** returned address before constructing the HTTP client, then pins the checked set for the connection. One non-public answer blocks the entire call. The policy is intentionally conservative: some globally reachable special-purpose ranges may also be denied.

The IPv4 and IPv6 predicates in `src/lib.rs` were compared with the IANA [IPv4 Special-Purpose Address Space](https://www.iana.org/assignments/iana-ipv4-special-registry/) and [IPv6 Special-Purpose Address Space](https://www.iana.org/assignments/iana-ipv6-special-registry/) registries on 2026-10-18. In particular, the IPv4 `192.88.99.0/24` relay range was already blocked; this review added the IPv6 documentation range `3fff::/20`. Tests cover each range and mixed DNS answer sets.

This static review is not a live registry feed or a proof that every allowed public IP is safe. A separate DNS deadline, controlled rebinding fixtures, and socket-level adversarial evidence remain release gates in [QUALITY_BAR.md](QUALITY_BAR.md).

## Generated policy regression evidence

Run `cargo test --locked --test ip_policy_properties`. The dependency-free integration test uses seed `0x6f7574626f756e64`, wrapping integer arithmetic, and a separate numeric CIDR interval oracle for the policy documented above. It checks about 1.31 million IPv4/IPv6 samples: 65,536 full-space samples per family, 65,536 interior samples for each denied CIDR, and exact edges and neighboring addresses. Allowed neighbors are checked as well as denied ranges, so an accidentally overbroad block also fails. This is a finite regression corpus against our conservative policy, not a new IANA review or coverage-guided fuzzing.

A second test places a generated forbidden answer at each of the 16 possible positions in otherwise public DNS results for every modeled denied range (288 mixed sets), with an all-public control. It calls the production validator with an injected resolver and checks `EGRESS_FORBIDDEN_ADDRESS`; it performs no DNS query or socket operation. Actual resolver and connection behavior remains covered separately by the isolated network probe.

Mutation sanity checks on 2026-10-20 confirmed the tests fail when the CGNAT predicate is omitted, and when DNS policy examines only the first answer. Both temporary mutations were restored before the full gate. Replay failures report the seed, IP, or DNS answer position. Broader IPv6 special-purpose policy review, wire-format DNS fuzzing, and arbitrary external DNS behavior remain separate work.
