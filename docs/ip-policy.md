# Address policy review

`guarded_fetch` accepts DNS hostnames only. It checks **every** returned address before constructing the HTTP client, then pins the checked set for the connection. One non-public answer blocks the entire call. The policy is intentionally conservative: some globally reachable special-purpose ranges may also be denied.

The IPv4 and IPv6 predicates in `src/lib.rs` were compared with the IANA [IPv4 Special-Purpose Address Space](https://www.iana.org/assignments/iana-ipv4-special-registry/) and [IPv6 Special-Purpose Address Space](https://www.iana.org/assignments/iana-ipv6-special-registry/) registries on 2026-10-18. In particular, the IPv4 `192.88.99.0/24` relay range was already blocked; this review added the IPv6 documentation range `3fff::/20`. Tests cover each range and mixed DNS answer sets.

This static review is not a live registry feed or a proof that every allowed public IP is safe. A separate DNS deadline, controlled rebinding fixtures, and socket-level adversarial evidence remain release gates in [QUALITY_BAR.md](QUALITY_BAR.md).
