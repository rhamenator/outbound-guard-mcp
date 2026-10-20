# Dependency decisions

The runtime declares two direct crates: `serde_json` for bounded JSON-RPC messages and `reqwest` with only `blocking` and `rustls-tls` enabled. TLS certificate and hostname verification, HTTP framing, and pinned address connection handling are security-sensitive enough that reimplementing them with raw sockets would add more risk than these maintained libraries. The lockfile pins their transitive graph for reproducible CI and audit. No HTML parser, regex engine, database, proxy middleware, or async runtime is directly required by this first milestone.

The server still needs dependency review and advisory gates before a stable release. A future move to a smaller HTTP client must preserve the pinned DNS behavior, TLS hostname checks, disabled ambient proxies, redirect policy, and bounded streaming reads.

`serde_json` enables its `arbitrary_precision` feature so response syntax validation accepts valid large JSON numbers (for example `1e400`) without forcing them into finite floating-point values. The existing nesting guard and response byte cap remain active. This feature adds no crate to the dependency graph.
