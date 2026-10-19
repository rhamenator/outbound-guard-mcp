# Isolated socket probe

`bash tools/netns_adversarial_probe.sh target/debug/outbound-guard-mcp` runs the built MCP server against DNS and HTTP fixtures inside a disposable Linux network namespace. The namespace has no external route. Its only approved address, `11.0.0.1`, is assigned to its own loopback interface; the host's DNS and firewall configuration are untouched. The script needs `sudo -n`, `iproute2`, and Python 3. It removes the namespace and its private resolver configuration on exit.

The probe sends actual MCP `tools/call` requests. Private-only and mixed public/private DNS answers must produce `EGRESS_FORBIDDEN_ADDRESS` with zero HTTP requests. An approved hostname must return its plain-text response. Redirect, gzip-encoded, and declared oversized responses must produce their respective denial codes. CI runs the same fixture after building the binary.

This is socket-level evidence for these six cases, not a full adversarial certification. It does not yet cover rebinding during reconnects, malformed framing, slow drip, decompression expansion, TLS hostname mismatch, exfiltration, concurrent resource exhaustion, or real-client use. Those remain release gates in [QUALITY_BAR.md](QUALITY_BAR.md). It also cannot govern traffic an agent sends through other tools.
