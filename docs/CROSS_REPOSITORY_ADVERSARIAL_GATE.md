# Independent AI Scraping Defense adversarial gates

The owner applies a reproducible adversarial testing standard to four AI Scraping Defense repositories in addition to Outbound Guard. This ledger tracks **separate acceptance work**. It does not evaluate those repositories or credit Outbound Guard results to them. The [machine-readable snapshot](evidence/independent-repository-gates-2026-11-06.json) records the local checkout heads inspected on 2026-11-06; those heads are not proposed release candidates and may change independently.

| Requested repository | Interface to qualify on its own build | Gate status in this ledger |
| --- | --- | --- |
| [ai-scraping-defense](https://github.com/rhamenator/ai-scraping-defense) | Nginx/Lua edge and Python services, using real HTTP callers | Not assessed by this loop |
| [ai-scraping-defense-rust](https://github.com/rhamenator/ai-scraping-defense-rust) | Deployed Rust service stack, using real HTTP callers | Not assessed by this loop |
| [ai-scraping-defense-iis](https://github.com/rhamenator/ai-scraping-defense-iis) | .NET edge gateway and services, using real HTTP callers on applicable platforms | Not assessed by this loop |
| `ai-scraping-defense-mcp` local checkout, now [request-guard-mcp](https://github.com/rhamenator/request-guard-mcp) | Implemented MCP transports, using real MCP clients | Not assessed by this loop; verify the requested name against the canonical repository before release decisions |

The local `ai-scraping-defense-mcp` checkout's `origin` points to `rhamenator/request-guard-mcp`, and GitHub resolves the old name to that repository. Preserve the owner's four-project requirement under the original requested name in this ledger, while recording the current canonical identity. Do not treat the Outbound Guard MCP server as a substitute for that inbound classifier.

## Evidence required for each repository

For each exact source revision and tested artifact, retain a repository-owned record of:

1. Its supported deployment and client matrix, clean installation, configuration, upgrade where applicable, removal, and residue.
2. Real client or caller versions and calls through the **implemented** interface, with request/response transcripts redacted and the relevant trust boundary identified.
3. Authorized, isolated hostile HTTP/DNS fixtures covering SSRF, DNS rebinding, exfiltration attempts, redirects, slow drip, decompression bombs, malformed protocol, resource exhaustion, and fail-closed behavior. Mark any category inapplicable only with an interface-specific explanation and a check for reachable outbound paths.
4. Negative controls that observe sockets and DNS packets where the threat is network egress, plus positive controls showing the intended route remained usable. Record fixture and capture hashes, exact commands, expected and actual outcomes, and cleanup of namespaces/containers/VMs.
5. Bounded CPU, memory, descriptor, connection, time, and output observations; record sampling limits and any failure or fix. Include native platform tests where the repository declares platform support.
6. The exact CI, static analysis, dependency, provenance, human/owner review and residual-risk decisions required by **that** repository. A passing test from another repository is methodology only.

The existing Outbound Guard [client fixture harness](../tools/client_cancellation_probe.py), [network namespace fixture](../tools/netns_adversarial_probe.py), and [Debian package probe](../tools/debian_native_container_probe.py) are reusable patterns. Port only controlled fixture data and checks appropriate to each repository's actual code and interfaces. Re-run them against that repository's own artifact and callers; record a separate result. Never claim coverage of traffic sent through other tools or components unless it was instrumented and exercised.

This ledger remains open until each repository has its own evidence and release decision. Outbound Guard itself still has open [release gates](QUALITY_BAR.md); this ledger is not an Outbound Guard release approval.
