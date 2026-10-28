# Separate AI Scraping Defense adversarial gates

The owner requires the Outbound Guard adversarial standard to be applied separately to four AI Scraping Defense repositories. This page tracks the handoff, not a result for any of them. The commit IDs below were read on 2026-10-28 only to identify the starting snapshots; no tests, package checks, client sessions or CI for those commits were performed in this Outbound Guard run. Recheck each repository's current commit and instructions before testing.

| Repository | Local snapshot | Gate status in this tracker |
| --- | --- | --- |
| `/home/rich/dev/ai-scraping-defense` | `3f693a683d6c` | Evidence not yet assessed here |
| `/home/rich/dev/ai-scraping-defense-rust` | `5be9e16d6cbe` | Evidence not yet assessed here |
| `/home/rich/dev/ai-scraping-defense-iis` | `60f1b7e75405` | Evidence not yet assessed here |
| `/home/rich/dev/ai-scraping-defense-mcp` | `89128f7632bc` | Evidence not yet assessed here |

For **each** repository, record the tested commit and built artifact, the production interface and actual client used, the authorized pentesting tool versions, the controlled fixture configuration, commands/seeds/corpus, resource limits, raw or redacted results, findings and fixes, CI identity, and unresolved limits. Test SSRF, DNS rebinding, exfiltration, redirects, slow drip, decompression bombs, malformed protocol, resource exhaustion and fail-closed behavior wherever the product can exercise that behavior. Explain any nonapplicable case from the product's actual interface; never turn “not applicable” or “untested” into a pass. MCP products need real MCP-client replays; other products need their real deployed client and hosting path. Tests should prove forbidden destinations were not reached and synthetic secrets were not returned or logged where those claims apply. Do not use real secrets or public attack targets.

The route-free DNS/HTTP fixtures, seeded mutation style, bounded fuzzing, process-limit probes and [native-client replay method](client-cancellation.md) from Outbound Guard are reusable starting points. Adapt the harness to each implementation and independently verify it exercises that product's actual enforcement path. Outbound Guard's [finite evidence](RELEASE_CHECKLIST.md) does not certify another repository, and traffic sent through other tools is outside Outbound Guard's boundary.

Before declaring any one repository's gate complete, link its own exact-head results, negative controls, residual risks and owner decision in that repository. Keep the other rows open until their own evidence is reviewed. No official Outbound Guard release decision or AI Scraping Defense release decision follows from this handoff page.
