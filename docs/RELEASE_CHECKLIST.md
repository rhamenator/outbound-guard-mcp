# Exact-candidate release evidence

Status: experimental; no stable release approved. [Tracking issue #65](https://github.com/rhamenator/outbound-guard-mcp/issues/65) is the durable approval record. [QUALITY_BAR.md](QUALITY_BAR.md) remains authoritative; this index does not waive or narrow its criteria.

| Gate | Evidence already available | Remaining work |
| --- | --- | --- |
| Core egress | [Threat model](threat-model.md), [DNS/HTTP fixtures](adversarial-netns.md), [address properties](ip-policy.md) | Configured HTTP parser/stream/time bounds now have controlled fixtures. Review every remaining quality-bar criterion, including OS/resolver resource limitations, fuller secrets/quarantine, redirects and reservation semantics. Current stricter denials and spent-budget behavior are documented, not automatic acceptance of a changed requirement. |
| Protocol | [Stdio regressions and Inspector](adversarial-stdio.md) | [Modern stdio and legacy compatibility](protocol-conformance.md) now have wire and official-client evidence. Independent read-only review identified a cancellation interleaving; correction and regressions are recorded in the protocol document. Saturation policy and the final client/version matrix remain open; optional/unadvertised features are not implied. |
| Clients | Historical [Codex CLI](client-codex-cli.md) and [Claude Code](client-claude-code.md) probes; official SDK fixtures | Fresh archive ec96881e4ca9 passed actual Codex/Claude denial/GET/HEAD calls; see dated machine-readable evidence. Repeat for the final release candidate; authenticated Cursor and client UI cancellation remain open. |
| Adversarial | Controlled hostile fixtures, seeded mutation/property corpora, bounded process probes | Review actual attack coverage and toolset; finite passing corpora alone do not close the adversarial gate. |
| Product and supply chain | [Candidate gate](candidate-packaging.md), [dependency evidence](dependencies.md), [unreleased changelog](../CHANGELOG.md) | Metadata, license/dependency review, cross-host build reproducibility, signing and complete distribution review. Inventory/checksums are not legal approval or publisher authentication. |
| Human release decision | This index and issue #65 | Explicit approval of the exact tested artifacts and buyer-facing claims before stable publication. |

## Record for each candidate

Add a comment to issue #65 containing the exact source SHA and artifact binary SHA-256, version/platform/toolchain, CI URLs, package/skill checksums, test corpus versions and results, client versions/configuration/permissions, limitations, and reviewer decision. Attach or link durable evidence: CI artifacts expire after seven days. Never put credentials, session tokens or private local paths in the record.

A failed check or missing evidence keeps the gate open. Rebuild/retest changed artifacts; a previous SHA's results do not automatically transfer. Scope adjustments require explicit recorded human review. Automation must not publish a stable tag, submit a skill, or mark this checklist complete on its own.

## Independent repositories

The user's adversarial-testing requirement separately applies to `ai-scraping-defense`, `ai-scraping-defense-rust`, `ai-scraping-defense-iis` and `ai-scraping-defense-mcp`. Reuse safe methodology and fixtures, but record each repository's commit, exercised interfaces, actual results and limitations separately. Outbound Guard evidence does not certify those projects, Request Guard or Runtime Guard.
