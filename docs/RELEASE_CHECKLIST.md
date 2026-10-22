# Exact-candidate release evidence

Status: experimental; no stable release approved. [Tracking issue #65](https://github.com/rhamenator/outbound-guard-mcp/issues/65) is the durable approval record. [QUALITY_BAR.md](QUALITY_BAR.md) remains authoritative; this index does not waive or narrow its criteria.

| Gate | Evidence already available | Remaining work |
| --- | --- | --- |
| Core egress | [Threat model](threat-model.md), [DNS/HTTP fixtures](adversarial-netns.md), [address properties](ip-policy.md) | Configured HTTP parser/stream/time bounds now have controlled fixtures. Review every remaining quality-bar criterion, including OS/resolver resource limitations, fuller secrets/quarantine, redirects and reservation semantics. Current stricter denials and spent-budget behavior are documented, not automatic acceptance of a changed requirement. |
| Protocol | [Stdio regressions and Inspector](adversarial-stdio.md) | [Modern stdio and legacy compatibility](protocol-conformance.md) now have wire and official-client evidence. Independent read-only review identified a cancellation interleaving; correction and regressions are recorded in the protocol document. Priority cancellation and bounded saturation now have regressions; the final client/version matrix remains open; optional/unadvertised features are not implied. |
| Clients | Historical [Codex CLI](client-codex-cli.md) and [Claude Code](client-claude-code.md) probes; official SDK fixtures | Fresh archive ec96881e4ca9 passed actual Codex/Claude denial/GET/HEAD calls; see dated machine-readable evidence. Repeat for the final release candidate; authenticated Cursor ACP discovery/deny/GET/HEAD now pass in controlled fixtures; Codex/Cursor control-path wire cancellation gaps and desktop/terminal UI cancellation remain open. See [cancellation evidence](client-cancellation.md). |
| Adversarial | Controlled hostile fixtures, seeded mutation/property corpora, bounded process probes | Review actual attack coverage and toolset; finite passing corpora alone do not close the adversarial gate. |
| Product and supply chain | [Candidate gate](candidate-packaging.md), [dependency evidence](dependencies.md), [unreleased changelog](../CHANGELOG.md) | Final metadata/license/dependency and distribution review; retain passing independent rebuild and signed trusted-main provenance for the exact candidate. Inventory/checksums alone are not legal approval or publisher authentication. |
| Human release decision | This index and issue #65 | Explicit approval of the exact tested artifacts and buyer-facing claims before stable publication. |

The [remaining-gap review](RELEASE_GAPS.md) separates next engineering/verification steps from concrete differences between the current narrow implementation and the quality bar. No difference is silently accepted by passing CI.

## Record for each candidate

Add a comment to issue #65 containing the exact source SHA and artifact binary SHA-256, version/platform/toolchain, CI URLs, package/skill checksums, test corpus versions and results, client versions/configuration/permissions, limitations, and reviewer decision. Attach or link durable evidence: CI artifacts expire after seven days. Never put credentials, session tokens or private local paths in the record.

A failed check or missing evidence keeps the gate open. Rebuild/retest changed artifacts; a previous SHA's results do not automatically transfer. Scope adjustments require explicit recorded human review. Automation must not publish a stable tag, submit a skill, or mark this checklist complete on its own.

## Independent repositories

The user's adversarial-testing requirement separately applies to `ai-scraping-defense`, `ai-scraping-defense-rust`, `ai-scraping-defense-iis` and `ai-scraping-defense-mcp`. Reuse safe methodology and fixtures, but record each repository's commit, exercised interfaces, actual results and limitations separately. Outbound Guard evidence does not certify those projects, Request Guard or Runtime Guard.

[Priority cancellation and overload](cancellation-priority.md) now have both-era socket/audit/recovery regressions. Independent review and final-candidate client matrix still apply; do not equate fixing server-side admission with clients sending cancellation notifications.

The [PR #75 independent artifact comparison](candidate-packaging.md#first-cross-host-observation-pr-75) found identical source bytes but different recorded compilers/executables. This historical mismatch was followed by a matching pinned-native pair in PR #79 and the continuous independent-rebuild gate in PR #80. Require a matching report for the exact current candidate.

Independent executable reproducibility is now a [continuous CI gate](candidate-packaging.md#continuous-independent-rebuild-gate): a clean second runner rebuilds and adversarially tests the candidate before comparing it with the primary artifact. This is not signing, physical-host attestation or human release approval; retain the report for the exact release candidate.

[Signed experimental provenance](candidate-packaging.md#signed-experimental-candidate-workflow-provenance) is generated only after trusted main builds and independent comparison succeed. Require an actual passing main signing/verifier job, matching reviewed source and artifact hashes; PR checks alone cannot close this gate. Human stable-release approval remains separate.

The [PR #81 trusted main run](https://github.com/rhamenator/outbound-guard-mcp/actions/runs/39697968581) passed actual signature/identity verification and rejected modified bytes/wrong source identity; a skipped PR signing job is not equivalent evidence. [Seeded frame mutation/recovery](adversarial-stdio.md#seeded-frame-mutation-and-recovery) now runs before candidate comparison/signing; finite seeded cases do not close the broader fuzz/client/adversarial gates.

The [2026-10-22 fresh CI archive replay](client-cancellation.md#fresh-ci-archive-replay--2026-10-22) records actual Claude, Codex and Cursor control observations for source `5c937811120a865564240b693f8bf558fd909ab3`, with verified archive/skill hashes. Recovery passed in all three; only Claude sent matching MCP cancellation. Codex/Cursor prompt-cancellation delivery and final approved-candidate/UI matrix remain open. This does not transfer client evidence to later builds.
