# Local candidate packaging gate

This is experimental release evidence, not approval for a stable release or marketplace submission. The gate currently supports Linux x86_64 with Python 3.11+, the configured Rust toolchain and GNU target, Cargo dependencies, Node/npm, OpenSSL, and passwordless `sudo -n ip` for the isolated network fixture. The packaging script never creates tags, uploads files, or modifies registry listings.

Commit the intended source and documentation first, then use a new output directory:

```bash
python3 tools/package_candidate.py --output dist/candidate
cd dist/candidate
sha256sum -c SHA256SUMS
```

The script rejects tracked changes in packaging/build inputs. It builds from a temporary export of the captured Git commit, excluding untracked build scripts and repository Cargo configuration, with `--release --locked`, an explicit GNU x86_64 target and target directory, two Cargo jobs, and low process priority. The gzip archive contains the executable under `bin/`, README, GPL license, security policy, a project source archive from the same commit, and provenance with the commit, version, platform, candidate flag, and executable SHA-256. The source archive includes the build inputs and lockfile; dependencies are resolved through Cargo rather than vendored. Local AGENTS edits, untracked files, and development output are excluded by an explicit file selection.

The companion ZIP contains exactly `outbound-guard/SKILL.md` and `outbound-guard/LICENSE`, with `name` and `description` frontmatter and its experimental status preserved. It contains no server binary. The skill requires a separately installed server; its installation and permissions instructions remain in SKILL.md. `SHA256SUMS` covers both archives. Checksums identify bytes and detect accidental changes; they are not signatures or proof of publisher identity.

The gate inspects archive membership and permissions, copies only the known executable into a temporary installation outside the checkout, and checks MCP initialization, discovery, a blocked call, and the audit resource. The installed optimized executable also runs through the isolated hostile HTTP/DNS fixtures and official Inspector. Server environment variables are cleared for this fresh-install test. The temporary installation is removed afterward; verified artifacts remain in the output directory for human review. CI runs the same gate after the debug checks.

After verification, CI retains the candidate archives and checksum manifest as an `experimental-candidate-linux-x86_64` workflow artifact for seven days. It uses the same pinned upload action as Request Guard. This is review storage, not a GitHub Release or marketplace listing.

Archive timestamps and ownership are fixed, and ZIP membership is explicit. This makes packaging repeatable for identical build outputs; it does not prove byte-identical compilation across toolchains, dependency caches, or hosts. The gate does not close client compatibility, full protocol conformance, dependency attribution review, signing, offline builds, or human release approval. Each candidate must still pass the repository quality bar before a stable release or marketplace submission.

The committed source snapshot includes `tests/`, including the generated IP-policy integration corpus, so address-policy evidence can be replayed from the candidate source archive.

Installed candidates also run the complete stdio adversarial probe, including malformed request metadata, handshake preservation, audit redaction, and the no-tool-dispatch regression.

Candidate archives include a [locked dependency inventory and upstream notices](dependencies.md#candidate-inventory-and-notices). Each notice is checked against its cached crate archive after the archive checksum is matched to Cargo.lock. The standalone skill ZIP continues to contain only its SKILL.md and the project GPL license.

Candidate checks compile a separate cancellation-probe example from the committed snapshot and run it against the controlled streaming fixture. Its source is included in the source archive; the consumer executable is not distributed as a second MCP server.

CI also sets `OUTBOUND_GUARD_TEST_SDK_DIR` to the locked development-only TypeScript SDK probe, so the installed optimized candidate must pass the official SDK AbortSignal streaming-cancellation scenario. Local candidate runs include this check only when that variable is set; the fixture prints an explicit omission otherwise. See [replay instructions](adversarial-netns.md#official-sdk-abortsignal).

The installed candidate also passes `tools/cli_smoke.py`: exact manifest version, help without valid configuration, zero-host and deduplicated-host config checks, malformed allowlist/CA rejection, unknown/combined-argument rejection, and no echo of synthetic private configuration. These diagnostic commands exit without starting an MCP session; only the no-argument invocation starts stdio. Startup checks do not probe network reachability or replace the controlled client/network tests.

Installed Inspector checks now select the era through a temporary read-only server config, exercising explicit legacy, automatic fallback and pinned-modern refusal. See [the harness correction and limits](adversarial-stdio.md#inspector-era-selection-and-fallback); earlier unsupported CLI flags did not prove era selection.
