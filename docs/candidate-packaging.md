# Local candidate packaging gate

This is experimental release evidence, not approval for a stable release or marketplace submission. The gate currently supports Linux x86_64 with Python 3.11+, the configured Rust toolchain and GNU target, Cargo dependencies, Node/npm, OpenSSL, and passwordless `sudo -n ip` for the isolated network fixture. The packaging script never creates tags, uploads files, or modifies registry listings.

Commit the intended source and documentation first, then use a new output directory:

```bash
python3 tools/package_candidate.py --output dist/candidate
cd dist/candidate
sha256sum -c SHA256SUMS
```

The script rejects tracked changes in packaging/build inputs. It builds from a temporary export of the captured Git commit, excluding untracked build scripts and repository Cargo configuration, with `--release --locked`, an explicit GNU x86_64 target and target directory, two Cargo jobs, and low process priority. The gzip archive contains the executable under `bin/`, README, unreleased changelog, GPL license, security policy, a project source archive from the same commit, and provenance with the commit, version, platform, candidate flag, and executable SHA-256. The source archive includes the build inputs and lockfile; dependencies are resolved through Cargo rather than vendored. Local AGENTS edits, untracked files, and development output are excluded by an explicit file selection.

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

Installed candidates now run the network-free modern stdio corpus plus Inspector explicit legacy/automatic-modern/pinned-modern checks. When the locked SDK fixture directory is enabled (as in CI), both legacy 1.32.1 and modern 2.3.1 cancellation/recovery cases are required. See [conformance evidence](protocol-conformance.md).

## Compiler/build evidence

Candidate `provenance.json` includes the exact `rustc -vV` and Cargo version strings observed in the exported source directory, the requested toolchain channel from that snapshot, explicit target/release/locked/jobs settings, and SHA-256 of the lockfile and embedded source archive. The build compiler is pinned to Rust/Cargo `1.99.1` in `rust-toolchain.toml`; primary CI and CodeQL read that file rather than choosing the moving stable channel. Packaging checks the observed Rust release and Cargo version against the exact pin before compiling, including when `RUSTUP_TOOLCHAIN` selects an override. This pin is not proof of cross-host reproducibility.

Before compiler/version/build execution, packaging rejects nonempty explicit compiler, wrapper, Rust flags, Cargo profile and target linker/runner override variables. Errors report variable names only, never their values. Clear those overrides before creating a review candidate; do not silently strip them and misrepresent a custom build. `RUSTUP_TOOLCHAIN` is allowed and the actual selected compiler is recorded and must match the repository pin for packaging.

This is a narrow environment gate. PATH executables, the installed toolchain, Cargo's configuration/dependency cache, native build tools and the host remain trusted build inputs. It is not a hermetic sandbox, a malicious-builder defense, signed provenance, or cross-host reproducibility evidence. Signing and independent rebuilds remain open in issue #65.

## Minimum compiler gate

The manifest declares Rust `1.89`. A separate Ubuntu 24.04 CI job installs `1.89.0`, explicitly runs `cargo +1.89.0 test --locked --all-targets` and builds the binaries/examples, then exercises the built server's CLI, modern wire protocol and numeric-ID corpus. It uses a separate compiler cache key and two build jobs. An assertion ties the tested version to the manifest so a future minimum-version edit cannot silently retain an obsolete job.

This job verifies the locked dependency graph on Linux x86_64 GNU with the declared minimum compiler. The main pinned-compiler CI job still runs the full network, SDK, Inspector, resource and packaging gates. It is not an MSRV promise for arbitrary future unlocked dependency versions, other targets or all feature combinations. Candidate provenance records its own observed build compiler; the MSRV job does not make a pinned-compiler release artifact a Rust 1.89 build. A passing job is required evidence before advertising minimum-compiler compatibility; see the PR/CI record in issue #65.

## Independent candidate comparison

Run the offline standard-library verifier on independently obtained candidate tarballs:

```bash
python3 tools/compare_candidates.py /path/to/local-candidate.tar.gz /path/to/ci-candidate.tar.gz
```

It executes no archive content and extracts nothing to disk. It checks the executable, source archive and embedded lockfile against provenance, then compares source-file bytes, recorded compiler/build settings, package claims and executable bytes. Root directory names, commit IDs and tar header timestamps are excluded from the source-content comparison: GitHub pull-request merge commits differ from branch commits even when their file bytes match. Exit 0 means those compared values match, 1 means a valid mismatch, and 2 means invalid input. Whole-archive hashes and revisions remain in the JSON report. Member count and file-content size are bounded; this is an artifact review helper, not an untrusted-archive sandbox.

A match does not authenticate a publisher or prove the builders were independent. Verify acquisition/checksums and record the hosts/workflow separately; a comparison of a file with itself is no independent rebuild evidence. This is not a signature check or stable-release approval. It compares source content, not original filesystem metadata or all packaged ancillary files.

### First cross-host observation: PR #75

The local optimized candidate at `2534e80d19e49cbf75096cb13ed2ce2e8904d4c3` and GitHub CI run [39680694775](https://github.com/rhamenator/outbound-guard-mcp/actions/runs/39680694775) at synthetic merge revision `d0c7e8be56f32025b1329b67713cfacf4cf6ded4` have identical source-file bytes and lockfile, but different compilers and executables. The verifier exits 1. The [recorded comparison](rebuild-comparison-pr75.json) retains observed hashes and settings. Local Rust is 1.96.0; CI Rust is 1.99.1. This is a failed reproducibility comparison, not an application-test failure; both candidates passed their installed tests.

Next: align an explicitly versioned build compiler across independent builders, then replay this comparison. Matching compilers alone will not guarantee identical native linker inputs, paths or executable bytes; investigate any remaining differences rather than waive them. Signing and human release review remain separate open gates.
