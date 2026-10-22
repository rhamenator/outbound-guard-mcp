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

## Controlled build path remapping

The first compiler-aligned local/CI comparison (PR #77, CI run 39684517905) matched source bytes and all recorded settings but not executable hashes. Both binaries embedded their builder's absolute Cargo cache paths in dependency panic strings. This identifies one concrete obstacle, not proof of the only cause.

Candidate builds now set only internally generated `--remap-path-prefix` Rust flags for the exported source, Cargo home and target directory, mapping to `/build/source`, `/build/cargo` and `/build/target`. The encoded Cargo flags preserve argument boundaries even when source/cache paths contain spaces. User-supplied compiler/wrapper/flag overrides remain rejected before constructing this environment. The logical mapping policy is recorded in provenance and compared by the offline verifier; private absolute builder paths are not recorded there. This applies to candidate Rust builds, including dependencies, not ordinary debug builds or native C compilation.

Path normalization is not a hermetic compiler/linker sandbox. Native tools, system libraries, host configuration and Cargo cache remain trusted inputs. Independent artifacts must still match; inspect any remaining mismatch rather than assuming that remapping proves reproducibility.

## Pinned native candidate builder

CI builds candidate binaries with `--container-build`. To reproduce that native environment locally, use Docker and a fresh output directory:

```bash
python3 tools/package_candidate.py --container-build --output dist/native-candidate
```

The builder is the Linux amd64 manifest of the official Rust 1.99.1 slim Bookworm image, pinned by immutable digest in `BUILDER_IMAGE` in the packaging script. This pins the image's Rust, GCC, libc/startup inputs and native build utilities together. No apt update or tool installation occurs inside the build. Docker may download the image and Cargo downloads checksum-locked public dependencies into a separate cache under `target/candidate-container-cargo`. Access to the local Docker daemon is required; Docker access itself is privileged host capability. The ordinary host build remains available without the flag, but is not equivalent independent native-build evidence.

The container runs as the invoking UID/GID with a read-only root filesystem/source mount, dropped capabilities, no-new-privileges, two CPUs, 4 GiB memory including swap, 256 PIDs and a bounded temporary filesystem. Only the committed source export, dedicated target directory and dedicated Cargo cache are mounted. Host home, credentials, environment overrides and Docker socket are not passed into the builder. Network remains available for Cargo; this is not an offline or malicious-builder sandbox. Builds execute dependency build scripts and trust the pinned image, Docker daemon and host kernel.

Provenance records the immutable builder reference, platform and observed container GCC/libc versions alongside the actual Rust/Cargo versions. Both versions are checked against the repository pin before compilation; evidence is rechecked after compilation. The offline comparator includes native-builder evidence, so host-vs-container settings cannot silently count as equivalent. The compiled binary and cancellation example are then exercised by the existing fresh-install/controlled-hostile fixtures outside the container. The server's runtime does not require Docker.

This follows the compiler-aligned/path-remapped PR #78 comparison, which still differed in `.text`, unwind data and other ELF sections with local GCC15.2 versus CI GCC13.3. A pinned environment is an input control; only an actual independent matching binary comparison can supply reproducibility evidence. Signing, independent-host attestation and human stable-release approval remain separate gates.

## Continuous independent rebuild gate

The separate `Independent native rebuild` CI job starts after the primary Rust job succeeds. It uses a new runner job, restores no compiler/target cache, fetches checksum-locked sources for notice inspection, and rebuilds in the same digest-pinned native image with its own Cargo and target directories. It runs the complete installed-candidate adversarial, SDK, Inspector, framing and resource gate again. Only after that independent build/test does it download the tested primary artifact from the same workflow run, verify both checksum manifests and require `compare_candidates.py` to exit 0. A source, recorded-setting, package-claim or executable mismatch fails CI; it is not automatically normalized or waived.

The comparison JSON is retained as `independent-rebuild-comparison-linux-x86_64` for seven days, including a valid mismatch report when comparison fails. The primary artifact contains the candidate bytes. No report is expected if the build fails before comparison; that failure remains visible in the job log. Both jobs have twenty-minute timeouts and the rebuild job has only contents/actions read permissions. Its GitHub token is used only by the host artifact-download step, after the builder has exited; it is not passed into the build container. No attestation/signing permission or stable publication is enabled.

This automates the manually observed PR #79 match (local Ubuntu26.04 vs GitHub Ubuntu24.04, executable SHA-256 `707c81e84afdd8f6dda181edc7250483df47855a46de9511ccc4a71fb5aa76e8`). Separate GitHub runner jobs are not cryptographic proof of independent physical hosts, independent publishers or a trustworthy builder image. Both use the same workflow/source and immutable build environment. Candidate/release review must retain the exact run, comparison, checksums and supported-client evidence; signing, client-cancellation coverage and human approval remain open.

## Signed experimental-candidate workflow provenance

After both build jobs pass on a push to this repository's `main`, the `Sign verified candidate provenance` job checks the primary archive against the successful independent comparison and exact workflow commit, then signs provenance for the candidate tarball, companion skill ZIP and checksum manifest. Pull requests and forks skip this signing job. It downloads and hashes data; it does not execute candidate contents. No stable tag, GitHub Release, registry push or marketplace publication is created.

The pinned official [`actions/attest` action](https://github.com/actions/attest) uses GitHub OIDC and a short-lived Sigstore certificate. Only that trusted job receives `id-token: write` and `attestations: write`, alongside read access for artifact downloads. Other build jobs retain their existing read permissions. Registry push/storage-record creation is disabled; no packages/content-write permission or long-lived signing key is added. This public repository uses GitHub/Sigstore's public attestation infrastructure; provenance is public and authenticates the workflow identity/digest, not human release approval.

The job verifies all three artifacts with the [GitHub CLI verifier](https://cli.github.com/manual/gh_attestation_verify), requiring this repository's `ci.yml`, `refs/heads/main`, the exact source commit and GitHub-hosted runners. It also requires rejection of a modified archive and an incorrect source identity. The signed bundle and JSON verification results are retained as `experimental-candidate-provenance-linux-x86_64` for seven days; the GitHub attestation API stores the published provenance. A skipped PR signing job is not passing signed-candidate evidence: inspect the trusted main run and its verification result before making that claim.

Before extracting or running a downloaded candidate, use a GitHub CLI with `gh attestation verify` support (the author's system CLI 2.46 lacks it; verification is being exercised with official CLI 2.103.0). Choose the **reviewed main source commit**, not a PR head or an arbitrary latest commit:

```bash
gh attestation verify ./candidate.tar.gz --repo rhamenator/outbound-guard-mcp --signer-workflow rhamenator/outbound-guard-mcp/.github/workflows/ci.yml --source-ref refs/heads/main --source-digest REVIEWED_MAIN_COMMIT --deny-self-hosted-runners
```

Repeat for the skill ZIP and `SHA256SUMS`, then check `sha256sum -c SHA256SUMS` in the downloaded directory. Keep the exact source, workflow run, archive hashes, comparison and verification results in release-review evidence. A valid signature proves the named workflow signed those bytes under the verifier's trust policy; it does not prove absence of vulnerabilities, independence of physical builders, a trustworthy pinned image/kernel, account security, supported-client cancellation or authorization to publish a stable release. Local and PR candidates remain unsigned by this workflow. Human review and all other quality gates remain required.

Candidate verification also requires Linux `strace` with permission to trace owned children for the [pre-DNS syscall observation gate](adversarial-stdio.md#independent-syscall-observation-of-pre-dns-denials). CI installs the development package if absent and runs the gate on debug and both installed candidates. Ordinary server users do not need strace or elevated permissions.

The controlled network launcher also requires the development `nftables` package for its namespace-only TCP SYN-drop fixture. CI installs it if absent. Rules are created only through `ip netns exec` in a fresh owned namespace and disappear with that namespace; no host firewall modification or production-user privilege is required.
