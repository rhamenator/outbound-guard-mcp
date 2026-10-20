# Local candidate packaging gate

This is experimental release evidence, not approval for a stable release or marketplace submission. The gate currently supports Linux x86_64 with Python 3.11+, the configured Rust toolchain and GNU target, Cargo dependencies, Node/npm, OpenSSL, and passwordless `sudo -n ip` for the isolated network fixture. It never creates tags, uploads files, or modifies registry listings.

Commit the intended source and documentation first, then use a new output directory:

```bash
python3 tools/package_candidate.py --output dist/candidate
cd dist/candidate
sha256sum -c SHA256SUMS
```

The script rejects tracked changes in packaging/build inputs. It builds from a temporary export of the captured Git commit, excluding untracked build scripts and repository Cargo configuration, with `--release --locked`, an explicit GNU x86_64 target and target directory, two Cargo jobs, and low process priority. The gzip archive contains the executable under `bin/`, README, GPL license, security policy, a project source archive from the same commit, and provenance with the commit, version, platform, candidate flag, and executable SHA-256. The source archive includes the build inputs and lockfile; dependencies are resolved through Cargo rather than vendored. Local AGENTS edits, untracked files, and development output are excluded by an explicit file selection.

The companion ZIP contains exactly `outbound-guard/SKILL.md` and `outbound-guard/LICENSE`, with `name` and `description` frontmatter and its experimental status preserved. It contains no server binary. The skill requires a separately installed server; its installation and permissions instructions remain in SKILL.md. `SHA256SUMS` covers both archives. Checksums identify bytes and detect accidental changes; they are not signatures or proof of publisher identity.

The gate inspects archive membership and permissions, copies only the known executable into a temporary installation outside the checkout, and checks MCP initialization, discovery, a blocked call, and the audit resource. The installed optimized executable also runs through the isolated hostile HTTP/DNS fixtures and official Inspector. Server environment variables are cleared for this fresh-install test. The temporary installation is removed afterward; verified artifacts remain in the output directory for human review. CI runs the same gate after the debug checks.

Archive timestamps and ownership are fixed, and ZIP membership is explicit. This makes packaging repeatable for identical build outputs; it does not prove byte-identical compilation across toolchains, dependency caches, or hosts. The gate does not close client compatibility, full protocol conformance, dependency attribution review, signing, offline builds, or human release approval. Each candidate must still pass the repository quality bar before a stable release or marketplace submission.
