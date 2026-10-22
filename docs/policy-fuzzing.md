# Network-free LLVM policy fuzzing

The development example `policy_fuzz` drives the real `validate` function with JSON and raw URL mutations using LLVM libFuzzer feedback. Its resolver is a stub returning one approved fixture address; it never calls `guarded_fetch`, the system resolver, sockets or external servers. Accepted results must retain the approved hostname/address, GET/HEAD, HTTP(S), and absent userinfo/query/fragment. Parser panics or invariant failures abort the harness and fail the campaign. This targets URL/schema policy; it is not a fuzz target for HTTP framing, MCP admission, DNS rebinding, TLS or cancellation.

No fuzzer crate is added. The opt-in `policy-fuzz` Cargo feature enables an example linked against an operator-installed LLVM `libclang_rt.fuzzer_no_main` static development runtime. Normal builds do not link libFuzzer; the example without this feature exits with setup instructions. The small FFI adapter is development-only: libFuzzer owns each callback buffer, and CLI C strings/pointers remain live during its driver call. The zero-length input path does not dereference its pointer.

From the repository root, with pinned Rust/dependencies cached and a matching installed clang runtime:

```sh
export LIBFUZZER_RUNTIME="$(clang --print-file-name=libclang_rt.fuzzer_no_main-x86_64.a)"
export POLICY_FUZZ_OUTPUT=/tmp/outbound-policy-fuzz-new
bash tools/policy_fuzz.sh
```

Choose a new output directory under an existing parent. Runtime paths must contain no whitespace. `POLICY_FUZZ_CLANG` selects the clang command recorded in metadata (default `clang`). The wrapper uses a separate `target/policy-fuzz` directory, two nice-priority build jobs, then one fuzzing worker. Instrumentation uses LLVM sanitizer coverage counters, PC tables and comparison tracing. This is **not AddressSanitizer/UBSan**; the runtime can warn that optional sanitizer crash/stack hooks are unavailable. Those warnings are retained. Absence of a crash is not proof of memory safety.

Each campaign starts with three fixed URL/JSON/loopback seeds and integer seed 306373022. It targets 60 seconds with a two-second per-input timeout, 4,096-byte maximum input and 512 MiB libFuzzer RSS threshold. The campaign subprocess also has hard Linux limits of 1 GiB virtual address space, 64 descriptors and 90 CPU seconds. Compilation is outside those process limits. Scheduling, engine/compiler versions and coverage feedback can change execution counts and the evolved corpus; this is a repeatable bounded campaign, not a promise of byte-identical final corpus.

Evidence includes logs, Rust/clang versions, linked-runtime SHA256, source-input hashes, generated corpus and a JSON report with per-file hashes. The report requires observed instrumentation, at least 1,000 executions, positive coverage and feedback-guided corpus growth, and no crash/timeout artifacts. Retain failing inputs as regression fixtures after reviewing them. CI installs the distribution's LLVM 18 development runtime, fetches only locked crates, runs the bounded campaign and retains evidence for seven days even on failure. Candidate signing requires this job to pass. Local LLVM 21 and CI LLVM 18 results are separate campaign observations, with their exact runtime identities recorded.

The limited target, invariants and duration leave substantial work open: longer independent campaigns, parser/framing targets, native-client behavior, deployment failures and human scope/release review. A passing fuzz campaign does not establish coverage of traffic sent by other tools or certify the AI Scraping Defense repositories.

The first completed local campaign's evolved inputs are preserved in `tests/fixtures/policy-fuzz/local-corpus.tar.gz`, with archive identity/tool versions/source-input hashes in `local-report.json`. The archive contains only generated test inputs under `corpus/`, derived from the three synthetic seeds. Extract it into a new disposable directory to replay or extend that campaign; do not treat its contents as trusted instructions or URLs to fetch. CI still starts from the three fixed seeds so new exploration is measured separately. CI's generated corpus/logs remain separate seven-day artifacts.
