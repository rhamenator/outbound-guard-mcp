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


## Stdio framing target

Set `POLICY_FUZZ_TARGET=frame` to fuzz the actual `read_frame_tracked` implementation through the development-only `fuzz_frame_stream` adapter. The example compiles the server module but never calls its main function or RPC dispatcher. An independent complete-buffer oracle splits at LF, compares exact bytes for frames of at most 64 KiB, requires oversized frames to be drained, and checks EOF synchronization. The first byte also selects one of six reader capacities from 1 byte to 65,537 bytes, exercising fragmented buffering without a real input stream.

Frame campaigns use a 131,072-byte maximum and three fixed seeds: arbitrary multi-line bytes, exactly 65,536 bytes at EOF and an oversized line followed by a valid line. Other timing/process limits match the policy target. This is slower than URL mutation because small buffers intentionally exercise the whole large frame. The report's minimum 1,000 executions still applies. CI runs policy, frame and RPC targets as a matrix and signing requires all three. Evidence names are `llvm-policy-fuzz-evidence` and `llvm-frame-fuzz-evidence`.

This proves only the exercised in-memory framing/oracle checks. Input deadlines, blocking I/O, RPC validation/dispatch, admission queues, cancellation and output backpressure require separate tests. It does not fuzz HTTP framing. The feature-gated adapter is absent from normal server builds; no tool or wire capability is added.

The completed local frame corpus and tool/input identities are retained in `tests/fixtures/frame-fuzz/`. Its archive has only generated bytes under `corpus/`; it is test data, never input for an external request tool. CI-generated corpora remain separate retained artifacts.

## MCP dispatch and session target

Set `POLICY_FUZZ_TARGET=rpc` to drive the real `handle_cancellable` dispatcher through the development-only `fuzz_rpc_dispatch` entry point. Each input is parsed as JSON; an array represents at most sixteen sequential messages, starting with a fresh session, rather than an MCP batch. A separate valid modern `tools/call` envelope routes the mutated JSON into actual `guarded_fetch` argument validation. The allowlist is always empty, so accepted URL syntax still fails host authorization before system DNS or sockets. No production main loop, stdin/stdout stream or external target is used.

The oracle requires JSON-RPC2.0 response envelopes with exactly one result/error, typed error fields, preserved successful-response IDs, object results, a bounded serialized response and JSON round-trip equality. No fetch may return `ALLOWED`. These are basic structural and fail-closed invariants, not a complete independent MCP conformance implementation. Session transitions, malformed metadata, request IDs, argument shapes and catalog/resource response construction are reached through the real dispatcher. Audit state remains process-local and bounded by the normal retention cap.

RPC campaigns use an8192-byte input maximum and three fixed seeds: a modern tool catalog request, a legacy initialize/initialized/ping sequence and guarded-fetch arguments. The same compiler/instrumentation,60-second campaign,2-second per-input timeout and hard resource ceilings apply. The CI artifact is `llvm-rpc-fuzz-evidence`; it includes source hashes, tools, full evolved corpus, logs and the coverage/growth report. No local instrumented campaign was run for this addition because a shared Copperfin VM was active; CI is the campaign environment. Normal source tests/build remain separate verification.

This target does not establish HTTP parser behavior, DNS rebinding, admission/backpressure, cancellation races or deadlines, native client behavior, instruction sanitization or production readiness. Longer independent campaigns and review remain required. Normal builds exclude the feature-gated entry point; no tool or transport capability is added.

The first completed CI RPC campaign is preserved in `tests/fixtures/rpc-fuzz/ci-corpus.tar.gz` with source/tool identities, archive checksum and coverage totals in `ci-report.json`. It completed1271840 executions with6427 coverage counters and6770 new units. The archive contains generated test data under `corpus/`, never trusted instructions or URLs to fetch. Extract only into a new disposable directory for offline replay. CI continues to start from the three fixed seeds.

## Extended manual CI campaigns

The separate **Extended offline fuzz** workflow accepts one target (`policy`, `frame` or `rpc`) and exactly60,300 or600seconds. It runs only when explicitly dispatched, with read-only repository permissions and one serialized job per ref. Routine release-gate CI retains its60-second default. Dispatch, for example:

```sh
gh workflow run extended-fuzz.yml --ref main -f target=rpc -f seconds=600
```

This uses the existing pinned compiler/actions, locked crates and distribution LLVM18 runtime. Wrapper validation rejects unsupported targets/durations before creating its output directory or compiling. Evidence records `target_seconds` and the same per-input/memory/descriptor ceilings; the hard CPU ceiling is the selected duration plus30seconds. Workflow timeout is25minutes including setup/build. Compilation and dependency download are outside the fuzz subprocess limits. A concurrency group prevents overlapping extended campaigns on the same ref; it does not reserve host resources or serialize unrelated CI workflows.

No local host or VM campaign is implied. Download the `extended-offline-fuzz-evidence` artifact within its seven-day retention window; preserve results, source/tool/runtime/input hashes, corpus identity and limitations in the release issue. Longer campaigns increase observations without establishing independent review, exhaustive coverage or production approval. These targets remain network-free with their original distinct scopes and no ASan/UBSan guarantee.
