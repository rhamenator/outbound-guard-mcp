# Network-free LLVM policy fuzzing

## Raw HTTP wire parser campaign (2026-11-09)

The `wire_fuzz` development target feeds mutated HTTP/1 response bytes through an in-process duplex peer to the production Hyper client parser configuration, header limits, `BudgetIo` stream wrapper, response-framing decision, and body poll. Its fixed 4 KiB read budget is smaller than the guarded fetch's per-call budget. Seeds include a valid response, duplicate and conflicting framing, chunked framing, truncated body, and an interim response. Run it with `POLICY_FUZZ_TARGET=wire` and the LLVM setup below. CI runs a bounded 60-second campaign and uploads its corpus and report. No new runtime dependency is needed.

The local Clang 18 campaign completed 375,754 executions in 60 seconds, reached 3,001 coverage counters and 3,066 features, and added 53 feedback-guided units. It produced no crash or timeout artifact. The [report](../tests/fixtures/wire-fuzz/local-report.json), [27-file verified corpus](../tests/fixtures/wire-fuzz/local-corpus.tar.gz), [source hashes](../tests/fixtures/wire-fuzz/local-inputs.sha256), [runtime hash](../tests/fixtures/wire-fuzz/local-runtime.sha256), [compressed log](../tests/fixtures/wire-fuzz/local-campaign.log.gz), and compiler identities are retained. The report and corpus SHA-256 values are `8cf36fc81489c28bc9a7bd85c46b7efeb2cf17def4afd69af4ecc5dd15dc428f` and `507ea1788ff94aec2f08ec5dbdbded57833a9f10b84c7d0101d859d866f777c8`.

```sh
python3 tools/verify_fuzz_archive.py tests/fixtures/wire-fuzz/local-corpus.tar.gz tests/fixtures/wire-fuzz/local-report.json --max-member-bytes 4096
```

This target checks for panics and bounded completion, without an independent semantic oracle. It does not use TCP, TLS, DNS, native MCP clients, cancellation, or traffic sent through other tools. It cannot close the independent adversarial review or release gates. The four AI Scraping Defense repositories need their own evidence.

The `http_fuzz` development target drives the same `response_framing_denial` decision used after Hyper parses a guarded response. It mutates up to two `Content-Length` and two `Transfer-Encoding` values in a `HeaderMap`, then compares the production rule with a separate checked-decimal oracle. Seeds cover the largest valid length, integer overflow, duplicate lengths, conflicting framing, `chunked`, and stacked codings. The normal build adds no dependency. CI runs a bounded 60-second campaign and retains its report and evolved corpus as a short-lived workflow artifact. To repeat locally, set `POLICY_FUZZ_TARGET=http` alongside the documented LLVM runtime and evidence-directory variables before running `tools/policy_fuzz.sh`.

This target starts after raw HTTP parsing. It does not fuzz Hyper's wire parser, sockets, DNS, deadlines, cancellation or clients, and a matching decision does not prove general HTTP request-smuggling resistance. The controlled raw-wire fixtures and real-client replays remain separate evidence.

The first local 60-second LLVM 21 campaign on 2026-11-09 completed 5,399,981 executions, reached 657 coverage counters and 1,664 features, and reported 298 new units with no crash or timeout artifact. Its [report](../tests/fixtures/http-fuzz/local-report.json), [96-file corpus archive](../tests/fixtures/http-fuzz/local-corpus.tar.gz), [source hashes](../tests/fixtures/http-fuzz/local-inputs.sha256), [runtime hash](../tests/fixtures/http-fuzz/local-runtime.sha256), [compressed log](../tests/fixtures/http-fuzz/local-campaign.log.gz), [Rust compiler identity](../tests/fixtures/http-fuzz/local-rustc.txt), and [Clang identity](../tests/fixtures/http-fuzz/local-clang.txt) are retained. The corpus and report hashes are `37c297226181986c11b93f276c224ca1f6d8bfa9ecb27e04526874afe4607d37` and `f5b1a284b9b3321b7c7f06f5f937fec95d0cd5c8f8862895ec33dd8dd90eff53` respectively. CI verifies the retained archive independently and also runs a fresh bounded campaign.

```sh
python3 tools/verify_fuzz_archive.py tests/fixtures/http-fuzz/local-corpus.tar.gz tests/fixtures/http-fuzz/local-report.json --max-member-bytes 512
```

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

Set `POLICY_FUZZ_TARGET=frame` to fuzz the actual `read_frame_tracked` implementation through the development-only `fuzz_frame_stream` adapter. The example compiles the server module but never calls its main function or RPC dispatcher. An independent complete-buffer oracle splits at LF, compares exact bytes for frames of at most 64 KiB, requires oversized frames to be drained, and requires a nonempty unterminated final slice to fail with `UnexpectedEof`. The first byte also selects one of six reader capacities from 1 byte to 65,537 bytes, exercising fragmented buffering without a real input stream.

Frame campaigns use a 131,072-byte maximum and three fixed seeds: arbitrary multi-line bytes, exactly 65,536 bytes at EOF and an oversized line followed by a valid line. Other timing/process limits match the policy target. This is slower than URL mutation because small buffers intentionally exercise the whole large frame. The report's minimum 1,000 executions still applies. CI runs policy, frame, RPC and JSON targets as a matrix and signing requires all four. Evidence names are `llvm-policy-fuzz-evidence` and `llvm-frame-fuzz-evidence`.

This proves only the exercised in-memory framing/oracle checks. Input deadlines, blocking I/O, RPC validation/dispatch, admission queues, cancellation and output backpressure require separate tests. It does not fuzz HTTP framing. The feature-gated adapter is absent from normal server builds; no tool or wire capability is added.

The completed local frame corpus and tool/input identities are retained in `tests/fixtures/frame-fuzz/`. Its archive has only generated bytes under `corpus/`; it is test data, never input for an external request tool. CI-generated corpora remain separate retained artifacts.

## MCP dispatch and session target

Set `POLICY_FUZZ_TARGET=rpc` to drive the real `handle_cancellable` dispatcher through the development-only `fuzz_rpc_dispatch` entry point. Each input is parsed as JSON; an array represents at most sixteen sequential messages, starting with a fresh session, rather than an MCP batch. A separate valid modern `tools/call` envelope routes the mutated JSON into actual `guarded_fetch` argument validation. The allowlist is always empty, so accepted URL syntax still fails host authorization before system DNS or sockets. No production main loop, stdin/stdout stream or external target is used.

The oracle requires JSON-RPC2.0 response envelopes with exactly one result/error, typed error fields, preserved successful-response IDs, object results, a bounded serialized response and JSON round-trip equality. No fetch may return `ALLOWED`. These are basic structural and fail-closed invariants, not a complete independent MCP conformance implementation. Session transitions, malformed metadata, request IDs, argument shapes and catalog/resource response construction are reached through the real dispatcher. Audit state remains process-local and bounded by the normal retention cap.

RPC campaigns use an8192-byte input maximum and three fixed seeds: a modern tool catalog request, a legacy initialize/initialized/ping sequence and guarded-fetch arguments. The same compiler/instrumentation,60-second campaign,2-second per-input timeout and hard resource ceilings apply. The CI artifact is `llvm-rpc-fuzz-evidence`; it includes source hashes, tools, full evolved corpus, logs and the coverage/growth report. No local instrumented campaign was run for this addition because a shared Copperfin VM was active; CI is the campaign environment. Normal source tests/build remain separate verification.

This target does not establish HTTP parser behavior, DNS rebinding, admission/backpressure, cancellation races or deadlines, native client behavior, instruction sanitization or production readiness. Longer independent campaigns and review remain required. Normal builds exclude the feature-gated entry point; no tool or transport capability is added.

The first completed CI RPC campaign is preserved in `tests/fixtures/rpc-fuzz/ci-corpus.tar.gz` with source/tool identities, archive checksum and coverage totals in `ci-report.json`. It completed1271840 executions with6427 coverage counters and6770 new units. The archive contains generated test data under `corpus/`, never trusted instructions or URLs to fetch. Extract only into a new disposable directory for offline replay. CI continues to start from the three fixed seeds.

## JSON response scanner target

Set `POLICY_FUZZ_TARGET=json` to exercise the production JSON response scanner through a feature-gated development adapter. For every valid JSON input, an independent recursive walk of a canonical `serde_json::Value` checks whether an instruction-like key occurs at any depth. The scanner must agree for accepted inputs, and it must accept and agree on every canonicalized value. Malformed and duplicate-key seeds are included; fixed unit tests separately assert duplicate-key rejection. Six seeds cover nested mixed-case keys, Unicode-escaped keys, a duplicate-key shadow, ordinary data, invalid trailing text and the arbitrary-precision `serde_json::Value` private-number representation collision. The target makes no HTTP request or MCP client call, and the `serde_json::Value` oracle also rejects some otherwise valid objects whose first key collides with its private number representation. The scanner's acceptance of that fixed case is asserted in a unit test; inputs the Value oracle cannot parse receive no equivalence assertion.

The bounded campaign uses at most 262,144 input bytes and the same 60-second, two-second per-input, hard virtual-memory/descriptor/CPU limits as the other targets. The [local evidence](../tests/fixtures/json-fuzz/local-identity.json) records 1,958,555 executions, 1,823 coverage counters, 10,054 features and 4,496 new units with no crash/timeout artifact. Its [full report](../tests/fixtures/json-fuzz/local-report.json), [corpus archive](../tests/fixtures/json-fuzz/local-corpus.tar.gz) and compressed campaign log are retained; all 997 corpus hashes were checked against the archive. The campaign used Rust 1.99.1 and clang 18.1.8; CI uses the pinned project compiler and clang 18. This is finite syntax/key scanning evidence, not general prompt-injection quarantine, response transport, native-client or HTTP/DNS evidence.

## Extended manual CI campaigns

The separate **Extended offline fuzz** workflow accepts one target (`policy`, `frame`, `rpc` or `json`) and exactly60,300 or600seconds. It runs only when explicitly dispatched, with read-only repository permissions and one serialized job per ref. Routine release-gate CI retains its60-second default. Dispatch, for example:

```sh
gh workflow run extended-fuzz.yml --ref main -f target=rpc -f seconds=600
```

This uses the existing pinned compiler/actions, locked crates and distribution LLVM18 runtime. Wrapper validation rejects unsupported targets/durations before creating its output directory or compiling. Evidence records `target_seconds` and the same per-input/memory/descriptor ceilings; the hard CPU ceiling is the selected duration plus30seconds. Workflow timeout is25minutes including setup/build. Compilation and dependency download are outside the fuzz subprocess limits. A concurrency group prevents overlapping extended campaigns on the same ref; it does not reserve host resources or serialize unrelated CI workflows.

No local host or VM campaign is implied. Download the `extended-offline-fuzz-evidence` artifact within its seven-day retention window; preserve results, source/tool/runtime/input hashes, corpus identity and limitations in the release issue. Longer campaigns increase observations without establishing independent review, exhaustive coverage or production approval. These targets remain network-free with their original distinct scopes and no ASan/UBSan guarantee.

The [2026-10-28 extended frame campaign](../tests/fixtures/frame-fuzz/extended-ci-report.json) ran the real stdio framer against its LF-slice oracle for 300 seconds on trusted `main` source `fd0342484e99`. The completed CI run recorded 24,120 executions, 271 coverage counters, 1,588 features and 286 new units, with no crash/timeout artifact. All 57 evolved corpus files and nine source-input hashes were verified after download; the [compressed corpus](../tests/fixtures/frame-fuzz/extended-ci-corpus.tar.gz) is retained for offline replay. The fuzzer warned that optional sanitizer hooks were unavailable. This does not test MCP dispatch, timing, HTTP/DNS, native clients or aggregate resources, and it does not close independent review.

The [2026-10-29 extended JSON scanner campaign](../tests/fixtures/json-fuzz/extended-ci-identity.json) ran for 300 seconds on trusted `main` source `bb2a5573dee2`. It completed 6,086,140 executions, 1,894 coverage counters, 11,196 features and 7,405 new units with no crash/timeout artifact. All 1,154 evolved corpus files and ten input hashes were verified; the [compressed corpus](../tests/fixtures/json-fuzz/extended-ci-corpus.tar.gz), full report and compressed log are retained. The oracle skips equivalence assertions when `serde_json::Value` rejects an input, including its private-number key collision. This extends finite scanner evidence only; HTTP/DNS, native clients, general prompt-injection quarantine and independent duplicate-key parsing remain open.

## Extended local MCP dispatcher campaign (2026-11-06)

A 300-second LLVM 21 libFuzzer campaign ran the real `handle_cancellable` MCP dispatcher/session target from trusted source `acd02dd0fd95296ce6c8665de6ad517aea3d8059`. It completed 2,401,059 executions, reached 6,122 coverage counters and 26,738 features, and added 9,049 feedback-guided units. The process stayed below its configured RSS threshold (45 MiB peak reported); no crash or timeout artifact was produced. The [identity and limits](../tests/fixtures/rpc-fuzz/extended-local-identity.json), [full report](../tests/fixtures/rpc-fuzz/extended-local-report.json), [compressed campaign log](../tests/fixtures/rpc-fuzz/extended-local-campaign.log.gz), and [evolved corpus](../tests/fixtures/rpc-fuzz/extended-local-corpus.tar.gz) are retained. All 2,065 corpus files were checked against the report and archive digest; a tampered-report negative control failed.

To check the retained corpus without extracting it:

```sh
python3 tools/verify_fuzz_archive.py tests/fixtures/rpc-fuzz/extended-local-corpus.tar.gz tests/fixtures/rpc-fuzz/extended-local-report.json --max-member-bytes 8192
```

The target uses a stub resolver and empty allowlist. It exercises RPC parsing, session transitions and tool validation without real DNS, sockets, HTTP response parsing, queue/backpressure, cancellation timing or native clients. libFuzzer coverage feedback is not an independent protocol specification, and this campaign is not a general security proof or release approval. It says nothing about traffic sent through other tools or the four AI Scraping Defense repositories.

## Extended local URL and schema policy campaign (2026-11-06)

A 300-second LLVM 21 libFuzzer campaign ran the real `validate` URL/schema policy target from trusted source `e23dcc9435bf959ccd02829ddbdb8d82b61335c7`. It completed 2,196,838 executions, reached 4,847 coverage counters and 23,546 features, and added 8,521 feedback-guided units. The reported peak RSS was 38 MiB and no crash or timeout artifact was produced. The [identity and limits](../tests/fixtures/policy-fuzz/extended-local-identity.json), [full report](../tests/fixtures/policy-fuzz/extended-local-report.json), [compressed log](../tests/fixtures/policy-fuzz/extended-local-campaign.log.gz), and [2,323-file evolved corpus](../tests/fixtures/policy-fuzz/extended-local-corpus.tar.gz) are retained. Every corpus member was checked against the report.

```sh
python3 tools/verify_fuzz_archive.py tests/fixtures/policy-fuzz/extended-local-corpus.tar.gz tests/fixtures/policy-fuzz/extended-local-report.json --max-member-bytes 4096
```

This target uses a stub resolver returning an approved fixture address. It exercises URL parsing and schema invariants but does not perform real DNS, HTTP, MCP transport or native-client calls. Coverage feedback is not an independent specification, and the finite campaign is not a general SSRF proof or release approval. Results from the four AI Scraping Defense repositories must be gathered separately.
