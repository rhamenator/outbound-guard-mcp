#!/usr/bin/env bash
set -euo pipefail
# LLVM runtime supplied by the operator's development toolchain, never a crate.
: "${LIBFUZZER_RUNTIME:?Set LIBFUZZER_RUNTIME to libclang_rt.fuzzer_no_main-x86_64.a}"
: "${POLICY_FUZZ_OUTPUT:?Set POLICY_FUZZ_OUTPUT to a dedicated evidence directory}"
mkdir "$POLICY_FUZZ_OUTPUT"
mkdir "$POLICY_FUZZ_OUTPUT/corpus" "$POLICY_FUZZ_OUTPUT/artifacts"
rustc -vV > "$POLICY_FUZZ_OUTPUT/rustc.txt"
"${POLICY_FUZZ_CLANG:-clang}" --version > "$POLICY_FUZZ_OUTPUT/clang.txt"
sha256sum "$LIBFUZZER_RUNTIME" > "$POLICY_FUZZ_OUTPUT/runtime.sha256"
sha256sum Cargo.toml Cargo.lock src/*.rs examples/policy_fuzz.rs tools/policy_fuzz.sh > "$POLICY_FUZZ_OUTPUT/inputs.sha256"
export CARGO_TARGET_DIR="$PWD/target/policy-fuzz"
export CARGO_BUILD_JOBS=2
export RUSTFLAGS="-C passes=sancov-module -C llvm-args=-sanitizer-coverage-level=3 -C llvm-args=-sanitizer-coverage-inline-8bit-counters -C llvm-args=-sanitizer-coverage-pc-table -C llvm-args=-sanitizer-coverage-trace-compares -C link-arg=$LIBFUZZER_RUNTIME -C link-arg=-lstdc++"
nice -n10 cargo build --locked --offline --example policy_fuzz --features policy-fuzz
printf '%s' 'http://allowed.test/plain' > "$POLICY_FUZZ_OUTPUT/corpus/url"
printf '%s' '{"url":"https://allowed.test/plain","method":"HEAD"}' > "$POLICY_FUZZ_OUTPUT/corpus/json"
printf '%s' 'http://127.0.0.1/' > "$POLICY_FUZZ_OUTPUT/corpus/loopback"
(
ulimit -v 1048576
ulimit -n 64
ulimit -t 90
nice -n10 "$CARGO_TARGET_DIR/debug/examples/policy_fuzz" \
    "$POLICY_FUZZ_OUTPUT/corpus" -seed=306373022 -max_total_time=60 \
    -timeout=2 -rss_limit_mb=512 -max_len=4096 \
    "-artifact_prefix=$POLICY_FUZZ_OUTPUT/artifacts/" -print_final_stats=1 \
    > "$POLICY_FUZZ_OUTPUT/campaign.log" 2>&1
)
python3 tools/policy_fuzz_report.py "$POLICY_FUZZ_OUTPUT"
