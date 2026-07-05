#!/usr/bin/env bash
# Mandatory local verification gate: run before opening or *updating* any PR.
#
# Lanes, fail-fast in order: host fmt/clippy/tests (property tests at PROPTEST_CASES, default
# 1024), the Lean gate (formal specs build + kernel axiom audit, scripts/lean-gate.sh), the achim
# cross verify (build + test + fmt + clippy for aarch64-unknown-linux-musl; the ssh runner
# forwards no environment, so proptest runs its default 256 cases there), the achim wire lane
# (tcpdump capture + independent checker; needs passwordless sudo on achim, see
# scripts/wire-check.sh), and a time-boxed libFuzzer smoke per fuzz target on this host.
#
# One-time prerequisites:  rustup toolchain install nightly && cargo install cargo-fuzz
# (cargo +nightly overrides the rust-toolchain.toml pin for the fuzz lane only.)
# If AddressSanitizer misbehaves on this host, add --sanitizer none to the fuzz invocation.

set -euo pipefail

cd "$(dirname "$0")/.."

PROPTEST_CASES="${PROPTEST_CASES:-1024}"
FUZZ_SECONDS="${PRE_PR_FUZZ_SECONDS:-60}"
# Extend in lockstep with every new parsing surface (TLV parser, typed options, OCS, pipeline, FRAG).
FUZZ_TARGETS=(wire_datagram options_tlv options_serialize options_ocs options_typed socket_assemble process_datagram frag_split)

command -v cargo-fuzz >/dev/null || {
    echo "pre-pr: cargo-fuzz is missing — run: cargo install cargo-fuzz" >&2
    exit 1
}
rustup toolchain list | grep -q '^nightly' || {
    echo "pre-pr: no nightly toolchain — run: rustup toolchain install nightly" >&2
    exit 1
}

passed=()
lane() {
    local name="$1"
    shift
    echo "==> $name"
    "$@" || {
        echo "pre-pr: FAILED lane '$name' (green before it: ${passed[*]:-none})" >&2
        exit 1
    }
    passed+=("$name")
}

start=$SECONDS
lane "fmt" cargo fmt --check
lane "clippy host" cargo clippy --all-targets -- -D warnings
lane "test host ($PROPTEST_CASES proptest cases)" env PROPTEST_CASES="$PROPTEST_CASES" cargo test
lane "lean gate (build + axiom audit)" scripts/lean-gate.sh
lane "achim verify" scripts/vm-ubuntu-server.sh verify
lane "achim wire (tcpdump + tshark second oracle)" scripts/vm-ubuntu-server.sh wire
for target in "${FUZZ_TARGETS[@]}"; do
    mkdir -p "fuzz/corpus/$target" "fuzz/seeds/$target"
    max_len=2048
    if [ "$target" = "options_serialize" ]; then
        max_len=512
    elif [ "$target" = "options_typed" ]; then
        max_len=64
    elif [ "$target" = "socket_assemble" ]; then
        max_len=256
    elif [ "$target" = "frag_split" ]; then
        max_len=384
    fi
    lane "fuzz $target (${FUZZ_SECONDS}s)" cargo +nightly fuzz run "$target" \
        "fuzz/corpus/$target" "fuzz/seeds/$target" -- \
        -max_total_time="$FUZZ_SECONDS" -max_len="$max_len" -timeout=5 -rss_limit_mb=512
done

echo "pre-pr: all ${#passed[@]} lanes green in $((SECONDS - start))s"
