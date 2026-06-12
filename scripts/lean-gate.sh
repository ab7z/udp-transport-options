#!/usr/bin/env bash
# Lean verification gate: build the formal specs and audit every theorem's axioms.
#
# "No cheating" is enforced at the kernel level, not by text matching: every theorem in the
# library must depend only on the three Lean foundation axioms (propext, Classical.choice,
# Quot.sound). A `sorry` shows up as `sorryAx`, a `native_decide` as `Lean.ofReduceBool` /
# `Lean.ofReduceNat`, and any hand-declared axiom under its own name -- all of which fail this
# gate. Comments mentioning these words do not.
set -euo pipefail

cd "$(dirname "$0")/../formal/lean-rfc9868"

LAKE="${LAKE:-$HOME/.elan/bin/lake}"
command -v "$LAKE" >/dev/null 2>&1 || LAKE=lake

echo "== lake build (toolchain: $(cat lean-toolchain)) =="
"$LAKE" build

echo "== axiom audit =="
audit_input=$(
    echo "import Rfc9868"
    grep -hoE '^theorem [A-Za-z0-9_]+' Rfc9868/*.lean | awk '{print "#print axioms Rfc9868." $2}'
)
n_theorems=$(($(printf '%s\n' "$audit_input" | wc -l) - 1))
audit_output=$(printf '%s\n' "$audit_input" | "$LAKE" env lean --stdin)
printf '%s\n' "$audit_output"

# Strip the allowed foundation axioms and the no-axiom lines; anything left is a violation.
violations=$(printf '%s\n' "$audit_output" \
    | grep "depends on axioms" \
    | sed -e 's/propext//g' -e 's/Classical\.choice//g' -e 's/Quot\.sound//g' \
    | grep -E "\[[^]]*[A-Za-z]" || true)
if [ -n "$violations" ]; then
    echo "FAIL: theorems depend on axioms beyond the Lean foundation:" >&2
    printf '%s\n' "$violations" >&2
    exit 1
fi

echo "OK: $n_theorems theorems, all proven from the Lean foundation axioms only."
