#!/usr/bin/env bash
# Make the repository root look like the Lean package to the RustRover lean4ij plugin.
#
# lean4ij assumes the opened IDE project root *is* the Lean package root: it looks for
# `<project>/lean-toolchain` and starts `lake serve` from there. This repo's Lean project lives
# under formal/lean-rfc9868/, so the plugin reports "Unable to locate lean toolchain". This script
# symlinks the Lean package markers into the repo root and excludes them locally via
# .git/info/exclude, so the tracked repo and the formal/ layout stay untouched.
#
#   scripts/lean-ide-setup.sh         # create symlinks + local git excludes (idempotent)
#   scripts/lean-ide-setup.sh down    # remove the symlinks and the local excludes
#
# After running, reload the project in RustRover (close + reopen, or File -> Reload).
# Set LEAN_IDE_SKIP_BUILD=1 to skip the initial `lake build`.
set -euo pipefail

cd "$(dirname "$0")/.."

LEAN_DIR="formal/lean-rfc9868"
# Symlinked into the repo root so lake sees the root as the package directory. `.lake/` is
# deliberately not linked -- lake builds a fresh, small one at the root (no external deps here).
LINKS=(lean-toolchain lakefile.toml lake-manifest.json Rfc9868.lean Rfc9868)
EXCLUDE_FILE=".git/info/exclude"
BEGIN_MARKER="# >>> lean4ij IDE setup (scripts/lean-ide-setup.sh) >>>"
END_MARKER="# <<< lean4ij IDE setup <<<"

remove_excludes() {
    [ -f "$EXCLUDE_FILE" ] || return 0
    grep -qF "$BEGIN_MARKER" "$EXCLUDE_FILE" || return 0
    local tmp
    tmp="$(mktemp)"
    awk -v b="$BEGIN_MARKER" -v e="$END_MARKER" '
        $0 == b { skip = 1; next }
        $0 == e { skip = 0; next }
        !skip   { print }
    ' "$EXCLUDE_FILE" >"$tmp"
    mv "$tmp" "$EXCLUDE_FILE"
}

if [ "${1:-up}" = "down" ]; then
    for name in "${LINKS[@]}"; do
        if [ -L "$name" ]; then
            rm "$name"
            echo "removed symlink: $name"
        fi
    done
    if [ -L ".lake" ]; then rm ".lake"; echo "removed symlink: .lake"; fi
    remove_excludes
    echo "teardown done. Reload the project in RustRover."
    exit 0
fi

[ -d "$LEAN_DIR" ] || { echo "error: $LEAN_DIR not found (run from the repo)" >&2; exit 1; }

# Populate formal/lean-rfc9868/.lake so the Lean server resolves imports immediately.
if [ "${LEAN_IDE_SKIP_BUILD:-0}" != "1" ]; then
    LAKE="${LAKE:-$HOME/.elan/bin/lake}"
    command -v "$LAKE" >/dev/null 2>&1 || LAKE=lake
    if command -v "$LAKE" >/dev/null 2>&1; then
        echo "building Lean package (set LEAN_IDE_SKIP_BUILD=1 to skip)..."
        (cd "$LEAN_DIR" && "$LAKE" build)
    else
        echo "warning: lake not found; skipping build" >&2
    fi
fi

# Create the symlinks. Refuse to clobber a real (non-symlink) file of the same name at the root.
for name in "${LINKS[@]}"; do
    if [ -e "$name" ] && [ ! -L "$name" ]; then
        echo "error: $name exists at the repo root and is not a symlink; aborting" >&2
        exit 1
    fi
    ln -sfn "$LEAN_DIR/$name" "$name"
    echo "linked: $name -> $LEAN_DIR/$name"
done

# Exclude the symlinks (and the root .lake lake will create) locally, without touching .gitignore.
mkdir -p "$(dirname "$EXCLUDE_FILE")"
if ! grep -qF "$BEGIN_MARKER" "$EXCLUDE_FILE" 2>/dev/null; then
    {
        echo "$BEGIN_MARKER"
        for name in "${LINKS[@]}"; do echo "/$name"; done
        echo "/.lake"
        echo "$END_MARKER"
    } >>"$EXCLUDE_FILE"
    echo "added local git excludes to $EXCLUDE_FILE"
fi

echo
echo "done. Now reload the project in RustRover (close + reopen)."
echo "verify: 'git status' stays clean and the lean4ij toolchain error is gone."
