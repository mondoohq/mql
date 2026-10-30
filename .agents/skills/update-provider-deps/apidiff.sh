#!/bin/bash
# Copyright Mondoo, Inc. 2024, 2026
# SPDX-License-Identifier: BUSL-1.1
#
# apidiff.sh <old-path> <old-ver> <new-path> <new-ver>
#
# Prints the exported symbols (types, funcs, methods) an SDK gained and lost between
# two versions. This is the check that catches what release notes leave out: generated
# SDKs describe their releases in terms of the generator, so "updated to spec 2025.08"
# routinely hides a dozen deleted API groups.
#
# The REMOVED list is the actionable half. Intersect it with what the provider calls:
#
#   ./apidiff.sh github.com/okta/okta-sdk-golang/v5 v5.0.6 \
#                github.com/okta/okta-sdk-golang/v6 v6.1.7 > /tmp/okta-diff.txt
#   sed -n '/### REMOVED/,/### ADDED/p' /tmp/okta-diff.txt \
#     | sed -E 's/^(METHOD|FUNC|TYPE) //' | sed 's/.*\.//' | sort -u > /tmp/removed.txt
#   grep -rhoE '\b[A-Z][A-Za-z0-9_]+\b' providers/okta --include='*.go' | sort -u > /tmp/used.txt
#   comm -12 /tmp/removed.txt /tmp/used.txt
#
# Anything that survives that intersection is a call site the compiler will reject, or
# worse, a name that still exists with different behavior.
#
# Caveat worth knowing: this greps declarations rather than type-checking, so a symbol
# that moved between packages inside the same module shows as removed-and-added. Read
# the pair together before concluding something is gone.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${SDKDIFF_DIR:-${TMPDIR:-/tmp}/mql-sdkdiff}"
mkdir -p "$WORK"

old=$("$HERE/modfetch.sh" "$1" "$2")
new=$("$HERE/modfetch.sh" "$3" "$4")

syms() {
  find "$1" -name '*.go' ! -name '*_test.go' -print0 \
  | xargs -0 grep -hE '^(func|type) ' 2>/dev/null \
  | sed -E 's/[[:space:]]+/ /g' \
  | sed -E 's/^func \(([a-zA-Z_0-9]+ )?\*?([A-Za-z0-9_]+)\) ([A-Z][A-Za-z0-9_]*).*/METHOD \2.\3/' \
  | sed -E 's/^func ([A-Z][A-Za-z0-9_]*).*/FUNC \1/' \
  | sed -E 's/^type ([A-Z][A-Za-z0-9_]*).*/TYPE \1/' \
  | grep -E '^(METHOD|FUNC|TYPE) ' \
  | grep -vE '^(METHOD|TYPE) Mock' \
  | sort -u
}

syms "$old" > "$WORK/.apidiff.old"
syms "$new" > "$WORK/.apidiff.new"

echo "### REMOVED (potentially breaking)"
comm -23 "$WORK/.apidiff.old" "$WORK/.apidiff.new"
echo
echo "### ADDED"
comm -13 "$WORK/.apidiff.old" "$WORK/.apidiff.new"
