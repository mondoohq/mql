#!/bin/bash
# Copyright Mondoo, Inc. 2024, 2026
# SPDX-License-Identifier: BUSL-1.1
#
# modfetch.sh <module-path> <version>  ->  extracts the module and prints its directory
#
# The printed path is the extraction root, not the module root. The module unpacks
# under <printed>/<module-path>@<version>/, so a file at the top of the module, its
# CHANGELOG.md say, sits two levels below what this prints. structdiff.py and
# enumdrift.py walk down and are unaffected; a direct grep or sed needs the full
# nested path.
#
# Fetches the module zip straight from proxy.golang.org and unpacks it. Going to the
# proxy rather than through `go mod download` matters for two reasons: it needs no
# module context (so you can fetch a version the tree does not depend on, which is the
# whole point when diffing old against new), and it uses curl, which trusts the system
# keychain. The Go toolchain does not, so inside the sandbox it fails on the proxy's
# intercepted TLS with `x509: OSStatus -26276` while curl sails through.
#
# Extractions land outside the repo so they never show up in `git status`. Override
# with SDKDIFF_DIR if you want them somewhere specific.
#
#   ./modfetch.sh github.com/google/go-github/v90 v90.0.0
#   ./modfetch.sh github.com/cloudflare/cloudflare-go/v6 v6.10.0
#
# Re-fetching the same version is free: an existing extraction is reused.
set -euo pipefail

WORK="${SDKDIFF_DIR:-${TMPDIR:-/tmp}/mql-sdkdiff}"
path="$1"
ver="$2"

# proxy.golang.org requires capitals in module paths and versions to be escaped as
# `!lowercase`, so `github.com/Azure/...` is `github.com/!azure/...`. Emitting a bare
# `!` from bash risks history expansion, which is why this uses sed rather than an
# inline literal.
enc=$(printf '%s' "$path" | sed -E 's/([A-Z])/!\1/g' | tr 'A-Z' 'a-z')
encv=$(printf '%s' "$ver" | sed -E 's/([A-Z])/!\1/g' | tr 'A-Z' 'a-z')

slug=$(printf '%s@%s' "$path" "$ver" | tr '/@.' '___')
dest="$WORK/$slug"

if [ -d "$dest" ]; then
  echo "$dest"
  exit 0
fi

mkdir -p "$dest"
zip="$WORK/$slug.zip"
if ! curl -sfL "https://proxy.golang.org/$enc/@v/$encv.zip" -o "$zip"; then
  rmdir "$dest" 2>/dev/null || true
  echo "FETCH FAILED $path@$ver" >&2
  echo "  check the version exists: curl -s https://proxy.golang.org/$enc/@v/list" >&2
  exit 1
fi

unzip -qq -o "$zip" -d "$dest"
rm -f "$zip"
echo "$dest"
