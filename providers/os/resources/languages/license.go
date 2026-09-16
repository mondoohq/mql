// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package languages

import "strings"

// A license value arrives from a package index or a manifest inside an
// artifact, not from the scanned host, so its size is chosen by whoever
// published the package. It then flows into SBOM documents, SARIF and
// generated NOTICE files, none of which bound it either.
//
// Being well-formed supplies no bound of its own: `MIT OR MIT OR ...` is a
// valid SPDX expression at any length, and a `licenses` array may hold any
// number of members. So the bound has to come from what a license value *is*.
//
// Neither bound truncates. A truncated identifier is a *wrong* license — a
// consumer comparing against "Apache-2.0" would read "Apache-2" as a
// different license rather than as a cut-off one — and a wrong license is
// worse than none. The oversized value is dropped instead, which reports the
// license as undetermined: true, and distinct from a stated license.
const (
	// LicenseMaxBytes bounds a single license operand — one member of a
	// `licenses` array, or the whole value when only one was stated.
	//
	// License identifiers are short. The longest identifier in the SPDX list
	// is under 60 bytes and the longest full license *name* under about 120,
	// and the free-text names that appear instead ("The Apache License,
	// Version 2.0") are shorter still. Past 256 bytes the value is not a
	// license name: it is a pasted license *text*, a URL list, or padding.
	// This is the same bound wheelegg already applies to the same kind of
	// value in Python core metadata.
	LicenseMaxBytes = 256

	// LicenseExpressionMaxBytes bounds the rendered expression.
	//
	// A per-operand bound alone stops nothing: thousands of short, individually
	// valid identifiers still join into an unbounded expression. A joined
	// expression legitimately needs more room than a single name, so this is
	// larger — three full-length license names, or around sixty typical SPDX
	// identifiers. A package genuinely offering a choice states a handful;
	// past this the value is not a choice anyone could exercise, and the whole
	// expression is dropped rather than half of it kept, because a subset of
	// an OR is a different statement about what the package permits.
	LicenseExpressionMaxBytes = 1024
)

// LicenseExpression renders one or more license strings as a single SPDX
// expression for Package.License.
//
// Several ecosystems record a package's license as a LIST — composer.lock and
// installed.json use a JSON array, npm's lockfile accepts either a string or an
// array. In every one of them the list means a CHOICE: the package is offered
// under any of these, and the consumer picks. That is SPDX's OR, so the members
// are OR-joined and parenthesised, which keeps the result a valid expression
// when it is embedded in a larger one.
//
// A single license passes through untouched, which is the overwhelmingly common
// case and must not acquire parentheses it did not have. Empty entries are
// dropped rather than joined into a malformed expression, and a list that is
// empty or entirely blank yields "" — the honest answer when a manifest
// declared nothing, and distinct from a package that declared a license this
// function could not render.
//
// Oversized input is dropped, not truncated: a member longer than
// LicenseMaxBytes is not a license identifier and is skipped, keeping the
// members around it, and a result longer than LicenseExpressionMaxBytes is not
// a license statement at all, so "" is returned.
//
// The strings are passed through as the manifest wrote them. Normalizing a
// license name to a canonical identifier is a consumer's decision, not a
// parser's, and doing it here would discard what the file actually said.
func LicenseExpression(licenses []string) string {
	parts := make([]string, 0, len(licenses))
	// Running total of the operands alone. It is always at most the length of
	// the rendered expression, so bailing on it is safe, and it keeps an array
	// of a million members from being materialized into one string before the
	// exact check below rejects it.
	sum := 0
	for _, l := range licenses {
		if l = strings.TrimSpace(l); l == "" || len(l) > LicenseMaxBytes {
			continue
		}
		if sum += len(l); sum > LicenseExpressionMaxBytes {
			return ""
		}
		parts = append(parts, l)
	}
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	}
	// The separators count toward the bound too, so the rendered expression is
	// what gets measured.
	expr := "(" + strings.Join(parts, " OR ") + ")"
	if len(expr) > LicenseExpressionMaxBytes {
		return ""
	}
	return expr
}
