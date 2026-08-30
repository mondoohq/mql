// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package languages

import "strings"

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
// The strings are passed through as the manifest wrote them. Normalizing a
// license name to a canonical identifier is a consumer's decision, not a
// parser's, and doing it here would discard what the file actually said.
func LicenseExpression(licenses []string) string {
	parts := make([]string, 0, len(licenses))
	for _, l := range licenses {
		if l = strings.TrimSpace(l); l != "" {
			parts = append(parts, l)
		}
	}
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	}
	return "(" + strings.Join(parts, " OR ") + ")"
}
