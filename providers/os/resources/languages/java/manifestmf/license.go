// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package manifestmf

import (
	"regexp"
	"strings"

	"go.mondoo.com/mql/providers/os/resources/languages"
)

// OSGi states a bundle's license in Bundle-License, and the header is
// structured rather than a plain name (OSGi Core, Module Layer):
//
//	Bundle-License ::= '<<EXTERNAL>>' | ( license ( ',' license ) * )
//	license        ::= license-identifier ( ';' license-attr ) *
//	license-attr   ::= description | link
//	description    ::= 'description' '=' string
//	link           ::= 'link' '=' <url>
//
// so a real header looks like any of:
//
//	Bundle-License: Apache-2.0;link="https://www.apache.org/licenses/LICENSE-2.0"
//	Bundle-License: The Apache License, Version 2.0;link="http://www.apache.org/..."
//	Bundle-License: https://www.eclipse.org/legal/epl-2.0/
//	Bundle-License: <<EXTERNAL>>
//
// Only the license-identifier is carried into the inventory. The attributes are
// dropped: `link` points at the license text and `description` is prose — the
// bnd documentation's own example is a full sentence — and neither is the
// identity of the license.

// bundleLicenseExternal is the magic identifier meaning "this artifact states
// no license here; it is provided some other way". It is a statement that the
// header is empty, so it is treated as one.
const bundleLicenseExternal = "<<EXTERNAL>>"

// urlPattern matches a value that is a URL rather than a license name.
//
// Both spellings that occur in the header, because a scheme is not what makes
// the value a link: `https://www.eclipse.org/legal/epl-2.0/` and
// `www.apache.org/licenses/LICENSE-2.0` are the same statement, and reporting
// the second as a license identifier is the outcome dropping the first exists
// to avoid. The schemeless form requires a dotted host followed by a path, so
// it cannot match a license name: those carry no dot-then-slash, and anything
// with a space has already been ruled out by the host pattern.
var urlPattern = regexp.MustCompile(`^([a-zA-Z][a-zA-Z0-9+.\-]*://|[a-zA-Z0-9\-]+(\.[a-zA-Z0-9\-]+)+/)`)

// license returns the license the manifest declares, or "" when it declares
// none this can name.
//
// The value is returned as the manifest wrote it. Normalizing a name to a
// canonical SPDX identifier is a consumer's decision, not a parser's.
func (m *manifest) license() string {
	return ParseBundleLicense(m.Headers[headerBundleLicense])
}

// ParseBundleLicense returns the license an OSGi Bundle-License header states,
// or "" when it states none this can name.
//
// Exported because a MANIFEST.MF is read by more than the inventory path. A
// scanner that has already opened a jar's manifest for its own reasons needs
// the same answer this gives, and the alternative — a second reader of the
// same header somewhere else — is a reader that will not know about the
// external marker, or schemeless URLs, or a comma inside a quoted attribute,
// and will report a different license for the same jar than mql does.
//
// The header value is the whole input, so nothing else about the manifest has
// to be shared. Unfolding continuation lines and looking the header up
// case-insensitively stay with the caller's manifest reader; this names only
// the value.
func ParseBundleLicense(header string) string {
	raw := strings.TrimSpace(header)
	if raw == "" {
		return ""
	}

	names := make([]string, 0, 1)
	// Running total of the identifiers kept, so a manifest carrying a header of
	// arbitrary size is never joined into one string before it is rejected.
	sum := 0
	for _, entry := range splitOutsideQuotes(raw, ',') {
		name := licenseIdentifier(entry)
		// A URL is a link to the terms, not the identity of the terms.
		// Reporting one in a field consumers compare against "Apache-2.0" or
		// "MIT" matches nothing while reading as a stated identifier, which is
		// worse than the honest blank they get today. The header is
		// URL-only on most real bundles, so most of them keep reporting
		// nothing — this only adds the ones that name a license.
		if name == "" || name == bundleLicenseExternal || urlPattern.MatchString(name) {
			continue
		}
		// A manifest comes out of an artifact someone else built, and nothing
		// in the OSGi grammar bounds an identifier. Past languages.LicenseMaxBytes
		// the entry is not a license name, so it is dropped — the entries beside
		// it are still reported, and truncating it would state a different
		// license rather than a shortened one.
		if len(name) > languages.LicenseMaxBytes {
			continue
		}
		if sum += len(name); sum > languages.LicenseExpressionMaxBytes {
			return ""
		}
		names = append(names, name)
	}

	// The grammar makes ',' a separator between licenses, but real manifests
	// also write an identifier that contains one: "The Apache License, Version
	// 2.0;link=..." is a single license, and it is what Eclipse/Tycho bundles
	// emit. The two shapes are told apart by what the pieces look like. A
	// header whose every piece is identifier-shaped is a genuine list, and
	// OR-joining it says what OSGi means by a list: the bundle is offered under
	// any of them. A header with a piece that is not, like "Version 2.0", is
	// one name that happens to contain a comma, and its pieces are rejoined.
	//
	// The conservative direction is deliberate. Rejoining a genuine list
	// reproduces what the manifest said and loses only the OR; OR-joining a
	// split name would report a bundle as dual-licensed under "The Apache
	// License" or "Version 2.0", a choice it never offered. So anything not
	// clearly a list is rejoined, which also leaves an operand like
	// "GPL-2.0-only WITH Classpath-exception-2.0" alone rather than guessing.
	if len(names) > 1 && allIdentifierShaped(names) {
		// LicenseExpression applies the shared bounds and the parenthesisation
		// that keeps the result valid inside a larger expression.
		return languages.LicenseExpression(names)
	}

	// The rejoined value carries the same total bound as an OR-joined one: past
	// it the header is not a license statement, and the whole value is dropped
	// rather than part of it kept, which would report a bundle as licensed
	// under some of the terms it named.
	joined := strings.Join(names, ", ")
	if len(joined) > languages.LicenseExpressionMaxBytes {
		return ""
	}
	return joined
}

// allIdentifierShaped reports whether every value could be a bare license
// identifier: one token of the characters identifiers actually use.
//
// It deliberately does not check against the SPDX list. This package reports
// what a manifest stated rather than what it recognises, and an unlisted
// identifier is still an identifier; the question here is only whether the
// comma separated two names or split one.
func allIdentifierShaped(names []string) bool {
	for _, n := range names {
		if !identifierShaped(n) {
			return false
		}
	}
	return true
}

func identifierShaped(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-' || r == '.' || r == '+' || r == '_':
		default:
			return false
		}
	}
	return true
}

// licenseIdentifier returns the license-identifier of one entry: everything
// before its first attribute, unquoted and trimmed.
func licenseIdentifier(entry string) string {
	parts := splitOutsideQuotes(entry, ';')
	if len(parts) == 0 {
		return ""
	}
	return unquote(strings.TrimSpace(parts[0]))
}

// splitOutsideQuotes splits on sep, ignoring separators inside a quoted string.
// Attribute values are quoted and do carry both separators —
// `description="Apache License, Version 2.0"` holds a comma, and a `link` URL
// can hold anything.
func splitOutsideQuotes(s string, sep byte) []string {
	var (
		parts []string
		start int
		quote byte
	)
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == sep:
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return append(parts, s[start:])
}

// unquote strips one layer of matching surrounding quotes.
func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return strings.TrimSpace(s[1 : len(s)-1])
	}
	return s
}
