// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package wheelegg

import (
	"net/textproto"
	"strings"

	"go.mondoo.com/mql/providers/os/resources/languages"
)

// Python distribution metadata states a license in three different places, and
// they do not agree about how precise they are.
//
// `License-Expression` (PEP 639, Metadata 2.4) is by definition a valid SPDX
// expression, so it is the answer whenever it is present. `License` is free
// text and holds anything from "MIT" to a pasted copy of the license itself.
// The `License ::` trove classifiers are a controlled vocabulary, which makes
// them more reliable than free text — but a coarse one: "BSD License" is a
// single classifier covering licenses whose obligations differ.
//
// Precedence follows that ordering, and each tier is consulted only when the
// one above it said nothing.
//
// Reading only the middle tier, which is what this package did before, is not a
// small gap. PEP 639 deprecates the `License` field in favour of
// `License-Expression` and forbids a distribution from carrying both, so a
// wheel built by a current toolchain states its license in a field that was
// never read — and reports no license at all, from a file already opened and
// parsed.

// licenseValueMaxBytes bounds a single license header's value.
//
// The `License` field was historically free text with no length limit, and
// distributions routinely paste an entire license *text* into it, continuation
// line by continuation line — one of the concrete problems PEP 639 exists to
// solve. That is a license text, not a license name: carried into
// Package.License it reaches every SBOM this produces as though it were an
// identifier, and no consumer can match it against one.
//
// Past this length the field is discarded rather than reported, which also lets
// the trove classifiers below it answer instead. Every identifier and
// expression that occurs in practice is far under this.
const licenseValueMaxBytes = 256

// metadataLicense picks the license out of a parsed METADATA/PKG-INFO header,
// in the precedence described above. It returns "" when nothing states a
// license — the honest answer, and distinct from a package whose license this
// could not render.
func metadataLicense(h textproto.MIMEHeader) string {
	if v := licenseValue(h.Get("License-Expression")); v != "" {
		return v
	}
	if v := licenseValue(h.Get("License")); v != "" {
		return v
	}
	return classifierExpression(h.Values("Classifier"))
}

// licenseValue trims a header value and drops it when it is too long to be a
// license name. See licenseValueMaxBytes.
func licenseValue(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > licenseValueMaxBytes {
		return ""
	}
	return v
}

// classifierExpression renders the license trove classifiers as one expression.
//
// A distribution listing several is offering a choice among them — that is what
// dual licensing looks like in this vocabulary — so they are OR-joined by the
// same rule the list-carrying ecosystems use, which keeps one joining
// convention in this package rather than two.
//
// Duplicates are dropped: a distribution that lists the same license under two
// classifier spellings has not offered a choice, and rendering "(MIT OR MIT)"
// would state one where there is none.
func classifierExpression(classifiers []string) string {
	var (
		seen  = map[string]bool{}
		parts []string
	)
	for _, c := range classifiers {
		name := classifierLicense(c)
		if name == "" {
			continue
		}
		key := strings.ToLower(name)
		if seen[key] {
			continue
		}
		seen[key] = true
		parts = append(parts, name)
	}
	return languages.LicenseExpression(parts)
}

// classifierLicense returns the license a single trove classifier names, or ""
// when it names none.
//
// A classifier is "::"-separated and increasingly specific, so the license is
// the last segment: "License :: OSI Approved :: MIT License" yields "MIT
// License". The value is passed through as the classifier spells it —
// normalizing a license name to a canonical identifier is a consumer's
// decision, not a parser's, the same rule LicenseExpression follows.
func classifierLicense(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "License ::") {
		return ""
	}
	tail := strings.TrimSpace(s[strings.LastIndex(s, "::")+2:])
	switch tail {
	case "", "OSI Approved", "DFSG approved", "Free For Educational Use",
		"Free For Home Use", "Free for non-commercial use", "Freely Distributable",
		"Free To Use But Restricted", "Freeware", "Other/Proprietary License",
		"Public Domain", "Repoze Public License":
		// Namespace labels, and buckets that name no specific license. "Public
		// Domain" is a category rather than an identifier — CC0 and Unlicense
		// are the identifiers, and a classifier saying "Public Domain" states
		// neither. Reporting one of these as the license would assert a
		// licensing fact the distribution did not state.
		return ""
	}
	return tail
}
