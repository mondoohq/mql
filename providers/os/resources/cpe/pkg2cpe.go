// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cpe

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/facebookincubator/nvdtools/wfn"
	"golang.org/x/text/unicode/norm"
)

// epochRegex matches a version that carries an epoch, e.g. `1:2.3.4`.
// Compiled once: this function runs two to three times per package, so
// compiling in the body cost a few kilobytes of garbage per package on every
// scan.
var epochRegex = regexp.MustCompile(`^\d+:(.*)$`)

// Field names for the WFNize error, positionally matched to the loop below.
var cpeFieldNames = [...]string{"vendor", "name", "version", "release", "arch"}

// asciiLetters spells the letters that have no decomposition into an ASCII
// base letter and a mark.
var asciiLetters = map[rune]string{
	'ß': "ss", 'ẞ': "ss", 'æ': "ae", 'Æ': "ae", 'œ': "oe", 'Œ': "oe",
	'ø': "o", 'Ø': "o", 'ł': "l", 'Ł': "l", 'đ': "d", 'Đ': "d",
	'ð': "d", 'Ð': "d", 'þ': "th", 'Þ': "th", 'ı': "i",
}

// toASCII transliterates s to ASCII: `Vendör` becomes `Vendor`, `Straße`
// `Strasse`. WFNize keeps only the low byte of a non-ASCII rune, so `ö`
// (U+00F6) was dropped and `ł` (U+0142) became `B`. A rune with no ASCII
// spelling (`日本語`) is dropped.
func toASCII(s string) string {
	ascii := true
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			ascii = false
			break
		}
	}
	if ascii {
		return s
	}

	var b strings.Builder
	for _, r := range norm.NFD.String(s) {
		switch {
		case r < utf8.RuneSelf:
			b.WriteRune(r)
		case unicode.Is(unicode.Mn, r):
			// the accent of a decomposed letter
		default:
			b.WriteString(asciiLetters[r])
		}
	}
	return b.String()
}

func NewPackage2Cpe(vendor, name, version, release, arch string) ([]string, error) {
	cpes := []string{}
	vendor = strings.ToLower(toASCII(vendor))
	name = strings.ToLower(toASCII(name))
	version = strings.ToLower(toASCII(version))
	release = strings.ToLower(toASCII(release))
	arch = strings.ToLower(toASCII(arch))

	// Remove epoch when present; otherwise WFNize will only use the epoch as
	// the version.
	if matches := epochRegex.FindStringSubmatch(version); len(matches) > 1 {
		version = matches[1]
	}

	for i, addr := range [...]*string{&vendor, &name, &version, &release, &arch} {
		// WFNize returns an empty string alongside its error, so the result is
		// only assigned once it succeeded. Assigning first would leave the
		// error message reporting "" instead of the value that failed.
		wfnized, err := wfn.WFNize(*addr)
		if err != nil {
			return cpes, fmt.Errorf("couldn't wfnize %s %q: %v", cpeFieldNames[i], *addr, err)
		}
		*addr = wfnized
	}

	// A CPE needs both a product name and a version. When either is missing we
	// simply cannot build one — that is not an error worth surfacing, since CPEs
	// are optional vulnerability-matching enrichment. Return no CPEs and no error
	// so callers don't log spurious warnings for nameless/versionless packages
	// (common in JS lockfiles).
	if name == "" || version == "" {
		return cpes, nil
	}

	attr := wfn.Attributes{}
	attr.Part = "a"
	attr.Vendor = vendor
	attr.Product = name
	attr.Version = version
	attr.Update = release
	attr.TargetHW = arch

	cpes = append(cpes, attr.BindToFmtString())
	return cpes, nil
}
