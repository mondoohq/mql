// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cpe

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/facebookincubator/nvdtools/wfn"
)

// epochRegex matches a version that carries an epoch, e.g. `1:2.3.4`.
// Compiled once: this function runs two to three times per package, so
// compiling in the body cost a few kilobytes of garbage per package on every
// scan.
var epochRegex = regexp.MustCompile(`^\d+:(.*)$`)

// Field names for the WFNize error, positionally matched to the loop below.
var cpeFieldNames = [...]string{"vendor", "name", "version", "release", "arch"}

func NewPackage2Cpe(vendor, name, version, release, arch string) ([]string, error) {
	cpes := []string{}
	vendor = strings.ToLower(vendor)
	name = strings.ToLower(name)
	version = strings.ToLower(version)
	release = strings.ToLower(release)
	arch = strings.ToLower(arch)

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
