// Copyright Mondoo, Inc. 2026
// SPDX-License-Identifier: BUSL-1.1

package sbom

import (
	_ "embed"
	"strings"
	"sync"
)

// spdxLicenseIDList holds the identifiers that CycloneDX accepts in license.id,
// one on each line. It is the enum of spdx.schema.json in the CycloneDX 1.7
// specification (SPDX license list 3.27.0). To update it, run:
//
//	curl -sL https://raw.githubusercontent.com/CycloneDX/specification/1.7/schema/spdx.schema.json | jq -r '.enum[]' > spdx_license_ids.txt
//
//go:embed spdx_license_ids.txt
var spdxLicenseIDList string

var spdxLicenseIDs = sync.OnceValue(func() map[string]struct{} {
	ids := map[string]struct{}{}
	for id := range strings.Lines(spdxLicenseIDList) {
		ids[strings.TrimSpace(id)] = struct{}{}
	}
	return ids
})

// isSPDXLicenseID reports whether s is an identifier that the CycloneDX schema
// accepts in license.id. The schema compares the value as written, so the
// comparison here is case-sensitive too.
func isSPDXLicenseID(s string) bool {
	_, ok := spdxLicenseIDs()[s]
	return ok
}
