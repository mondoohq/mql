// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package manifestmf

// manifest represents the parsed contents of a META-INF/MANIFEST.MF file.
type manifest struct {
	// Headers maps header names to their values.
	Headers map[string]string

	// evidence is a list of file paths where the MANIFEST.MF was found.
	evidence []string `json:"-"`
}

// Common MANIFEST.MF header names.
const (
	headerImplementationTitle   = "Implementation-Title"
	headerImplementationVersion = "Implementation-Version"
	headerImplementationVendor  = "Implementation-Vendor"
	headerBundleSymbolicName    = "Bundle-SymbolicName"
	headerBundleVersion         = "Bundle-Version"
	headerBundleName            = "Bundle-Name"
	headerBundleVendor          = "Bundle-Vendor"
	headerBundleLicense         = "Bundle-License"
)
