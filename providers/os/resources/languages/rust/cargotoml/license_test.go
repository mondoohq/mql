// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cargotoml

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parseFixture(t *testing.T, name string) (*cargoToml, error) {
	t.Helper()
	f, err := os.Open("./testdata/" + name)
	require.NoError(t, err)
	defer f.Close()

	bom, err := (&Extractor{}).Parse(f, "Cargo.toml")
	if err != nil {
		return nil, err
	}
	return bom.(*cargoToml), nil
}

// Cargo's `license` is already an SPDX expression, so the crate's own license
// is carried through as written. Before this it was not read at all and every
// Rust project reported no license.
func TestCargoTomlReadsTheCrateLicense(t *testing.T) {
	ct, err := parseFixture(t, "licensed.Cargo.toml")
	require.NoError(t, err)

	root := ct.Root()
	require.NotNil(t, root)
	assert.Equal(t, "MIT OR Apache-2.0", root.License)
}

// license-file names a file, not a license. Reporting the path in a field
// consumers read as an SPDX expression would be a wrong answer where an empty
// one is the honest one.
func TestCargoTomlDoesNotReadLicenseFileAsALicense(t *testing.T) {
	ct, err := parseFixture(t, "license-file.Cargo.toml")
	require.NoError(t, err)

	root := ct.Root()
	require.NotNil(t, root)
	assert.Empty(t, root.License, "a path is not a license expression")
	assert.Equal(t, "custom-terms", root.Name, "the rest of the manifest must still parse")
}

// TestCargoTomlParsesAWorkspaceMember is the regression this file exists for.
//
// A workspace member writes `version.workspace = true` — a TABLE where the
// struct held a string — and decoding failed the whole FILE:
//
//	toml: (last key "package.version"): incompatible types: TOML value has type
//	map[string]any; destination has type string
//
// So Parse returned an error and the crate reported no root, no dependencies and
// no license: an empty inventory, not a missing version. Workspace inheritance
// has been the standard Cargo layout since 1.64 and no fixture used it.
func TestCargoTomlParsesAWorkspaceMember(t *testing.T) {
	ct, err := parseFixture(t, "workspace-member.Cargo.toml")
	require.NoError(t, err, "a workspace member must parse, not fail the file")

	root := ct.Root()
	require.NotNil(t, root, "the crate is still a package even when it inherits its version")
	assert.Equal(t, "member", root.Name)

	// Inherited values live in the workspace root manifest, which this parser
	// was not given. Empty is the honest answer; a guess would be worse.
	assert.Empty(t, root.Version, "an inherited version is unknown here, not invented")
	assert.Empty(t, root.License, "an inherited license is unknown here, not invented")

	// The point of not failing the file: the dependencies are still readable.
	direct := ct.Direct()
	require.Len(t, direct, 1)
	assert.Equal(t, "serde", direct[0].Name)
}
