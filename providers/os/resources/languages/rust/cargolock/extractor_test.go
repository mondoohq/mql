// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cargolock

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/sbom"
)

func TestCargoLockExtractor(t *testing.T) {
	f, err := os.Open("./testdata/simple.Cargo.lock")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "path/to/Cargo.lock")
	require.NoError(t, err)

	// Root is the project without a source
	root := info.Root()
	require.NotNil(t, root)
	assert.Equal(t, "myproject", root.Name)
	assert.Equal(t, "0.1.0", root.Version)
	assert.Equal(t, "pkg:cargo/myproject@0.1.0", root.Purl)
	assert.Equal(t, []*sbom.Evidence{{Type: sbom.EvidenceType_EVIDENCE_TYPE_FILE, Value: "path/to/Cargo.lock"}}, root.EvidenceList)

	// No direct/transitive distinction in Cargo.lock
	assert.Nil(t, info.Direct())

	// Transitive excludes the root
	transitive := info.Transitive()
	assert.Equal(t, 6, len(transitive))

	p := transitive.Find("serde")
	require.NotNil(t, p)
	assert.Equal(t, "1.0.188", p.Version)
	assert.Equal(t, "pkg:cargo/serde@1.0.188", p.Purl)
	// a version-less "serde_derive" edge resolves to the single locked version
	assert.Equal(t, []string{"pkg:cargo/serde_derive@1.0.188"}, p.DependsOn)

	// multi-edge crate resolves all edges (all sorted)
	p = transitive.Find("serde_derive")
	require.NotNil(t, p)
	assert.Equal(t, []string{
		"pkg:cargo/proc-macro2@1.0.66",
		"pkg:cargo/quote@1.0.33",
		"pkg:cargo/syn@2.0.29",
	}, p.DependsOn)

	p = transitive.Find("tokio")
	require.NotNil(t, p)
	assert.Equal(t, "1.32.0", p.Version)

	p = transitive.Find("proc-macro2")
	require.NotNil(t, p)
	assert.Equal(t, "1.0.66", p.Version)

	// Root should not be in transitive list
	assert.Nil(t, transitive.Find("myproject"))
}
