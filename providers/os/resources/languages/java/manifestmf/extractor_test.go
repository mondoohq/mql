// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package manifestmf

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/sbom"
)

func TestManifestExtractorSimple(t *testing.T) {
	f, err := os.Open("./testdata/simple.MANIFEST.MF")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "META-INF/MANIFEST.MF")
	require.NoError(t, err)

	root := info.Root()
	require.NotNil(t, root)
	assert.Equal(t, "commons-lang3", root.Name)
	assert.Equal(t, "3.12.0", root.Version)
	assert.Equal(t, "The Apache Software Foundation", root.Vendor)
	assert.Equal(t, []*sbom.Evidence{{Type: sbom.EvidenceType_EVIDENCE_TYPE_FILE, Value: "META-INF/MANIFEST.MF"}}, root.EvidenceList)

	assert.Nil(t, info.Direct())

	transitive := info.Transitive()
	assert.Equal(t, 1, len(transitive))
}

func TestManifestExtractorOSGi(t *testing.T) {
	f, err := os.Open("./testdata/osgi.MANIFEST.MF")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "META-INF/MANIFEST.MF")
	require.NoError(t, err)

	root := info.Root()
	require.NotNil(t, root)
	// Prefers Bundle-SymbolicName over Implementation-Title
	assert.Equal(t, "org.apache.commons.lang3", root.Name)
	assert.Equal(t, "3.12.0", root.Version)
	assert.Equal(t, "The Apache Software Foundation", root.Vendor)
}
