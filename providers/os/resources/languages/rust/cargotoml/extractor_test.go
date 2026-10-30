// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cargotoml

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/sbom"
)

func TestCargoTomlExtractor(t *testing.T) {
	f, err := os.Open("./testdata/simple.Cargo.toml")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "path/to/Cargo.toml")
	require.NoError(t, err)

	// Root project
	root := info.Root()
	require.NotNil(t, root)
	assert.Equal(t, "myproject", root.Name)
	assert.Equal(t, "0.1.0", root.Version)
	assert.Equal(t, "pkg:cargo/myproject@0.1.0", root.Purl)
	assert.Equal(t, []*sbom.Evidence{{Type: sbom.EvidenceType_EVIDENCE_TYPE_FILE, Value: "path/to/Cargo.toml"}}, root.EvidenceList)

	// Direct = [dependencies] + [build-dependencies] (excludes dev)
	direct := info.Direct()
	assert.Equal(t, 4, len(direct)) // serde, tokio, log + cc

	assert.NotNil(t, direct.Find("serde"))
	assert.Equal(t, "1.0", direct.Find("serde").Version)

	assert.NotNil(t, direct.Find("tokio"))
	assert.Equal(t, "1.32", direct.Find("tokio").Version)

	assert.NotNil(t, direct.Find("cc"))
	assert.Equal(t, "1.0", direct.Find("cc").Version)

	// Dev deps should NOT be in direct
	assert.Nil(t, direct.Find("criterion"))

	// Transitive = all declared deps (direct + dev + build)
	transitive := info.Transitive()
	assert.Equal(t, 6, len(transitive)) // serde, tokio, log, criterion, mockall, cc

	assert.NotNil(t, transitive.Find("criterion"))
	assert.Equal(t, "0.5", transitive.Find("criterion").Version)

	assert.NotNil(t, transitive.Find("mockall"))
	assert.Equal(t, "0.11", transitive.Find("mockall").Version)
}
