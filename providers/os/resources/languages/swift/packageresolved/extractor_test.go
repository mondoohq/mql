// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packageresolved

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/sbom"
)

func TestPackageResolvedV2(t *testing.T) {
	f, err := os.Open("./testdata/v2.Package.resolved")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "Package.resolved")
	require.NoError(t, err)

	assert.Nil(t, info.Root())
	assert.Nil(t, info.Direct())

	transitive := info.Transitive()
	assert.Equal(t, 3, len(transitive))

	p := transitive.Find("alamofire")
	require.NotNil(t, p)
	assert.Equal(t, "5.8.1", p.Version)
	assert.Equal(t, "pkg:swift/alamofire@5.8.1", p.Purl)
	assert.Equal(t, []*sbom.Evidence{{Type: sbom.EvidenceType_EVIDENCE_TYPE_FILE, Value: "Package.resolved"}}, p.EvidenceList)

	p = transitive.Find("swift-argument-parser")
	require.NotNil(t, p)
	assert.Equal(t, "1.2.3", p.Version)
}

func TestPackageResolvedV1(t *testing.T) {
	f, err := os.Open("./testdata/v1.Package.resolved")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "Package.resolved")
	require.NoError(t, err)

	transitive := info.Transitive()
	assert.Equal(t, 2, len(transitive))

	p := transitive.Find("Alamofire")
	require.NotNil(t, p)
	assert.Equal(t, "5.8.1", p.Version)

	p = transitive.Find("Kingfisher")
	require.NotNil(t, p)
	assert.Equal(t, "7.10.1", p.Version)
}
