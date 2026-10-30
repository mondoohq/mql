// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package stacklock

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/sbom"
)

func TestStackLockExtractor(t *testing.T) {
	f, err := os.Open("./testdata/simple.stack.yaml.lock")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "path/to/stack.yaml.lock")
	require.NoError(t, err)

	assert.Nil(t, info.Root())
	assert.Nil(t, info.Direct())

	transitive := info.Transitive()
	assert.Equal(t, 3, len(transitive))

	p := transitive.Find("aeson")
	require.NotNil(t, p)
	assert.Equal(t, "2.2.1.0", p.Version)
	assert.Equal(t, "pkg:hackage/aeson@2.2.1.0", p.Purl)
	assert.Equal(t, []*sbom.Evidence{{Type: sbom.EvidenceType_EVIDENCE_TYPE_FILE, Value: "path/to/stack.yaml.lock"}}, p.EvidenceList)

	p = transitive.Find("text")
	require.NotNil(t, p)
	assert.Equal(t, "2.1.1", p.Version)

	p = transitive.Find("bytestring")
	require.NotNil(t, p)
	assert.Equal(t, "0.12.1.0", p.Version)
}
