// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package rebarlock

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/sbom"
)

func TestRebarLockExtractor(t *testing.T) {
	f, err := os.Open("./testdata/simple.rebar.lock")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "path/to/rebar.lock")
	require.NoError(t, err)

	assert.Nil(t, info.Root())
	assert.Nil(t, info.Direct())

	transitive := info.Transitive()
	assert.Equal(t, 5, len(transitive))

	p := transitive.Find("cowboy")
	require.NotNil(t, p)
	assert.Equal(t, "2.10.0", p.Version)
	assert.Equal(t, "pkg:hex/cowboy@2.10.0", p.Purl)
	assert.Equal(t, []*sbom.Evidence{{Type: sbom.EvidenceType_EVIDENCE_TYPE_FILE, Value: "path/to/rebar.lock"}}, p.EvidenceList)

	p = transitive.Find("ranch")
	require.NotNil(t, p)
	assert.Equal(t, "2.1.0", p.Version)

	p = transitive.Find("hackney")
	require.NotNil(t, p)
	assert.Equal(t, "1.20.1", p.Version)
}

func TestRebarLockVersionedFormat(t *testing.T) {
	f, err := os.Open("./testdata/versioned.rebar.lock")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "rebar.lock")
	require.NoError(t, err)

	transitive := info.Transitive()
	assert.Equal(t, 2, len(transitive))

	p := transitive.Find("cowboy")
	require.NotNil(t, p)
	assert.Equal(t, "2.10.0", p.Version)

	p = transitive.Find("cowlib")
	require.NotNil(t, p)
	assert.Equal(t, "2.12.1", p.Version)
}
