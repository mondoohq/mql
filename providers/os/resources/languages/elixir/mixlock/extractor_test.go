// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mixlock

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/sbom"
)

func TestMixLockExtractor(t *testing.T) {
	f, err := os.Open("./testdata/simple.mix.lock")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "path/to/mix.lock")
	require.NoError(t, err)

	assert.Nil(t, info.Root())
	assert.Nil(t, info.Direct())

	transitive := info.Transitive()
	assert.Equal(t, 5, len(transitive))

	p := transitive.Find("jason")
	require.NotNil(t, p)
	assert.Equal(t, "1.4.1", p.Version)
	assert.Equal(t, "pkg:hex/jason@1.4.1", p.Purl)
	assert.Equal(t, []*sbom.Evidence{{Type: sbom.EvidenceType_EVIDENCE_TYPE_FILE, Value: "path/to/mix.lock"}}, p.EvidenceList)

	p = transitive.Find("plug")
	require.NotNil(t, p)
	assert.Equal(t, "1.15.3", p.Version)

	p = transitive.Find("telemetry")
	require.NotNil(t, p)
	assert.Equal(t, "1.2.1", p.Version)
}
