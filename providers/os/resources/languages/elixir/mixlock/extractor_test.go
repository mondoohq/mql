// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mixlock

import (
	"os"
	"strings"
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

// mix.lock keeps each dependency on one line, which for a git dependency with
// a long ref list can pass 64 KiB. Fails if the scanner's buffer is not
// raised again.
func TestMixLockLongLine(t *testing.T) {
	lock := "%{\n  \"jason\": {:hex, :jason, \"1.4.0\", \"" + strings.Repeat("a", 70*1024) + "\", [:mix], [], \"hexpm\"},\n}\n"
	bom, err := (&Extractor{}).Parse(strings.NewReader(lock), "mix.lock")
	require.NoError(t, err)
	require.Len(t, bom.Transitive(), 1)
	assert.Equal(t, "1.4.0", bom.Transitive()[0].Version)
}

// A mix.lock cut off before its closing brace is truncated, not empty.
func TestMixLockTruncated(t *testing.T) {
	_, err := (&Extractor{}).Parse(strings.NewReader("%{\"jason\": {:hex, "), "mix.lock")
	assert.Error(t, err)
	bom, err := (&Extractor{}).Parse(strings.NewReader("%{}\n"), "mix.lock")
	require.NoError(t, err)
	assert.Empty(t, bom.Transitive())
}
