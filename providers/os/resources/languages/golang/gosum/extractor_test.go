// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package gosum

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/sbom"
)

func TestGoSumExtractor(t *testing.T) {
	f, err := os.Open("./testdata/simple.go.sum")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "path/to/go.sum")
	require.NoError(t, err)

	// go.sum has no root
	assert.Nil(t, info.Root())

	// go.sum cannot distinguish direct from indirect
	assert.Nil(t, info.Direct())

	transitive := info.Transitive()
	// 6 unique modules (go.mod hash lines are filtered out)
	assert.Equal(t, 6, len(transitive))

	p := transitive.Find("github.com/pkg/errors")
	require.NotNil(t, p)
	assert.Equal(t, "v0.9.1", p.Version)
	assert.Equal(t, "pkg:golang/github.com/pkg/errors@v0.9.1", p.Purl)
	assert.Equal(t, []*sbom.Evidence{{Type: sbom.EvidenceType_EVIDENCE_TYPE_FILE, Value: "path/to/go.sum"}}, p.EvidenceList)

	p = transitive.Find("golang.org/x/sys")
	require.NotNil(t, p)
	assert.Equal(t, "v0.12.0", p.Version)
	assert.Equal(t, "pkg:golang/golang.org/x/sys@v0.12.0", p.Purl)

	p = transitive.Find("github.com/rs/zerolog")
	require.NotNil(t, p)
	assert.Equal(t, "v1.31.0", p.Version)
}
