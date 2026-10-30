// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package pubspeclock

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/sbom"
)

func TestPubspecLockExtractor(t *testing.T) {
	f, err := os.Open("./testdata/simple.pubspec.lock")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "path/to/pubspec.lock")
	require.NoError(t, err)

	assert.Nil(t, info.Root())

	// Direct = "direct main" only (excludes "direct dev" and transitive)
	direct := info.Direct()
	assert.Equal(t, 2, len(direct))

	p := direct.Find("http")
	require.NotNil(t, p)
	assert.Equal(t, "1.2.1", p.Version)
	assert.Equal(t, "pkg:pub/http@1.2.1", p.Purl)
	assert.Equal(t, []*sbom.Evidence{{Type: sbom.EvidenceType_EVIDENCE_TYPE_FILE, Value: "path/to/pubspec.lock"}}, p.EvidenceList)

	p = direct.Find("provider")
	require.NotNil(t, p)
	assert.Equal(t, "6.1.2", p.Version)

	// Dev deps should NOT be in direct
	assert.Nil(t, direct.Find("flutter_lints"))

	// Transitive = all packages
	transitive := info.Transitive()
	assert.Equal(t, 6, len(transitive))

	p = transitive.Find("meta")
	require.NotNil(t, p)
	assert.Equal(t, "1.15.0", p.Version)
	assert.Equal(t, "pkg:pub/meta@1.15.0", p.Purl)

	p = transitive.Find("http_parser")
	require.NotNil(t, p)
	assert.Equal(t, "4.0.2", p.Version)

	// Dev deps are in transitive
	assert.NotNil(t, transitive.Find("flutter_lints"))
	assert.NotNil(t, transitive.Find("flutter_test"))
}
