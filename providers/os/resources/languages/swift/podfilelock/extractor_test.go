// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package podfilelock

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/sbom"
)

func TestPodfileLockExtractor(t *testing.T) {
	f, err := os.Open("./testdata/simple.Podfile.lock")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "Podfile.lock")
	require.NoError(t, err)

	assert.Nil(t, info.Root())
	assert.Nil(t, info.Direct())

	transitive := info.Transitive()
	// Alamofire, SwiftyJSON, Moya, Moya/Core (4 top-level pods)
	assert.Equal(t, 4, len(transitive))

	p := transitive.Find("Alamofire")
	require.NotNil(t, p)
	assert.Equal(t, "5.8.1", p.Version)
	assert.Equal(t, "pkg:cocoapods/Alamofire@5.8.1", p.Purl)
	assert.Equal(t, []*sbom.Evidence{{Type: sbom.EvidenceType_EVIDENCE_TYPE_FILE, Value: "Podfile.lock"}}, p.EvidenceList)

	p = transitive.Find("Moya")
	require.NotNil(t, p)
	assert.Equal(t, "15.0.3", p.Version)

	p = transitive.Find("Moya/Core")
	require.NotNil(t, p)
	assert.Equal(t, "15.0.3", p.Version)

	p = transitive.Find("SwiftyJSON")
	require.NotNil(t, p)
	assert.Equal(t, "5.0.1", p.Version)
}

func TestParsePodEntryQuotedName(t *testing.T) {
	// CocoaPods quotes names with special characters; the quotes must be stripped.
	e := parsePodEntry(`"Artsy+UIColors (3.1.0)"`)
	assert.Equal(t, "Artsy+UIColors", e.Name)
	assert.Equal(t, "3.1.0", e.Version)

	// A quoted name with a trailing colon (has sub-dependencies).
	e = parsePodEntry(`"Artsy+UIFonts (3.1.3)":`)
	assert.Equal(t, "Artsy+UIFonts", e.Name)
	assert.Equal(t, "3.1.3", e.Version)

	// Unquoted names are unchanged.
	e = parsePodEntry("Alamofire (5.8.1)")
	assert.Equal(t, "Alamofire", e.Name)
	assert.Equal(t, "5.8.1", e.Version)
}
