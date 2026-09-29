// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package gomod

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/sbom"
)

func TestGoModExtractorSimple(t *testing.T) {
	f, err := os.Open("./testdata/simple.go.mod")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "path/to/go.mod")
	require.NoError(t, err)

	root := info.Root()
	assert.Equal(t, "github.com/example/myproject", root.Name)
	assert.Equal(t, "", root.Version)
	assert.Equal(t, "pkg:golang/github.com/example/myproject", root.Purl)
	assert.Equal(t, []*sbom.Evidence{{Type: sbom.EvidenceType_EVIDENCE_TYPE_FILE, Value: "path/to/go.mod"}}, root.EvidenceList)

	direct := info.Direct()
	assert.Equal(t, 3, len(direct))

	p := direct.Find("github.com/pkg/errors")
	require.NotNil(t, p)
	assert.Equal(t, &languages.Package{
		Name:         "github.com/pkg/errors",
		Version:      "v0.9.1",
		Purl:         "pkg:golang/github.com/pkg/errors@v0.9.1",
		Cpes:         p.Cpes, // CPE generation is tested separately
		EvidenceList: []*sbom.Evidence{{Type: sbom.EvidenceType_EVIDENCE_TYPE_FILE, Value: "path/to/go.mod"}},
	}, p)

	p = direct.Find("github.com/rs/zerolog")
	require.NotNil(t, p)
	assert.Equal(t, "v1.31.0", p.Version)
	assert.Equal(t, "pkg:golang/github.com/rs/zerolog@v1.31.0", p.Purl)

	// Transitive should include all 6 deps
	transitive := info.Transitive()
	assert.Equal(t, 6, len(transitive))

	// Indirect deps should be in transitive but not in direct
	p = transitive.Find("github.com/mattn/go-colorable")
	require.NotNil(t, p)
	assert.Equal(t, "v0.1.13", p.Version)

	p = transitive.Find("golang.org/x/sys")
	require.NotNil(t, p)
	assert.Equal(t, "v0.12.0", p.Version)
}

func TestGoModExtractorSingleRequire(t *testing.T) {
	f, err := os.Open("./testdata/single-require.go.mod")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "go.mod")
	require.NoError(t, err)

	root := info.Root()
	assert.Equal(t, "github.com/example/small", root.Name)

	direct := info.Direct()
	assert.Equal(t, 1, len(direct))
	assert.Equal(t, "github.com/pkg/errors", direct[0].Name)
	assert.Equal(t, "v0.9.1", direct[0].Version)

	transitive := info.Transitive()
	assert.Equal(t, 1, len(transitive))
}

func TestGoModExtractorWithReplace(t *testing.T) {
	f, err := os.Open("./testdata/with-replace.go.mod")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "go.mod")
	require.NoError(t, err)

	root := info.Root()
	assert.Equal(t, "github.com/example/replaced", root.Name)

	direct := info.Direct()
	assert.Equal(t, 2, len(direct))

	// foo/bar/v2 should have the replaced version v2.2.0
	p := direct.Find("github.com/foo/bar/v2")
	require.NotNil(t, p)
	assert.Equal(t, "v2.2.0", p.Version)

	transitive := info.Transitive()
	assert.Equal(t, 3, len(transitive))
}

// TestGoModExtractorWithLocalReplace: a LOCAL (filesystem) replacement — no
// version on the RHS, as a monorepo vendoring a module in-tree does — must keep
// the ORIGINAL module path as the package name/purl, not the directory path.
// Naming it `./staging/apimachinery` instead of `k8s.io/apimachinery` breaks
// advisory matching (mondoohq/xgrep#3173).
func TestGoModExtractorWithLocalReplace(t *testing.T) {
	f, err := os.Open("./testdata/with-local-replace.go.mod")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "go.mod")
	require.NoError(t, err)

	direct := info.Direct()

	// The locally-replaced module keeps its module-path identity...
	p := direct.Find("k8s.io/apimachinery")
	require.NotNil(t, p, "a local-replaced module must be named by its module path")
	assert.Equal(t, "v0.0.0", p.Version)
	assert.Equal(t, "pkg:golang/k8s.io/apimachinery@v0.0.0", p.Purl)

	// ...and the filesystem path is never used as a package name.
	assert.Nil(t, direct.Find("./staging/apimachinery"), "the replacement directory must not be a package name")
}
