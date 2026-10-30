// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package composerlock

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/sbom"
)

func TestComposerLockExtractor(t *testing.T) {
	f, err := os.Open("./testdata/simple.composer.lock")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "path/to/composer.lock")
	require.NoError(t, err)

	assert.Nil(t, info.Root())

	// Direct = production packages only
	direct := info.Direct()
	assert.Equal(t, 3, len(direct))

	p := direct.Find("monolog/monolog")
	require.NotNil(t, p)
	assert.Equal(t, "3.5.0", p.Version)
	assert.Equal(t, "pkg:composer/monolog/monolog@3.5.0", p.Purl)
	assert.Equal(t, []*sbom.Evidence{{Type: sbom.EvidenceType_EVIDENCE_TYPE_FILE, Value: "path/to/composer.lock"}}, p.EvidenceList)

	p = direct.Find("symfony/console")
	require.NotNil(t, p)
	assert.Equal(t, "v6.4.1", p.Version)

	// Dev packages should NOT be in direct
	assert.Nil(t, direct.Find("phpunit/phpunit"))

	// Transitive = all packages, scoped: "packages" → prod, "packages-dev" → dev.
	transitive := info.Transitive()
	assert.Equal(t, 5, len(transitive))
	assert.Equal(t, languages.PackageScopeProd, transitive.Find("monolog/monolog").Scope)
	assert.Equal(t, languages.PackageScopeDev, transitive.Find("phpunit/phpunit").Scope)
	assert.Equal(t, languages.PackageScopeDev, transitive.Find("mockery/mockery").Scope)
}

// TestComposerLockExtractorLicense pins that the license composer.lock states
// reaches the package.
//
// The parser has always read the field; makePackage dropped it, so every PHP
// dependency reached an SBOM with an empty License and a policy evaluating them
// could only report "unknown". Consumers worked around it by re-reading the
// lockfile themselves.
func TestComposerLockExtractorLicense(t *testing.T) {
	f, err := os.Open("./testdata/simple.composer.lock")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "path/to/composer.lock")
	require.NoError(t, err)

	transitive := info.Transitive()
	for name, want := range map[string]string{
		"monolog/monolog": "MIT",
		"symfony/console": "MIT",
		"psr/log":         "MIT",
		"phpunit/phpunit": "BSD-3-Clause", // a dev package still states one
		"mockery/mockery": "BSD-3-Clause",
	} {
		p := transitive.Find(name)
		require.NotNil(t, p, name)
		assert.Equal(t, want, p.License, name)
	}
}
