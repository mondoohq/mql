// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package installedjson

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInstalledJsonExtractor(t *testing.T) {
	f, err := os.Open("./testdata/simple.installed.json")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "vendor/composer/installed.json")
	require.NoError(t, err)

	assert.Nil(t, info.Root())
	assert.Nil(t, info.Direct())

	transitive := info.Transitive()
	assert.Equal(t, 3, len(transitive))

	p := transitive.Find("monolog/monolog")
	require.NotNil(t, p)
	assert.Equal(t, "3.5.0", p.Version)
	assert.Equal(t, "pkg:composer/monolog/monolog@3.5.0", p.Purl)

	p = transitive.Find("symfony/console")
	require.NotNil(t, p)
	assert.Equal(t, "v6.4.1", p.Version)
}

// TestInstalledJsonLicense pins that the license installed.json states reaches
// the package. Same defect as composer.lock: the parser read the field and the
// extractor dropped it.
func TestInstalledJsonLicense(t *testing.T) {
	f, err := os.Open("./testdata/simple.installed.json")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "path/to/installed.json")
	require.NoError(t, err)

	transitive := info.Transitive()
	for name, want := range map[string]string{
		"monolog/monolog": "MIT",
		"symfony/console": "MIT",
		"psr/log":         "MIT",
	} {
		p := transitive.Find(name)
		require.NotNil(t, p, name)
		assert.Equal(t, want, p.License, name)
	}
}
