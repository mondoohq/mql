// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package yarnlock

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/javascript"
)

func TestYarnLockExtractor(t *testing.T) {
	f, err := os.Open("./testdata/d3-yarn.lock")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "/path/to/yarn.lock")
	assert.Nil(t, err)

	list := info.Transitive()
	assert.Equal(t, 99, len(list))

	evidence := javascript.NewEvidenceList([]string{"/path/to/yarn.lock"})

	p := list.Find("has")
	assert.Equal(t, &languages.Package{
		Name:         "has",
		Version:      "1.0.3",
		Purl:         "pkg:npm/has@1.0.3",
		Cpes:         []string{"cpe:2.3:a:has:has:1.0.3:*:*:*:*:*:*:*"},
		EvidenceList: evidence,
		DependsOn:    []string{"pkg:npm/function-bind@1.1.1"},
	}, p)

	p = list.Find("iconv-lite")
	assert.Equal(t, &languages.Package{
		Name:         "iconv-lite",
		Version:      "0.4.24",
		Purl:         "pkg:npm/iconv-lite@0.4.24",
		Cpes:         []string{"cpe:2.3:a:iconv-lite:iconv-lite:0.4.24:*:*:*:*:*:*:*"},
		EvidenceList: evidence,
		DependsOn:    []string{"pkg:npm/safer-buffer@2.1.2"},
	}, p)
}

func findVersion(list languages.Packages, name, version string) *languages.Package {
	for _, p := range list {
		if p.Name == name && p.Version == version {
			return p
		}
	}
	return nil
}

// Real `yarn install` output (yarn 1.22) for a project whose tree includes
// headers that quote only some of their specs, e.g.
// `"statuses@>= 1.5.0 < 2", statuses@~1.5.0:`. That line is not a YAML key and
// the whole lockfile failed to parse.
func TestYarnLockClassicMixedQuoteHeaders(t *testing.T) {
	f, err := os.Open("./testdata/classic-multispec-yarn.lock")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "/srv/app/yarn.lock")
	require.NoError(t, err)

	list := info.Transitive()
	assert.Len(t, list, 60)
	require.NotNil(t, findVersion(list, "lodash", "4.17.20"))
	require.NotNil(t, findVersion(list, "minimist", "0.0.8"))
	require.NotNil(t, findVersion(list, "minimist", "0.0.10"))

	statuses := findVersion(list, "statuses", "1.5.0")
	require.NotNil(t, statuses, "entry with a mixed quoted/unquoted header")
	// both specs of the header resolve, so edges to either spec are kept
	assert.Contains(t, findVersion(list, "http-errors", "1.7.2").DependsOn, "pkg:npm/statuses@1.5.0")
	assert.Contains(t, findVersion(list, "send", "0.17.1").DependsOn, "pkg:npm/statuses@1.5.0")
}

// Real `yarn install` output (yarn 4, nodeLinker node-modules). Berry lockfiles
// are YAML already; the classic `key value` rewrite turned
// `"@types/node": "npm:20.11.5"` into `"@types/node":: ...` and broke them.
func TestYarnLockBerry(t *testing.T) {
	f, err := os.Open("./testdata/berry-yarn.lock")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "/srv/app/yarn.lock")
	require.NoError(t, err)

	list := info.Transitive()
	assert.Len(t, list, 60, "every npm: entry, without __metadata and the workspace itself")
	assert.Nil(t, list.Find("nested-app"), "the project workspace is not an installed package")

	lodash := findVersion(list, "lodash", "4.17.20")
	require.NotNil(t, lodash)
	assert.Equal(t, "pkg:npm/lodash@4.17.20", lodash.Purl)
	require.NotNil(t, findVersion(list, "minimist", "0.0.8"))
	require.NotNil(t, findVersion(list, "@types/node", "20.11.5"))

	// berry dependency specs carry the npm: protocol, as do the entry keys
	assert.Equal(t, []string{"pkg:npm/minimist@0.0.8"}, findVersion(list, "mkdirp", "0.5.1").DependsOn)
}
