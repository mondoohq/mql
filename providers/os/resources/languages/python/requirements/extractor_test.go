// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package requirements

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractor(t *testing.T) {
	const reqs = `# a pip freeze style requirements.txt
blinker==1.9.0
Flask==3.1.3
requests==2.32.5
werkzeug[watchdog]==3.1.3
unpinned-package
ranged>=2.0
-e git+https://example.com/repo.git#egg=editable
--index-url https://pypi.org/simple
`

	bom, err := (&Extractor{}).Parse(strings.NewReader(reqs), "requirements.txt")
	require.NoError(t, err)

	pkgs := bom.Transitive()

	// Pinned packages are extracted with a purl and file evidence; unpinned and
	// ranged entries (no concrete version) and option/URL lines are skipped.
	flask := pkgs.Find("Flask")
	require.NotNil(t, flask)
	assert.Equal(t, "3.1.3", flask.Version)
	assert.Equal(t, "pkg:pypi/flask@3.1.3", flask.Purl)
	require.Len(t, flask.EvidenceList, 1)
	assert.Equal(t, "requirements.txt", flask.EvidenceList[0].Value)

	// extras don't break the name/version
	assert.NotNil(t, pkgs.Find("werkzeug"))

	assert.Nil(t, pkgs.Find("unpinned-package"), "unpinned entry skipped")
	assert.Nil(t, pkgs.Find("ranged"), "ranged (no pinned version) skipped")
	assert.Equal(t, 4, len(pkgs), "blinker, Flask, requests, werkzeug")
}
