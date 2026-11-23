// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/google/go-github/v93/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func decodeAdvisory(t *testing.T, body string) *github.SecurityAdvisory {
	t.Helper()
	var a github.SecurityAdvisory
	require.NoError(t, json.Unmarshal([]byte(body), &a))
	return &a
}

// Synthetic: advisory shapes from GitHub's documented response; no target
// showed these.
func TestAdvisoryCWEIDs(t *testing.T) {
	a := decodeAdvisory(t, `{"cwes": [{"cwe_id": "CWE-79", "name": "XSS"}, {"name": "no id"}], "cwe_ids": ["CWE-1"]}`)
	assert.Equal(t, []any{"CWE-79"}, advisoryCWEIDs(a), "the cwes objects win over the flat list")

	a = decodeAdvisory(t, `{"cwe_ids": ["CWE-22", "CWE-23"]}`)
	assert.Equal(t, []any{"CWE-22", "CWE-23"}, advisoryCWEIDs(a))

	assert.Empty(t, advisoryCWEIDs(decodeAdvisory(t, `{}`)))
}

// Synthetic: scored and unscored advisories; no target showed these.
func TestAdvisoryCVSS(t *testing.T) {
	score, vector := advisoryCVSS(decodeAdvisory(t, `{"cvss": {"score": 9.8, "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}`))
	assert.Equal(t, 9.8, score.Value)
	assert.Equal(t, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", vector.Value)

	score, vector = advisoryCVSS(decodeAdvisory(t, `{"cvss": {"score": null, "vector_string": null}}`))
	assert.Equal(t, llx.NilData, score, "an unscored advisory has a null score, not 0")
	assert.Equal(t, llx.NilData, vector)

	score, _ = advisoryCVSS(decodeAdvisory(t, `{}`))
	assert.Equal(t, llx.NilData, score)
}
