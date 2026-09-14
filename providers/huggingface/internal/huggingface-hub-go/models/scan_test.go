// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package models

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// eicarScanBody is the live response of
// GET https://huggingface.co/api/models/mcpotato/42-eicar-street/scan,
// a public repository the Hub publishes as a scanner test case.
const eicarScanBody = `{"scansDone":true,"filesWithIssues":[` +
	`{"path":"model_broken_X.pkl","level":"unsafe"},` +
	`{"path":"danger.dat","level":"unsafe"},` +
	`{"path":"build_pickles.py","level":"caution"},` +
	`{"path":"eicar_test_file","level":"unsafe"}]}`

// A flagged file must decode with both its path and its severity. A mistyped
// struct tag on either one yields an empty string, which would report an
// unsafe pickle as a finding with no level and no location.
func TestRepoScanDecodeFlaggedFiles(t *testing.T) {
	var scan RepoScan
	require.NoError(t, json.Unmarshal([]byte(eicarScanBody), &scan))

	assert.True(t, scan.ScansDone)
	require.Len(t, scan.FilesWithIssues, 4)

	assert.Equal(t, "model_broken_X.pkl", scan.FilesWithIssues[0].Path)
	assert.Equal(t, "unsafe", scan.FilesWithIssues[0].Level)
	assert.Equal(t, "build_pickles.py", scan.FilesWithIssues[2].Path)
	assert.Equal(t, "caution", scan.FilesWithIssues[2].Level)

	unsafe := 0
	for _, f := range scan.FilesWithIssues {
		if f.Level == "unsafe" {
			unsafe++
		}
	}
	assert.Equal(t, 3, unsafe)
}

// An outstanding scan reports scansDone false with an empty file list, which is
// the same file list a clean repository reports. Only scansDone separates them,
// so it has to survive decoding in both directions: a mistyped tag would pin it
// to false and make every scanned repository look unfinished, while a default
// of true would make an unscanned repository look clean.
func TestRepoScanScansDoneBothDirections(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		scansDone bool
		files     int
	}{
		{
			// Live: a model created minutes earlier, scan still queued.
			name:      "queued scan reports no issues yet",
			body:      `{"scansDone":false,"filesWithIssues":[]}`,
			scansDone: false,
			files:     0,
		},
		{
			// Live: openai-community/gpt2, fully scanned and clean.
			name:      "finished scan on a clean repository",
			body:      `{"scansDone":true,"filesWithIssues":[]}`,
			scansDone: true,
			files:     0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var scan RepoScan
			require.NoError(t, json.Unmarshal([]byte(tt.body), &scan))
			assert.Equal(t, tt.scansDone, scan.ScansDone)
			assert.Len(t, scan.FilesWithIssues, tt.files)
		})
	}
}

// The three repository kinds have to keep their distinct API path segments; a
// dataset scanned under the models segment reads back as "not found", which the
// resource layer turns into a null verdict.
func TestRepoTypeSegments(t *testing.T) {
	assert.Equal(t, "models", string(RepoTypeModel))
	assert.Equal(t, "datasets", string(RepoTypeDataset))
	assert.Equal(t, "spaces", string(RepoTypeSpace))
}
