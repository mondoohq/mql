// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseJsonParamsRepairsMalformedApparmorOutput(t *testing.T) {
	content := `{"version": "1", "profiles": {, "/usr/bin/man": "complain"}, "processes": {], "/usr/sbin/chronyd": [{"profile": "/usr/sbin/chronyd", "pid": "339", "status": "unconfined"}]}}`

	res, err := (&mqlParseJson{}).params(content)
	require.NoError(t, err)

	params := res.(map[string]any)
	assert.Equal(t, "1", params["version"])

	profiles := params["profiles"].(map[string]any)
	assert.Equal(t, "complain", profiles["/usr/bin/man"])

	processes := params["processes"].(map[string]any)
	chronyd := processes["/usr/sbin/chronyd"].([]any)
	require.Len(t, chronyd, 1)

	proc := chronyd[0].(map[string]any)
	assert.Equal(t, "/usr/sbin/chronyd", proc["profile"])
	assert.Equal(t, "339", proc["pid"])
	assert.Equal(t, "unconfined", proc["status"])
}

func TestParseJsonParamsRejectsUnrepairableJSON(t *testing.T) {
	_, err := (&mqlParseJson{}).params(`{"version": nope}`)
	require.Error(t, err)
}

func TestParseYamlDocumentsKeepsMarkersInsideValues(t *testing.T) {
	// Synthetic: the reproduction from the issue; no target showed this.
	content := "a: 1\nnote: \"x---y\"\n---\nb: 2\n"

	docs, err := (&mqlParseYaml{}).documents(content)
	require.NoError(t, err)
	assert.Equal(t, []any{
		map[string]any{"a": float64(1), "note": "x---y"},
		map[string]any{"b": float64(2)},
	}, docs)
}

func TestParseYamlDocumentsSplitsOnMarkerLines(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []any
	}{
		// Synthetic: each case below covers one shape of marker or value.
		{
			name:    "markdown rule and PEM armor inside a block scalar",
			content: "cert: |\n  -----BEGIN CERTIFICATE-----\n  abc\n  -----END CERTIFICATE-----\nrule: '---'\n---\nb: 2\n",
			want: []any{
				map[string]any{"cert": "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n", "rule": "---"},
				map[string]any{"b": float64(2)},
			},
		},
		{
			name:    "indented dashes in a list value",
			content: "items:\n  - ---\n  - '--- x'\n",
			want:    []any{map[string]any{"items": []any{"---", "--- x"}}},
		},
		{
			name:    "four dashes are not a marker",
			content: "a: 1\nb: ----\n",
			want:    []any{map[string]any{"a": float64(1), "b": "----"}},
		},
		{
			name:    "leading and trailing markers",
			content: "---\na: 1\n---\nb: 2\n---\n",
			want:    []any{map[string]any{"a": float64(1)}, map[string]any{"b": float64(2)}},
		},
		{
			name:    "marker followed by a comment",
			content: "--- # first\na: 1\n--- # second\nb: 2\n",
			want:    []any{map[string]any{"a": float64(1)}, map[string]any{"b": float64(2)}},
		},
		{
			name:    "marker followed by a block scalar header",
			content: "--- |\n  text --- inside\n--- >\n  folded\n",
			want:    []any{"text --- inside\n", "folded\n"},
		},
		{
			name:    "document end marker",
			content: "a: 1\n...\n---\nb: 2\n...\n",
			want:    []any{map[string]any{"a": float64(1)}, map[string]any{"b": float64(2)}},
		},
		{
			name:    "windows line endings",
			content: "a: 1\r\n---\r\nb: 2\r\n",
			want:    []any{map[string]any{"a": float64(1)}, map[string]any{"b": float64(2)}},
		},
		{
			name:    "empty and null documents are skipped",
			content: "---\n---\n# only a comment\n---\nnull\n---\nb: 2\n",
			want:    []any{map[string]any{"b": float64(2)}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			docs, err := (&mqlParseYaml{}).documents(tt.content)
			require.NoError(t, err)
			assert.Equal(t, tt.want, docs)
		})
	}
}

func TestParseYamlDocumentsReportsInvalidDocument(t *testing.T) {
	// Synthetic: the second document is malformed; the error must name the
	// parse failure instead of silently dropping the document.
	_, err := (&mqlParseYaml{}).documents("a: 1\n---\nb: [unclosed\n")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse YAML document")
}

func TestSplitYamlDocuments(t *testing.T) {
	// Synthetic: the chunks keep their own text, markers removed.
	assert.Equal(t, []string{"a: 1", "b: 2"}, trimAll(splitYamlDocuments("a: 1\n---\nb: 2")))
	assert.Equal(t, []string{"a: 1\nnote: x---y", "b: 2"}, trimAll(splitYamlDocuments("a: 1\nnote: x---y\n---\nb: 2")))
	assert.Equal(t, []string{"a: --- b"}, trimAll(splitYamlDocuments("a: --- b")))
	assert.Equal(t, []string{"", "a: 1"}, trimAll(splitYamlDocuments("---\na: 1")))
	assert.Equal(t, []string{""}, trimAll(splitYamlDocuments("")))
}

func trimAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.TrimSpace(s)
	}
	return out
}
