// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	hfmodels "go.mondoo.com/mql/providers/huggingface/internal/huggingface-hub-go/models"
)

func TestNormalizeModelID(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"plain owner/model", "meta-llama/Llama-3.1-8B", "meta-llama/Llama-3.1-8B", false},
		{"plain canonical", "gpt2", "gpt2", false},
		{"url owner/model", "https://huggingface.co/meta-llama/Llama-3.1-8B", "meta-llama/Llama-3.1-8B", false},
		{"url with trailing path", "https://huggingface.co/meta-llama/Llama-3.1-8B/tree/main", "meta-llama/Llama-3.1-8B", false},
		{"url canonical single segment", "https://huggingface.co/gpt2", "gpt2", false},
		{"url trailing slash", "https://huggingface.co/gpt2/", "gpt2", false},
		{"url no path", "https://huggingface.co", "", true},
		{"url root only", "https://huggingface.co/", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeModelID(tt.in)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseHFTime(t *testing.T) {
	// RFC3339Nano (the common form, with and without fractional seconds).
	got := parseHFTime("2024-01-02T03:04:05.123456789Z")
	require.NotNil(t, got)
	assert.True(t, got.Equal(time.Date(2024, 1, 2, 3, 4, 5, 123456789, time.UTC)))

	got = parseHFTime("2024-01-02T03:04:05Z")
	require.NotNil(t, got)
	assert.True(t, got.Equal(time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)))

	// Millisecond "Z" form handled by the fallback layout.
	got = parseHFTime("2024-01-02T03:04:05.000Z")
	require.NotNil(t, got)
	assert.True(t, got.Equal(time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)))

	// Empty and unparseable inputs yield nil (null time), never a panic.
	assert.Nil(t, parseHFTime(""))
	assert.Nil(t, parseHFTime("not-a-timestamp"))
}

// gatedMode has to keep "auto" (anyone accepting the terms is admitted) apart
// from "manual" (an owner approves each request), and has to stay null when the
// Hub never reported the field. Returning the mode unconditionally would turn an
// unread setting into the claim that the repository is ungated.
func TestGatedModeValue(t *testing.T) {
	tests := []struct {
		name string
		in   hfmodels.GatedValue
		want *string
	}{
		{"ungated", hfmodels.GatedValue{IsGated: false, Mode: "false"}, ptr("false")},
		{"auto", hfmodels.GatedValue{IsGated: true, Mode: "auto"}, ptr("auto")},
		{"manual", hfmodels.GatedValue{IsGated: true, Mode: "manual"}, ptr("manual")},
		{"legacy bool true", hfmodels.GatedValue{IsGated: true, Mode: "true"}, ptr("true")},
		{"never reported", hfmodels.GatedValue{}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := gatedModeValue(tt.in)
			if tt.want == nil {
				assert.Nil(t, got, "an unreported gated field must resolve to null, not to \"false\"")
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, *tt.want, *got)
		})
	}
}

func ptr(s string) *string { return &s }

func TestStringsToInterface(t *testing.T) {
	assert.Equal(t, []any{}, stringsToInterface(nil))
	assert.Equal(t, []any{"a", "b"}, stringsToInterface([]string{"a", "b"}))
}
