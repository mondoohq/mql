// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAcrEpochMillis covers the millisecond timestamp conversion. The zero case
// matters: a registry record that has never carried a timestamp must stay null
// rather than reporting 1 January 1970 as a real date.
func TestAcrEpochMillis(t *testing.T) {
	t.Run("nil stays nil", func(t *testing.T) {
		assert.Nil(t, acrEpochMillis(nil))
	})
	t.Run("zero stays nil", func(t *testing.T) {
		assert.Nil(t, acrEpochMillis(tea.Int64(0)))
	})
	t.Run("a real timestamp converts", func(t *testing.T) {
		got := acrEpochMillis(tea.Int64(1562849679000))
		require.NotNil(t, got)
		assert.Equal(t, time.Date(2019, 7, 11, 12, 54, 39, 0, time.UTC), *got)
	})
}

// TestAcrEpochMillisString covers the same conversion for the string-encoded
// form ListInstance returns. A non-numeric value must yield nil rather than a
// fabricated date.
func TestAcrEpochMillisString(t *testing.T) {
	tests := []struct {
		name string
		in   *string
		want *time.Time
	}{
		{"nil stays nil", nil, nil},
		{"empty stays nil", new(""), nil},
		{"zero stays nil", new("0"), nil},
		{"not a number stays nil", new("2019-07-11T12:54:39Z"), nil},
		{"whitespace is tolerated", new(" 1562849679000 "), new(time.Date(2019, 7, 11, 12, 54, 39, 0, time.UTC))},
		{"a real timestamp converts", new("1562849679000"), new(time.Date(2019, 7, 11, 12, 54, 39, 0, time.UTC))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := acrEpochMillisString(tt.in)
			if tt.want == nil {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, *tt.want, *got)
		})
	}
}

//go:fix inline
func timePtr(t time.Time) *time.Time { return new(t) }

// TestAcrRepoIsPublic covers the two-factor public verdict. PUBLIC visibility
// alone is not reachability: a public repository inside an instance whose
// internet endpoint is switched off is still only pullable from a linked VPC,
// and reporting it as public would be a false finding.
func TestAcrRepoIsPublic(t *testing.T) {
	tests := []struct {
		name            string
		repoType        string
		internetEnabled bool
		want            bool
	}{
		{"public repo on an internet-facing registry", "PUBLIC", true, true},
		{"public repo on a vpc-only registry", "PUBLIC", false, false},
		{"private repo on an internet-facing registry", "PRIVATE", true, false},
		{"private repo on a vpc-only registry", "PRIVATE", false, false},
		{"lowercase visibility is still matched", "public", true, true},
		{"surrounding whitespace is tolerated", " PUBLIC ", true, true},
		{"empty visibility is not public", "", true, false},
		{"an unknown visibility is not public", "INTERNAL", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, acrRepoIsPublic(tt.repoType, tt.internetEnabled))
		})
	}
}
