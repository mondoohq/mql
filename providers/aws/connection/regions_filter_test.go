// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeRegionFilter(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "nothing to normalize",
			in:   []string{"us-east-1", "us-west-2"},
			want: []string{"us-east-1", "us-west-2"},
		},
		{
			// `--filters regions=us-east-1, us-west-2` is split on the comma with
			// no trimming, so the second entry keeps its leading space and
			// resolves to no endpoint at all.
			name: "a space after the comma",
			in:   []string{"us-east-1", " us-west-2"},
			want: []string{"us-east-1", "us-west-2"},
		},
		{
			// A trailing comma yields "", and an empty region means "use the
			// configured one", so the default region would be scanned twice.
			name: "a trailing comma",
			in:   []string{"us-east-1", ""},
			want: []string{"us-east-1"},
		},
		{
			name: "duplicates collapse",
			in:   []string{"us-east-1", "us-east-1", " us-east-1 "},
			want: []string{"us-east-1"},
		},
		{
			name: "tabs and surrounding space",
			in:   []string{"\tus-east-1 ", " eu-central-1"},
			want: []string{"us-east-1", "eu-central-1"},
		},
		{
			name: "nothing but empties",
			in:   []string{"", "  ", "\t"},
			want: []string{},
		},
		{
			name: "no filter at all",
			in:   nil,
			want: []string{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, normalizeRegionFilter(tc.in))
		})
	}
}

func TestUnknownRegions(t *testing.T) {
	enabled := []string{"us-east-1", "us-east-2", "us-west-2", "eu-central-1"}

	for _, tc := range []struct {
		name      string
		requested []string
		want      []string
	}{
		{
			name:      "every requested region is enabled",
			requested: []string{"us-east-1", "eu-central-1"},
			want:      []string{},
		},
		{
			// The case that returned an empty account with exit 0.
			name:      "a region that does not exist",
			requested: []string{"us-east-99"},
			want:      []string{"us-east-99"},
		},
		{
			name:      "a transposed region name",
			requested: []string{"eu-wets-1"},
			want:      []string{"eu-wets-1"},
		},
		{
			name:      "a real region the account has not enabled",
			requested: []string{"us-east-1", "ap-south-2"},
			want:      []string{"ap-south-2"},
		},
		{
			name:      "several unknown, reported in the order given",
			requested: []string{"zz-top-1", "us-east-1", "aa-bottom-2"},
			want:      []string{"zz-top-1", "aa-bottom-2"},
		},
		{
			name:      "region names are case sensitive, as AWS treats them",
			requested: []string{"US-EAST-1"},
			want:      []string{"US-EAST-1"},
		},
		{
			name:      "nothing requested",
			requested: []string{},
			want:      []string{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, unknownRegions(tc.requested, enabled))
		})
	}
}

// If the account's region list cannot be read there is nothing to check against,
// and every requested region has to be accepted rather than rejected.
func TestUnknownRegionsWithNoEnabledListRejectsEverything(t *testing.T) {
	// unknownRegions itself reports all of them; Regions() is what decides not to
	// call it when the enabled list could not be determined. Pin the raw
	// behaviour so that decision stays deliberate.
	got := unknownRegions([]string{"us-east-1"}, nil)
	assert.Equal(t, []string{"us-east-1"}, got,
		"with no enabled list everything looks unknown, which is why the caller "+
			"must skip the check rather than pass an empty list")
}
