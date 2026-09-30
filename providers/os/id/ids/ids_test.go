// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package ids

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"single detector", "hostname", []string{"hostname"}},
		{"list", "default,crowdstrike-aid", []string{"default", "crowdstrike-aid"}},
		{"whitespace", " default , crowdstrike-aid\t", []string{"default", "crowdstrike-aid"}},
		{"empty entries", ",hostname,,", []string{"hostname"}},
		{"empty", "", nil},
		{"only separators", " , ", nil},
		{"unknown names are kept", "hostname,no-such-detector", []string{"hostname", "no-such-detector"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, Parse(tt.in))
		})
	}
}

func TestHasDefault(t *testing.T) {
	assert.True(t, HasDefault(nil))
	assert.True(t, HasDefault([]string{}))
	assert.True(t, HasDefault([]string{IdDetector_CrowdStrikeAID, IdDetector_Default}))
	assert.False(t, HasDefault([]string{IdDetector_Hostname}))
}

func TestExpandDefault(t *testing.T) {
	defaults := []string{IdDetector_CloudDetect, IdDetector_Hostname}

	assert.Equal(t, defaults, ExpandDefault(nil, defaults), "empty list is the defaults")
	assert.Equal(t, defaults, ExpandDefault([]string{IdDetector_Default}, defaults), "default alone is the defaults")
	assert.Equal(t,
		[]string{IdDetector_CloudDetect, IdDetector_Hostname, IdDetector_CrowdStrikeAID},
		ExpandDefault([]string{IdDetector_Default, IdDetector_CrowdStrikeAID}, defaults))
	assert.Equal(t,
		[]string{IdDetector_CrowdStrikeAID, IdDetector_CloudDetect, IdDetector_Hostname},
		ExpandDefault([]string{IdDetector_CrowdStrikeAID, IdDetector_Default}, defaults), "order is kept")
	assert.Equal(t,
		[]string{IdDetector_Hostname, IdDetector_CloudDetect},
		ExpandDefault([]string{IdDetector_Hostname, IdDetector_Default}, defaults), "each detector once")
	assert.Equal(t, []string{IdDetector_MachineID}, ExpandDefault([]string{IdDetector_MachineID}, defaults),
		"a list without default is unchanged")

	ExpandDefault(nil, defaults)[0] = "changed"
	assert.Equal(t, IdDetector_CloudDetect, defaults[0], "the defaults are not aliased")
}
