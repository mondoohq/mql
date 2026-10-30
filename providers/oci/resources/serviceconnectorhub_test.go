// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOciSplitLogGroupRefs(t *testing.T) {
	const (
		groupA = "ocid1.loggroup.oc1.us-ashburn-1.aaaaaaaaexamplegroupa"
		groupB = "ocid1.loggroup.oc1.us-ashburn-1.aaaaaaaaexamplegroupb"
	)

	tests := []struct {
		name      string
		refs      []string
		wantOcids []string
		wantAudit bool
	}{
		{"no sources", nil, []string{}, false},

		{"a single log group", []string{groupA}, []string{groupA}, false},
		{"several log groups", []string{groupA, groupB}, []string{groupA, groupB}, false},

		// The regression. `_Audit` is a reserved name for the tenancy audit
		// stream, not an OCID, so it can never resolve to a log group. Feeding
		// it to the lookup made it fail and get dropped, and a connector that
		// exports the audit log - the main reason to run Connector Hub -
		// reported no sources at all.
		{"the audit sentinel alone", []string{"_Audit"}, []string{}, true},
		{"the audit sentinel beside a log group", []string{"_Audit", groupA}, []string{groupA}, true},

		// A source scoped to a whole compartment names no log group.
		{"empty reference", []string{""}, []string{}, false},
		{"empty reference beside a log group", []string{"", groupA}, []string{groupA}, false},

		// Anything else is not resolvable and must not reach the lookup.
		{"non-ocid junk", []string{"not-an-ocid"}, []string{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ocids, audit := ociSplitLogGroupRefs(tt.refs)
			assert.Equal(t, tt.wantOcids, ocids)
			assert.Equal(t, tt.wantAudit, audit)
		})
	}
}
