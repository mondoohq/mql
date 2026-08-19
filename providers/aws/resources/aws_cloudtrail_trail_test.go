// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
)

func TestCapturesAllManagementEvents(t *testing.T) {
	selector := func(mgmt bool, readWriteType string) *mqlAwsCloudtrailTrailEventSelector {
		sel := &mqlAwsCloudtrailTrailEventSelector{}
		sel.IncludeManagementEvents = plugin.TValue[bool]{Data: mgmt, State: plugin.StateIsSet}
		sel.ReadWriteType = plugin.TValue[string]{Data: readWriteType, State: plugin.StateIsSet}
		return sel
	}
	// A trail uses classic or advanced selectors, never both, so these trails
	// carry an empty advanced set. capturesAllManagementEvents consults both,
	// and leaving the field unset would send it to the API for the answer.
	trail := func(sels ...*mqlAwsCloudtrailTrailEventSelector) *mqlAwsCloudtrailTrail {
		entries := make([]any, len(sels))
		for i, s := range sels {
			entries[i] = s
		}
		tr := &mqlAwsCloudtrailTrail{}
		tr.EventSelectorEntries = plugin.TValue[[]any]{Data: entries, State: plugin.StateIsSet}
		tr.AdvancedEventSelectors = plugin.TValue[[]any]{Data: []any{}, State: plugin.StateIsSet}
		return tr
	}

	tests := []struct {
		name string
		sels []*mqlAwsCloudtrailTrailEventSelector
		want bool
	}{
		{"management + All", []*mqlAwsCloudtrailTrailEventSelector{selector(true, "All")}, true},
		{"management but write only", []*mqlAwsCloudtrailTrailEventSelector{selector(true, "WriteOnly")}, false},
		{"All but no management", []*mqlAwsCloudtrailTrailEventSelector{selector(false, "All")}, false},
		{"matches among several", []*mqlAwsCloudtrailTrailEventSelector{selector(false, "ReadOnly"), selector(true, "All")}, true},
		{"no selectors", nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := trail(tc.sels...).capturesAllManagementEvents()
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	// A trail configured through CloudFormation or Terraform has no classic
	// selectors at all, and the answer has to come from the advanced ones.
	t.Run("advanced selectors with no classic selectors", func(t *testing.T) {
		tr := &mqlAwsCloudtrailTrail{}
		tr.EventSelectorEntries = plugin.TValue[[]any]{Data: []any{}, State: plugin.StateIsSet}
		tr.AdvancedEventSelectors = plugin.TValue[[]any]{
			Data:  advancedSelectors(advancedSelector(equalsSelector("eventCategory", "Management"))),
			State: plugin.StateIsSet,
		}

		got, err := tr.capturesAllManagementEvents()
		require.NoError(t, err)
		assert.True(t, got)
	})
}
