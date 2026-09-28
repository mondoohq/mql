// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/aws/connection"
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

func TestTrailTagsForFilters(t *testing.T) {
	const tagged, untagged, unreadable = "arn:tagged", "arn:untagged", "arn:unreadable"
	tagsByArn := map[string]map[string]string{
		tagged:   {"env": "test"},
		untagged: {},
		// unreadable: absent, its ListTags call failed
	}
	include := connection.GeneralDiscoveryFilters{Tags: map[string]string{"env": "test"}}
	exclude := connection.GeneralDiscoveryFilters{ExcludeTags: map[string]string{"env": "test"}}

	tests := []struct {
		name     string
		filters  connection.GeneralDiscoveryFilters
		arn      string
		wantKeep bool
		wantTags map[string]string
	}{
		{"no filters keep every trail, tags stay lazy", connection.GeneralDiscoveryFilters{}, untagged, true, nil},
		{"include keeps a matching trail and seeds its tags", include, tagged, true, map[string]string{"env": "test"}},
		{"include drops a trail without the tag", include, untagged, false, nil},
		{"include drops a trail whose tags could not be read", include, unreadable, false, nil},
		{"exclude drops a matching trail", exclude, tagged, false, nil},
		{"exclude keeps a trail without the tag", exclude, untagged, true, map[string]string{}},
		{"exclude keeps a trail whose tags could not be read, tags stay lazy", exclude, unreadable, true, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tags, keep := trailTagsForFilters(tc.filters, tagsByArn, tc.arn)
			assert.Equal(t, tc.wantKeep, keep)
			assert.Equal(t, tc.wantTags, tags)
		})
	}
}
