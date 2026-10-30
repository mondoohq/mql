// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

// Activity log alerts and Databricks workspaces carry ARM tags, so the tag
// filters narrow their subscription lists as they narrow the other lists.
func TestKeepTagMatchesAlertsAndDatabricks(t *testing.T) {
	runtime := runtimeWithTagFilters(t, map[string]string{"env": "a"}, nil)

	for _, tc := range []struct {
		resource string
		idPrefix string
	}{
		{ResourceAzureSubscriptionMonitorServiceActivityLogAlert, "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Insights/activityLogAlerts/"},
		{ResourceAzureSubscriptionDatabricksServiceWorkspace, "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Databricks/workspaces/"},
	} {
		t.Run(tc.resource, func(t *testing.T) {
			create := func(name string, tags map[string]any) any {
				res, err := CreateResource(runtime, tc.resource, map[string]*llx.RawData{
					"id":   llx.StringData(tc.idPrefix + name),
					"tags": llx.MapData(tags, types.String),
				})
				require.NoError(t, err)
				return res
			}
			a := create("a", map[string]any{"env": "a"})
			b := create("b", map[string]any{"env": "b"})
			untagged := create("untagged", map[string]any{})

			assert.Equal(t, []any{a}, keepTagMatches(runtime, []any{a, b, untagged}))
			assert.Same(t, b, tagFilteredOut(runtime, tc.resource, tc.idPrefix+"b"))
		})
	}
}
