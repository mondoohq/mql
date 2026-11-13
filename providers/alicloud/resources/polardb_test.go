// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	polardb "github.com/alibabacloud-go/polardb-20170801/v10/client"
	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/stretchr/testify/assert"
)

func TestPolardbWhitelistEntries(t *testing.T) {
	// Synthetic: shaped after the SDK's documented example; no live cluster
	// with a project whitelist was available.
	body := &polardb.DescribeDBClusterAccessWhitelistResponseBody{
		Items: &polardb.DescribeDBClusterAccessWhitelistResponseBodyItems{
			DBClusterIPArray: []*polardb.DescribeDBClusterAccessWhitelistResponseBodyItemsDBClusterIPArray{
				{SecurityIps: tea.String("10.0.0.0/8, 192.168.1.1")},
				nil,
				{SecurityIps: nil},
			},
		},
		ProjectItems: &polardb.DescribeDBClusterAccessWhitelistResponseBodyProjectItems{
			DBClusterProjectIPArray: []*polardb.DescribeDBClusterAccessWhitelistResponseBodyProjectItemsDBClusterProjectIPArray{
				{ProjectId: tea.String("proj-a"), SecurityIps: tea.String("192.168.2.0/24")},
				{ProjectId: tea.String("proj-b"), SecurityIps: tea.String("0.0.0.0/0,")},
			},
		},
	}
	cluster, project := polardbWhitelistEntries(body)
	assert.Equal(t, []any{"10.0.0.0/8", "192.168.1.1"}, cluster)
	assert.Equal(t, []any{"192.168.2.0/24", "0.0.0.0/0"}, project)

	// Synthetic: a response without project whitelists.
	cluster, project = polardbWhitelistEntries(&polardb.DescribeDBClusterAccessWhitelistResponseBody{})
	assert.Empty(t, cluster)
	assert.Empty(t, project)

	cluster, project = polardbWhitelistEntries(nil)
	assert.Empty(t, cluster)
	assert.Empty(t, project)
}
