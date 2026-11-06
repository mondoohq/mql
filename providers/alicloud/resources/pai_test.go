// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"testing"

	easclient "github.com/alibabacloud-go/eas-20210701/v7/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPaiPagedList(t *testing.T) {
	// Synthetic: page walks over a fake listing; no target showed these.
	pages := func(sizes []int, total int64) (func(page int) ([]int, int64, error), *int) {
		calls := 0
		return func(page int) ([]int, int64, error) {
			calls++
			if page > len(sizes) {
				return nil, total, nil
			}
			items := make([]int, sizes[page-1])
			for i := range items {
				items[i] = page*1000 + i
			}
			return items, total, nil
		}, &calls
	}

	t.Run("stops once the reported total is reached", func(t *testing.T) {
		fetch, calls := pages([]int{2, 2, 1}, 5)
		got, err := paiPagedList(2, fetch)
		require.NoError(t, err)
		assert.Len(t, got, 5)
		assert.Equal(t, 3, *calls)
	})

	t.Run("a full last page ends on the total without an extra call", func(t *testing.T) {
		fetch, calls := pages([]int{2, 2}, 4)
		got, err := paiPagedList(2, fetch)
		require.NoError(t, err)
		assert.Len(t, got, 4)
		assert.Equal(t, 2, *calls)
	})

	t.Run("a short page ends the walk even when the total says more", func(t *testing.T) {
		fetch, calls := pages([]int{2, 1, 2}, 100)
		got, err := paiPagedList(2, fetch)
		require.NoError(t, err)
		assert.Len(t, got, 3)
		assert.Equal(t, 2, *calls)
	})

	t.Run("an empty page ends the walk when the total overstates", func(t *testing.T) {
		fetch, calls := pages([]int{2}, 100)
		got, err := paiPagedList(2, fetch)
		require.NoError(t, err)
		assert.Len(t, got, 2)
		assert.Equal(t, 2, *calls)
	})

	t.Run("an error on a later page fails the walk", func(t *testing.T) {
		boom := errors.New("boom")
		_, err := paiPagedList(1, func(page int) ([]int, int64, error) {
			if page == 2 {
				return nil, 0, boom
			}
			return []int{1}, 3, nil
		})
		assert.ErrorIs(t, err, boom)
	})

	t.Run("no results yields an empty list, not nil", func(t *testing.T) {
		got, err := paiPagedList(2, func(page int) ([]int, int64, error) { return nil, 0, nil })
		require.NoError(t, err)
		assert.NotNil(t, got)
		assert.Empty(t, got)
	})
}

func TestParseEasNetworking(t *testing.T) {
	t.Run("reads the VPC placement", func(t *testing.T) {
		// Synthetic: shape from the EAS service configuration reference; no
		// target showed this.
		cfg := `{"name":"llm","token":"secret-value","metadata":{"instance":1},` +
			`"cloud":{"computing":{"instance_type":"ecs.gn6i-c4g1.xlarge"},` +
			`"networking":{"vpc_id":"vpc-abc","vswitch_id":" vsw-def ","security_group_id":"sg-ghi"}}}`
		n := parseEasNetworking(cfg)
		assert.Equal(t, "vpc-abc", n.VpcId)
		assert.Equal(t, "vsw-def", n.VswitchId)
		assert.Equal(t, "sg-ghi", n.SecurityGroupId)
	})

	t.Run("a service with no VPC has empty ids", func(t *testing.T) {
		// Synthetic: the example ServiceConfig in the EAS SDK, which has no cloud section.
		cfg := `{"metadata":{"cpu":1,"instance":1,"memory":1024},"name":"echo","processor_entry":"libecho.so","processor_type":"cpp"}`
		assert.Equal(t, easNetworking{}, parseEasNetworking(cfg))
	})

	t.Run("empty and malformed documents yield empty ids", func(t *testing.T) {
		// Synthetic: no target showed these.
		assert.Equal(t, easNetworking{}, parseEasNetworking(""))
		assert.Equal(t, easNetworking{}, parseEasNetworking("   "))
		assert.Equal(t, easNetworking{}, parseEasNetworking("{not json"))
		assert.Equal(t, easNetworking{}, parseEasNetworking(`{"cloud":"oops"}`))
	})
}

func TestEasInternetAclEntries(t *testing.T) {
	t.Run("flattens every policy list", func(t *testing.T) {
		// Synthetic: shape from the ListAclPolicy response model; no target showed this.
		var body easclient.ListAclPolicyResponseBody
		require.NoError(t, json.Unmarshal([]byte(`{
			"GatewayId": "gw-1",
			"InternetAclPolicyList": [
				{"AclPolicyList": [{"Entry": "10.0.0.0/8", "Comment": "office"}, {"Entry": " 0.0.0.0/0 "}]},
				{"AclPolicyList": [{"Entry": ""}, {"Entry": "192.168.1.0/24", "Comment": "lab"}]}
			],
			"IntranetVpcAclPolicyList": [
				{"VpcId": "vpc-1", "AclPolicyList": [{"Entry": "172.16.0.0/12"}]}
			]
		}`), &body))

		got := easInternetAclEntries(&body)
		assert.Equal(t, []any{
			map[string]any{"entry": "10.0.0.0/8", "comment": "office"},
			map[string]any{"entry": "0.0.0.0/0", "comment": ""},
			map[string]any{"entry": "192.168.1.0/24", "comment": "lab"},
		}, got)
	})

	t.Run("no body or no internet policies yields an empty list", func(t *testing.T) {
		// Synthetic: no target showed this.
		assert.Equal(t, []any{}, easInternetAclEntries(nil))
		assert.Equal(t, []any{}, easInternetAclEntries(&easclient.ListAclPolicyResponseBody{}))
	})
}
