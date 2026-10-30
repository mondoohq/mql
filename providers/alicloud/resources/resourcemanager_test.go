// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	rmclient "github.com/alibabacloud-go/resourcemanager-20200331/v3/client"
	"github.com/stretchr/testify/assert"
)

// TestRmPageDone covers the Resource Management pagination guard. The failure
// this protects against is silent: an endpoint that reports no total and always
// returns a full page would page forever without the short-page check, and a
// listing cut off one page early reports a partial account as the whole account.
func TestRmPageDone(t *testing.T) {
	t.Run("short page ends the walk", func(t *testing.T) {
		assert.True(t, rmPageDone(37, 1, 100, 0))
	})
	t.Run("empty page ends the walk", func(t *testing.T) {
		assert.True(t, rmPageDone(0, 3, 100, 0))
	})
	t.Run("full page with no reported total continues", func(t *testing.T) {
		assert.False(t, rmPageDone(100, 1, 100, 0))
	})
	t.Run("full page short of the total continues", func(t *testing.T) {
		assert.False(t, rmPageDone(100, 1, 100, 250))
	})
	t.Run("full page reaching the total ends the walk", func(t *testing.T) {
		assert.True(t, rmPageDone(100, 3, 100, 250))
	})
	t.Run("full page exactly at the total ends the walk", func(t *testing.T) {
		assert.True(t, rmPageDone(100, 2, 100, 200))
	})
}

// TestResourceGroupTagsToMap covers the tag envelope flattening. A resource
// group's tags select environments in an audit, so a dropped or empty-keyed tag
// silently changes which resources a query matches.
func TestResourceGroupTagsToMap(t *testing.T) {
	tag := func(k, v *string) *rmclient.ListResourceGroupsResponseBodyResourceGroupsResourceGroupTags {
		return &rmclient.ListResourceGroupsResponseBodyResourceGroupsResourceGroupTags{
			Tag: []*rmclient.ListResourceGroupsResponseBodyResourceGroupsResourceGroupTagsTag{
				{TagKey: k, TagValue: v},
			},
		}
	}

	t.Run("nil envelope yields an empty map, not nil", func(t *testing.T) {
		got := resourceGroupTagsToMap(nil)
		assert.NotNil(t, got)
		assert.Empty(t, got)
	})
	t.Run("key and value are carried through", func(t *testing.T) {
		got := resourceGroupTagsToMap(tag(new("env"), new("production")))
		assert.Equal(t, map[string]any{"env": "production"}, got)
	})
	t.Run("nil value becomes an empty string", func(t *testing.T) {
		got := resourceGroupTagsToMap(tag(new("env"), nil))
		assert.Equal(t, map[string]any{"env": ""}, got)
	})
	t.Run("nil key is dropped", func(t *testing.T) {
		assert.Empty(t, resourceGroupTagsToMap(tag(nil, new("production"))))
	})
	t.Run("empty key is dropped", func(t *testing.T) {
		assert.Empty(t, resourceGroupTagsToMap(tag(new(""), new("production"))))
	})
	t.Run("nil tag entry is skipped", func(t *testing.T) {
		tags := &rmclient.ListResourceGroupsResponseBodyResourceGroupsResourceGroupTags{
			Tag: []*rmclient.ListResourceGroupsResponseBodyResourceGroupsResourceGroupTagsTag{
				nil,
				{TagKey: new("env"), TagValue: new("staging")},
			},
		}
		assert.Equal(t, map[string]any{"env": "staging"}, resourceGroupTagsToMap(tags))
	})
}
