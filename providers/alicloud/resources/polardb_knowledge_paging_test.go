// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"testing"

	polardb "github.com/alibabacloud-go/polardb-20170801/v9/client"
	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// polardbSyncLinkPages builds a page reader over a fixed set of links, recording
// the page numbers it was asked for. The recorded order is what separates a walk
// that pages from one that asks for the same page over and over.
func polardbSyncLinkPages(total int, pageSize int32) (polardbSyncLinkPageFunc, *[]int32) {
	asked := []int32{}
	fetch := func(pageNumber, size int32) ([]*polardb.DescribeKBSyncLinksResponseBodyItems, error) {
		asked = append(asked, pageNumber)
		start := int(pageNumber-1) * int(size)
		if start >= total {
			return nil, nil
		}
		end := start + int(size)
		if end > total {
			end = total
		}
		page := []*polardb.DescribeKBSyncLinksResponseBodyItems{}
		for i := start; i < end; i++ {
			page = append(page, &polardb.DescribeKBSyncLinksResponseBodyItems{
				LinkId: tea.String(fmt.Sprintf("pkbl-%03d", i)),
			})
		}
		return page, nil
	}
	return fetch, &asked
}

// TestCollectPolardbSyncLinks covers the synchronization link paging walk.
// DescribeKBSyncLinks answers with 30 links when no page is asked for, so a
// knowledge base carrying more unattended feeds than that reported only the
// first 30, and an audit counting the feeds on a busy corpus came up short.
func TestCollectPolardbSyncLinks(t *testing.T) {
	t.Run("every page is collected", func(t *testing.T) {
		fetch, asked := polardbSyncLinkPages(207, 100)

		got, err := collectPolardbSyncLinks(100, fetch)
		require.NoError(t, err)
		require.Len(t, got, 207)
		assert.Equal(t, []int32{1, 2, 3}, *asked)
		assert.Equal(t, "pkbl-000", tea.StringValue(got[0].LinkId))
		assert.Equal(t, "pkbl-206", tea.StringValue(got[206].LinkId))
	})

	t.Run("a page shorter than requested ends the walk", func(t *testing.T) {
		fetch, asked := polardbSyncLinkPages(7, 100)

		got, err := collectPolardbSyncLinks(100, fetch)
		require.NoError(t, err)
		assert.Len(t, got, 7)
		assert.Equal(t, []int32{1}, *asked)
	})

	t.Run("a full last page costs one more call and yields no duplicates", func(t *testing.T) {
		fetch, asked := polardbSyncLinkPages(200, 100)

		got, err := collectPolardbSyncLinks(100, fetch)
		require.NoError(t, err)
		require.Len(t, got, 200)
		assert.Equal(t, []int32{1, 2, 3}, *asked)

		seen := map[string]bool{}
		for _, l := range got {
			id := tea.StringValue(l.LinkId)
			assert.False(t, seen[id], "link %q was collected twice", id)
			seen[id] = true
		}
	})

	t.Run("a knowledge base with no links yields none", func(t *testing.T) {
		fetch, asked := polardbSyncLinkPages(0, 100)

		got, err := collectPolardbSyncLinks(100, fetch)
		require.NoError(t, err)
		assert.Empty(t, got)
		assert.Equal(t, []int32{1}, *asked)
	})

	t.Run("nil links in a page are skipped", func(t *testing.T) {
		fetch := func(pageNumber, pageSize int32) ([]*polardb.DescribeKBSyncLinksResponseBodyItems, error) {
			return []*polardb.DescribeKBSyncLinksResponseBodyItems{
				nil,
				{LinkId: tea.String("pkbl-bp1example")},
				nil,
			}, nil
		}

		got, err := collectPolardbSyncLinks(100, fetch)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, "pkbl-bp1example", tea.StringValue(got[0].LinkId))
	})

	t.Run("an error on a later page fails the walk rather than truncating it", func(t *testing.T) {
		calls := 0
		fetch := func(pageNumber, pageSize int32) ([]*polardb.DescribeKBSyncLinksResponseBodyItems, error) {
			calls++
			if pageNumber > 1 {
				return nil, errors.New("Throttling.User")
			}
			page := []*polardb.DescribeKBSyncLinksResponseBodyItems{}
			for i := 0; i < int(pageSize); i++ {
				page = append(page, &polardb.DescribeKBSyncLinksResponseBodyItems{
					LinkId: tea.String(fmt.Sprintf("pkbl-%03d", i)),
				})
			}
			return page, nil
		}

		got, err := collectPolardbSyncLinks(100, fetch)
		require.Error(t, err)
		assert.Nil(t, got)
		assert.Equal(t, 2, calls)
	})

	t.Run("a server that ignores PageNumber stops at the page cap", func(t *testing.T) {
		calls := 0
		fetch := func(pageNumber, pageSize int32) ([]*polardb.DescribeKBSyncLinksResponseBodyItems, error) {
			calls++
			page := []*polardb.DescribeKBSyncLinksResponseBodyItems{}
			for i := 0; i < int(pageSize); i++ {
				page = append(page, &polardb.DescribeKBSyncLinksResponseBodyItems{
					LinkId: tea.String("pkbl-bp1example"),
				})
			}
			return page, nil
		}

		got, err := collectPolardbSyncLinks(10, fetch)
		require.NoError(t, err)
		assert.Equal(t, polardbKnowledgeMaxPages, calls)
		assert.Len(t, got, polardbKnowledgeMaxPages*10)
	})
}
