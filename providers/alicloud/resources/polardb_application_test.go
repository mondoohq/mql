// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	polardb "github.com/alibabacloud-go/polardb-20170801/v10/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolardbApplicationEndpointsToDict(t *testing.T) {
	t.Run("absent endpoints read as an empty list, never nil", func(t *testing.T) {
		assert.Equal(t, []any{}, polardbApplicationEndpointsToDict(nil))
		assert.Equal(t, []any{}, polardbApplicationEndpointsToDict(
			&polardb.DescribeApplicationsResponseBodyItemsApplicationsEndpoints{}))
	})

	t.Run("netType is carried through verbatim", func(t *testing.T) {
		// netType is what separates an address reachable from the internet from
		// a VPC-internal one, so it has to survive the flattening intact.
		endpoints := &polardb.DescribeApplicationsResponseBodyItemsApplicationsEndpoints{
			Endpoint: []*polardb.DescribeApplicationsResponseBodyItemsApplicationsEndpointsEndpoint{
				{IP: new("192.0.2.10"), NetType: new("Private"), Port: new("5432")},
				{IP: new("203.0.113.7"), NetType: new("Public"), Port: new("5432")},
			},
		}

		res := polardbApplicationEndpointsToDict(endpoints)
		require.Len(t, res, 2)
		assert.Equal(t, map[string]any{
			"ip": "192.0.2.10", "netType": "Private", "port": "5432",
		}, res[0])
		assert.Equal(t, map[string]any{
			"ip": "203.0.113.7", "netType": "Public", "port": "5432",
		}, res[1])
	})

	t.Run("a nil entry is skipped without dropping its siblings", func(t *testing.T) {
		endpoints := &polardb.DescribeApplicationsResponseBodyItemsApplicationsEndpoints{
			Endpoint: []*polardb.DescribeApplicationsResponseBodyItemsApplicationsEndpointsEndpoint{
				nil,
				{IP: new("203.0.113.7"), NetType: new("Public"), Port: new("5432")},
			},
		}

		res := polardbApplicationEndpointsToDict(endpoints)
		require.Len(t, res, 1)
		assert.Equal(t, "Public", res[0].(map[string]any)["netType"])
	})

	t.Run("absent members read as empty strings, not as a panic", func(t *testing.T) {
		endpoints := &polardb.DescribeApplicationsResponseBodyItemsApplicationsEndpoints{
			Endpoint: []*polardb.DescribeApplicationsResponseBodyItemsApplicationsEndpointsEndpoint{{}},
		}

		res := polardbApplicationEndpointsToDict(endpoints)
		require.Len(t, res, 1)
		assert.Equal(t, map[string]any{"ip": "", "netType": "", "port": ""}, res[0])
	})
}

func TestPolardbApplicationTagsToMap(t *testing.T) {
	t.Run("absent tags read as an empty map, never nil", func(t *testing.T) {
		assert.Equal(t, map[string]any{}, polardbApplicationTagsToMap(nil))
		assert.Equal(t, map[string]any{}, polardbApplicationTagsToMap(
			&polardb.DescribeApplicationsResponseBodyItemsApplicationsTags{}))
	})

	t.Run("key and value pairs are flattened", func(t *testing.T) {
		tags := &polardb.DescribeApplicationsResponseBodyItemsApplicationsTags{
			Tag: []*polardb.DescribeApplicationsResponseBodyItemsApplicationsTagsTag{
				{Key: new("env"), Value: new("prod")},
				{Key: new("owner"), Value: new("platform")},
			},
		}

		assert.Equal(t, map[string]any{"env": "prod", "owner": "platform"},
			polardbApplicationTagsToMap(tags))
	})

	t.Run("a keyless or nil tag is skipped, and a valueless key survives", func(t *testing.T) {
		// A tag with no value is a real Alibaba Cloud shape and must still
		// appear, otherwise a `tags["x"] != null` check misses it.
		tags := &polardb.DescribeApplicationsResponseBodyItemsApplicationsTags{
			Tag: []*polardb.DescribeApplicationsResponseBodyItemsApplicationsTagsTag{
				nil,
				{Value: new("orphan")},
				{Key: new("novalue")},
				{Key: new("env"), Value: new("prod")},
			},
		}

		assert.Equal(t, map[string]any{"novalue": "", "env": "prod"},
			polardbApplicationTagsToMap(tags))
	})
}
