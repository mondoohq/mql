// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	polardb "github.com/alibabacloud-go/polardb-20170801/v10/client"
	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPolardbDnatMappingKey covers the DNAT entry cache key, including the
// fallback for an entry the API returned without an EntryId. Two such entries
// on one application would otherwise share a cache key, and the runtime hands
// back the first instance for a repeated key: the second published port would
// report the first one's address and status, which is the direction that hides
// an exposed port rather than inventing one.
func TestPolardbDnatMappingKey(t *testing.T) {
	t.Run("the entry id is the key", func(t *testing.T) {
		assert.Equal(t, "fwd-bp1abc", polardbDnatMappingKey(&polardb.DescribeApplicationAttributeResponseBodyDnatMappings{
			EntryId:     new("fwd-bp1abc"),
			PortName:    new("webui"),
			FrontPort:   tea.Int32(10001),
			BackendPort: tea.Int32(8787),
		}))
	})

	t.Run("an entry with no id falls back to the port triple", func(t *testing.T) {
		assert.Equal(t, "webui/10001/8787", polardbDnatMappingKey(&polardb.DescribeApplicationAttributeResponseBodyDnatMappings{
			PortName:    new("webui"),
			FrontPort:   tea.Int32(10001),
			BackendPort: tea.Int32(8787),
		}))
	})

	t.Run("two id-less entries on one application stay distinct", func(t *testing.T) {
		webui := polardbDnatMappingKey(&polardb.DescribeApplicationAttributeResponseBodyDnatMappings{
			PortName:    new("webui"),
			FrontPort:   tea.Int32(10001),
			BackendPort: tea.Int32(8787),
		})
		ssh := polardbDnatMappingKey(&polardb.DescribeApplicationAttributeResponseBodyDnatMappings{
			PortName:    new("ssh"),
			FrontPort:   tea.Int32(10002),
			BackendPort: tea.Int32(22),
		})
		assert.NotEqual(t, webui, ssh)
	})

	t.Run("an empty entry id is not used as the key", func(t *testing.T) {
		assert.Equal(t, "ssh/10002/22", polardbDnatMappingKey(&polardb.DescribeApplicationAttributeResponseBodyDnatMappings{
			EntryId:     new(""),
			PortName:    new("ssh"),
			FrontPort:   tea.Int32(10002),
			BackendPort: tea.Int32(22),
		}))
	})

	t.Run("a nil entry yields no key", func(t *testing.T) {
		assert.Equal(t, "", polardbDnatMappingKey(nil))
	})

	t.Run("absent ports read as zero rather than panicking", func(t *testing.T) {
		assert.Equal(t, "/0/0", polardbDnatMappingKey(&polardb.DescribeApplicationAttributeResponseBodyDnatMappings{}))
	})
}

// TestDescribeApplicationAttributeDecode pins the struct tags the NAT-exposure
// fields read against a payload shaped like the documented response. A tag that
// drifts on an SDK bump decodes to a zero value rather than to an error, so an
// application published through DNAT would report no gateway and no mappings
// and read as unreachable.
func TestDescribeApplicationAttributeDecode(t *testing.T) {
	payload := []byte(`{
	  "ApplicationId": "pa-bp1example",
	  "VpcNatGatewayId": "ngw-bp1example",
	  "NatMappingSnatIpAddress": "10.64.0.20",
	  "SnatStatus": "off",
	  "DnatMappings": [
	    {
	      "AccessAddress": "10.64.0.10:10001",
	      "BackendPort": 8787,
	      "EntryId": "fwd-bp1example",
	      "FrontPort": 10001,
	      "PortName": "webui",
	      "Status": "Available"
	    }
	  ]
	}`)

	var body polardb.DescribeApplicationAttributeResponseBody
	require.NoError(t, json.Unmarshal(payload, &body))

	assert.Equal(t, "ngw-bp1example", tea.StringValue(body.VpcNatGatewayId))
	assert.Equal(t, "10.64.0.20", tea.StringValue(body.NatMappingSnatIpAddress))
	require.Len(t, body.DnatMappings, 1)

	m := body.DnatMappings[0]
	assert.Equal(t, "10.64.0.10:10001", tea.StringValue(m.AccessAddress))
	assert.Equal(t, "fwd-bp1example", tea.StringValue(m.EntryId))
	assert.Equal(t, int32(10001), tea.Int32Value(m.FrontPort))
	assert.Equal(t, int32(8787), tea.Int32Value(m.BackendPort))
	assert.Equal(t, "webui", tea.StringValue(m.PortName))
	assert.Equal(t, "Available", tea.StringValue(m.Status))
}

// TestDescribeApplicationAttributeAbsentNat covers an application with no NAT
// mapping: the gateway and the SNAT address must decode as absent pointers, not
// as empty strings, so the accessors report null rather than a blank address.
func TestDescribeApplicationAttributeAbsentNat(t *testing.T) {
	var body polardb.DescribeApplicationAttributeResponseBody
	require.NoError(t, json.Unmarshal([]byte(`{"ApplicationId": "pa-bp1example"}`), &body))

	assert.Nil(t, body.VpcNatGatewayId)
	assert.Nil(t, body.NatMappingSnatIpAddress)
	assert.Empty(t, body.DnatMappings)
}
