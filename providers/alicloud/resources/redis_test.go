// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	rkvclient "github.com/alibabacloud-go/r-kvstore-20150101/v8/client"
	"github.com/stretchr/testify/assert"
)

func TestRedisAiGatewayTags(t *testing.T) {
	// Synthetic: no target showed an untagged gateway.
	assert.Empty(t, redisAiGatewayTags(nil))

	// Synthetic: a nil entry and an entry without a key are dropped; a nil value reads as empty.
	got := redisAiGatewayTags(&rkvclient.DescribeTairAIGatewayInstancesResponseBodyInstancesTairSemanticCacheInstancesTags{
		Tag: []*rkvclient.DescribeTairAIGatewayInstancesResponseBodyInstancesTairSemanticCacheInstancesTagsTag{
			nil,
			{Value: new("orphan")},
			{Key: new("env"), Value: new("prod")},
			{Key: new("owner")},
		},
	})
	assert.Equal(t, map[string]any{"env": "prod", "owner": ""}, got)
}

func TestAddRedisAiGatewayParameter(t *testing.T) {
	// Synthetic: parameter rows as DescribeTairAIGatewayParameters returns them; no target showed these.
	res := map[string]any{}
	addRedisAiGatewayParameter(res, new("ai_cache"), new("on"))
	addRedisAiGatewayParameter(res, nil, new("dropped"))
	addRedisAiGatewayParameter(res, new(""), new("dropped"))
	addRedisAiGatewayParameter(res, new("ttl"), nil)
	assert.Equal(t, map[string]any{"ai_cache": "on", "ttl": ""}, res)
}
